// Package proxy evaluates MCP tool calls against compiled policy and can sit in
// front of stdio or Streamable HTTP MCP servers.
package proxy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/1124875284/caplock/internal/canonical"
	"github.com/1124875284/caplock/internal/inventory"
	"github.com/1124875284/caplock/internal/lockfile"
	"github.com/1124875284/caplock/internal/policy"
)

// Version is the audit record version.
const Version = 1

// ApprovalMode decides what the proxy does with require_approval decisions.
type ApprovalMode string

const (
	// ApprovalBlock turns require_approval into a runtime denial. This is the
	// default because an MCP proxy cannot obtain a human decision inline.
	ApprovalBlock ApprovalMode = "block"
	// ApprovalForward forwards require_approval calls and records the
	// obligation in the audit log for an out-of-band approval system.
	ApprovalForward ApprovalMode = "forward"
)

// ParseApprovalMode validates a command-line approval mode.
func ParseApprovalMode(value string) (ApprovalMode, error) {
	switch ApprovalMode(strings.ToLower(strings.TrimSpace(value))) {
	case ApprovalBlock:
		return ApprovalBlock, nil
	case ApprovalForward:
		return ApprovalForward, nil
	default:
		return "", fmt.Errorf("unsupported approval mode %q; use block or forward", value)
	}
}

// Options configures the policy engine.
type Options struct {
	// Policy is required.
	Policy *policy.IR
	// Lockfile is optional. When provided and it contains captured tools, a
	// tools/call that is absent from the lockfile is denied before policy is
	// evaluated. This makes manifest drift fail closed.
	Lockfile *lockfile.File
	// Subject is the agent identity evaluated by the policy. Required.
	Subject string
	// Environment populates request.context.environment.
	Environment string
	// ApprovalMode defaults to ApprovalBlock.
	ApprovalMode ApprovalMode
	// AuditEnabled reports whether the caller has an audit sink. A decision
	// carrying the audit obligation fails closed when this is false.
	AuditEnabled bool
	// RedactionKeys configures recursive argument-field redaction when a matched
	// rule carries the redact obligation. The redaction happens before forwarding
	// and only field names, never values, appear in audit or trace records.
	RedactionKeys []string
	// TraceRedactionKeys redacts sensitive fields from full trace capture only.
	// It does not rewrite the forwarded request.
	TraceRedactionKeys []string
	// RateLimiter enables enforcement of the rate_limit obligation. Without it a
	// forwardable rate-limited decision fails closed.
	RateLimiter *RateLimiter
	// AlertEnabled reports whether the caller has an alert sink. A forwardable
	// decision carrying alert without a sink fails closed.
	AlertEnabled bool
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// Engine evaluates MCP tool calls without touching the network or filesystem.
type Engine struct {
	policy      *policy.IR
	lockfile    *lockfile.File
	subject     string
	environment string
	approval    ApprovalMode
	audit       bool
	redaction   []string
	traceRedact []string
	rateLimiter *RateLimiter
	alerts      bool
	now         func() time.Time
}

// NewEngine validates options and constructs a deterministic evaluator.
func NewEngine(options Options) (*Engine, error) {
	if options.Policy == nil {
		return nil, errors.New("policy is required")
	}
	subject := strings.TrimSpace(options.Subject)
	if subject == "" {
		return nil, errors.New("subject is required")
	}
	mode := options.ApprovalMode
	if mode == "" {
		mode = ApprovalBlock
	}
	if _, err := ParseApprovalMode(string(mode)); err != nil {
		return nil, err
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Engine{
		policy:      options.Policy,
		lockfile:    options.Lockfile,
		subject:     subject,
		environment: options.Environment,
		approval:    mode,
		audit:       options.AuditEnabled,
		redaction:   append([]string(nil), options.RedactionKeys...),
		traceRedact: append([]string(nil), options.TraceRedactionKeys...),
		rateLimiter: options.RateLimiter,
		alerts:      options.AlertEnabled,
		now:         now,
	}, nil
}

// RequiresAudit reports whether any policy rule carries the audit obligation.
// The CLI uses this to refuse a proxy without an audit sink instead of silently
// forwarding unaudited decisions.
func RequiresAudit(ir *policy.IR) bool {
	return RequiresObligation(ir, "audit")
}

// RequiresObligation reports whether any policy rule declares the named
// obligation. Callers use this to require a runtime sink before startup.
func RequiresObligation(ir *policy.IR, name string) bool {
	if ir == nil {
		return false
	}
	for _, rule := range ir.Rules {
		for _, obligation := range rule.Obligations {
			if obligation == name {
				return true
			}
		}
	}
	return false
}

// Decision is the runtime result for one tools/call request. It intentionally
// contains only derived facts, never raw tool arguments.
type Decision struct {
	Policy                policy.Decision `json:"policy"`
	Tool                  string          `json:"tool"`
	Capabilities          []string        `json:"capabilities"`
	CapabilitySource      string          `json:"capabilitySource"`
	Servers               []string        `json:"servers,omitempty"`
	Sink                  string          `json:"sink,omitempty"`
	ArgsHash              string          `json:"argsHash"`
	Forward               bool            `json:"forward"`
	Reason                string          `json:"reason,omitempty"`
	ApprovalMode          ApprovalMode    `json:"approvalMode"`
	UnenforcedObligations []string        `json:"unenforcedObligations,omitempty"`
	RedactedFields        []string        `json:"redactedFields,omitempty"`
	RuntimeBlocked        bool            `json:"runtimeBlocked,omitempty"`
	ForwardArguments      map[string]any  `json:"-"`
	EvaluatedAt           time.Time       `json:"-"`
}

// Decide evaluates one tool call. A non-nil error is an internal evaluation
// failure; callers must fail closed. Policy denials are returned as a Decision
// with Forward=false.
func (e *Engine) Decide(tool string, arguments map[string]any) (Decision, error) {
	tool = strings.TrimSpace(tool)
	if tool == "" {
		return Decision{}, errors.New("tool name is required")
	}
	if arguments == nil {
		arguments = map[string]any{}
	}
	argsHash, err := HashArguments(arguments)
	if err != nil {
		return Decision{}, fmt.Errorf("hash arguments: %w", err)
	}
	at := e.now().UTC()
	capabilities, source, servers, found := e.resolveCapabilities(tool)
	sink := inventory.Sink(tool, capabilities)

	if !found {
		return Decision{
			Policy: policy.Decision{
				Effect:       policy.EffectDeny,
				Default:      false,
				Obligations:  []string{},
				MatchedRules: []policy.MatchedRule{},
			},
			Tool:             tool,
			Capabilities:     capabilities,
			CapabilitySource: source,
			Sink:             sink,
			ArgsHash:         argsHash,
			Forward:          false,
			Reason:           "tool is not present in the lockfile",
			ApprovalMode:     e.approval,
			EvaluatedAt:      at,
		}, nil
	}

	decision, err := policy.Evaluate(e.policy, policy.Request{
		Subject:      e.subject,
		Tool:         tool,
		Capabilities: capabilities,
		Sink:         sink,
		Args:         arguments,
		Context: policy.RequestContext{
			Time:        at,
			Environment: e.environment,
		},
	})
	if err != nil {
		return Decision{}, err
	}
	forward := decision.Effect == policy.EffectAllow
	if decision.Effect == policy.EffectRequireApproval {
		forward = e.approval == ApprovalForward
	}
	unenforced := unenforcedObligations(decision, e.approval, e.audit, len(e.redaction) > 0, e.rateLimiter != nil, e.alerts)
	reason := decisionReason(decision)
	runtimeBlocked := false
	var forwardArguments map[string]any
	var redactedFields []string
	if forward && contains(decision.Obligations, "redact") && len(e.redaction) > 0 {
		forwardArguments, redactedFields = canonical.RedactArguments(arguments, e.redaction)
	}
	if forward && contains(unenforced, "audit") {
		forward = false
		reason = "audit obligation cannot be enforced without an audit sink"
	}
	if forward && contains(unenforced, "redact") {
		forward = false
		reason = "redact obligation cannot be enforced without configured redaction fields"
	}
	if forward && contains(unenforced, "alert") {
		forward = false
		runtimeBlocked = true
		reason = "alert obligation cannot be enforced without an alert sink"
	}
	if forward && contains(decision.Obligations, "rate_limit") {
		if e.rateLimiter == nil {
			forward = false
			runtimeBlocked = true
			reason = "rate_limit obligation cannot be enforced without a configured limiter"
		} else {
			allowed, _, reset := e.rateLimiter.Allow(e.subject+"\x00"+tool, at)
			if !allowed {
				forward = false
				runtimeBlocked = true
				reason = fmt.Sprintf("rate_limit exceeded; retry after %s", reset.UTC().Format(time.RFC3339))
			}
		}
	}
	return Decision{
		Policy:                decision,
		Tool:                  tool,
		Capabilities:          capabilities,
		CapabilitySource:      source,
		Servers:               servers,
		Sink:                  sink,
		ArgsHash:              argsHash,
		Forward:               forward,
		Reason:                reason,
		ApprovalMode:          e.approval,
		UnenforcedObligations: unenforced,
		RedactedFields:        redactedFields,
		RuntimeBlocked:        runtimeBlocked,
		ForwardArguments:      forwardArguments,
		EvaluatedAt:           at,
	}, nil
}

// InvalidDecision records a request that could not be evaluated safely. It is
// used for malformed tools/call payloads so every attempted call is auditable.
func InvalidDecision(tool, reason string) Decision {
	hash, _ := HashArguments(nil)
	return Decision{
		Policy: policy.Decision{
			Effect:       policy.EffectDeny,
			Obligations:  []string{},
			MatchedRules: []policy.MatchedRule{},
		},
		Tool:             strings.TrimSpace(tool),
		Capabilities:     []string{},
		CapabilitySource: "invalid-request",
		ArgsHash:         hash,
		Forward:          false,
		Reason:           reason,
		ApprovalMode:     ApprovalBlock,
		EvaluatedAt:      time.Now().UTC(),
	}
}

// HashArguments returns a stable digest of a JSON object. It never serializes
// raw arguments into logs.
func HashArguments(arguments map[string]any) (string, error) {
	return canonical.HashArguments(arguments)
}

func (e *Engine) resolveCapabilities(tool string) ([]string, string, []string, bool) {
	if e.lockfile == nil {
		return heuristicCapabilities(tool), "heuristic", nil, true
	}
	var capabilities []string
	var servers []string
	hasManifests := false
	found := false
	for _, server := range e.lockfile.Servers {
		if server.Tools == nil {
			continue
		}
		hasManifests = true
		for _, lockedTool := range *server.Tools {
			if lockedTool.Name != tool {
				continue
			}
			found = true
			servers = append(servers, server.Name)
			capabilities = append(capabilities, lockedTool.Capabilities...)
		}
	}
	if found {
		return sortedUnique(capabilities), "lockfile", sortedUnique(servers), true
	}
	if hasManifests {
		return heuristicCapabilities(tool), "lockfile-missing", nil, false
	}
	return heuristicCapabilities(tool), "heuristic", nil, true
}

func heuristicCapabilities(tool string) []string {
	return inventory.ClassifyDetailed(tool, "", nil)
}

func decisionReason(decision policy.Decision) string {
	switch decision.Effect {
	case policy.EffectDeny:
		if decision.Default {
			return "denied by the default policy"
		}
		return fmt.Sprintf("denied by policy rule %q", decision.RuleID)
	case policy.EffectRequireApproval:
		if decision.Default {
			return "approval required by the default policy"
		}
		return fmt.Sprintf("approval required by policy rule %q", decision.RuleID)
	default:
		return ""
	}
}

func unenforcedObligations(decision policy.Decision, mode ApprovalMode, auditEnabled, redactionEnabled, rateLimitEnabled, alertEnabled bool) []string {
	result := make([]string, 0, len(decision.Obligations))
	for _, obligation := range decision.Obligations {
		switch obligation {
		case "audit":
			if !auditEnabled {
				result = append(result, obligation)
			}
		case "redact":
			if !redactionEnabled {
				result = append(result, obligation)
			}
		case "rate_limit":
			if !rateLimitEnabled {
				result = append(result, obligation)
			}
		case "alert":
			if !alertEnabled {
				result = append(result, obligation)
			}
		case "human_approval":
			if mode == ApprovalForward && decision.Effect == policy.EffectRequireApproval {
				result = append(result, obligation)
			}
		}
	}
	sort.Strings(result)
	return result
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
