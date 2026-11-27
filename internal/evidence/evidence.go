// Package evidence loads deterministic attack fixtures and compares policy
// decisions across a corpus.
package evidence

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/caplock/caplock/internal/lockfile"
	"github.com/caplock/caplock/internal/policy"
	"github.com/caplock/caplock/internal/safefile"
	"github.com/caplock/caplock/internal/trace"
	"github.com/caplock/caplock/packs"
)

const (
	// Version is the supported corpus format version.
	Version = 1
	// MaxBytes is the largest corpus Caplock will read.
	MaxBytes = 4 << 20
	// MaxCases bounds corpus execution time and report size.
	MaxCases = 1_000
)

// defaultRequestTime is used when a corpus case omits request.context.time.
// Regression evidence must not depend on the wall clock.
var defaultRequestTime = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

var validEffects = map[string]bool{
	policy.EffectAllow:           true,
	policy.EffectDeny:            true,
	policy.EffectRequireApproval: true,
}

var validObligations = map[string]bool{
	"audit":          true,
	"alert":          true,
	"redact":         true,
	"human_approval": true,
	"rate_limit":     true,
}

var severityRank = map[string]int{
	"info":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// Corpus is a deterministic set of authorization requests and expectations.
type Corpus struct {
	Version     int    `json:"version" yaml:"version"`
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Cases       []Case `json:"cases" yaml:"cases"`
}

// Case is one replayable attack or authorization scenario.
type Case struct {
	ID          string         `json:"id" yaml:"id"`
	Description string         `json:"description,omitempty" yaml:"description,omitempty"`
	Tags        []string       `json:"tags,omitempty" yaml:"tags,omitempty"`
	Severity    string         `json:"severity" yaml:"severity"`
	Path        []PathStep     `json:"path,omitempty" yaml:"path,omitempty"`
	Request     policy.Request `json:"request" yaml:"request"`
	Expect      Expectation    `json:"expect" yaml:"expect"`
}

// PathStep provides human-readable attack-path context around a request.
type PathStep struct {
	Tool         string   `json:"tool,omitempty" yaml:"tool,omitempty"`
	Capabilities []string `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Sink         string   `json:"sink,omitempty" yaml:"sink,omitempty"`
	Note         string   `json:"note,omitempty" yaml:"note,omitempty"`
}

// Expectation is the secure outcome a case asserts.
type Expectation struct {
	Effect      string   `json:"effect" yaml:"effect"`
	Rule        string   `json:"rule,omitempty" yaml:"rule,omitempty"`
	Default     *bool    `json:"default,omitempty" yaml:"default,omitempty"`
	Obligations []string `json:"obligations,omitempty" yaml:"obligations,omitempty"`
}

// CaseResult records one evaluated fixture.
type CaseResult struct {
	ID             string          `json:"id"`
	Description    string          `json:"description,omitempty"`
	Tags           []string        `json:"tags"`
	Severity       string          `json:"severity"`
	Path           []PathStep      `json:"path"`
	Expect         Expectation     `json:"expect"`
	Decision       policy.Decision `json:"decision"`
	Passed         bool            `json:"passed"`
	FailureReasons []string        `json:"failureReasons"`
}

// DecisionChange is a baseline-to-current policy outcome change.
type DecisionChange struct {
	CaseID     string `json:"caseId"`
	OldEffect  string `json:"oldEffect"`
	NewEffect  string `json:"newEffect"`
	OldRuleID  string `json:"oldRuleId,omitempty"`
	NewRuleID  string `json:"newRuleId,omitempty"`
	OldDefault bool   `json:"oldDefault"`
	NewDefault bool   `json:"newDefault"`
}

// InvariantViolation identifies a concrete broken policy invariant.
type InvariantViolation struct {
	CaseID       string `json:"caseId"`
	Subject      string `json:"subject"`
	Parent       string `json:"parent"`
	ChildEffect  string `json:"childEffect"`
	ParentEffect string `json:"parentEffect"`
	Message      string `json:"message"`
}

// InvariantResult groups checks for one invariant.
type InvariantResult struct {
	Code       string               `json:"code"`
	Passed     bool                 `json:"passed"`
	Checked    int                  `json:"checked"`
	Violations []InvariantViolation `json:"violations"`
}

// ToolCoverage records whether a locked tool has any policy path that identifies
// it by tool or capability. Context-only selectors are treated as conditional.
type ToolCoverage struct {
	Server      string   `json:"server"`
	Tool        string   `json:"tool"`
	Subject     string   `json:"subject"`
	Covered     bool     `json:"covered"`
	RuleIDs     []string `json:"ruleIds"`
	Conditional bool     `json:"conditional"`
}

// Result is the deterministic evidence report used by test and report commands.
type Result struct {
	Version         int               `json:"version"`
	Policy          string            `json:"policy"`
	Corpus          string            `json:"corpus"`
	Passed          bool              `json:"passed"`
	Total           int               `json:"total"`
	PassedCount     int               `json:"passedCount"`
	FailedCount     int               `json:"failedCount"`
	Cases           []CaseResult      `json:"cases"`
	Invariants      []InvariantResult `json:"invariants"`
	Coverage        []ToolCoverage    `json:"coverage,omitempty"`
	BaselineChanges []DecisionChange  `json:"baselineChanges,omitempty"`
}

// Options controls optional evidence checks.
type Options struct {
	Baseline *policy.IR
	Lockfile *lockfile.File
	Subject  string
}

// Load reads and validates a corpus file.
func Load(path string) (*Corpus, error) {
	data, err := safefile.ReadFile(path, MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("read evidence corpus %s: %w", path, err)
	}
	corpus, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse evidence corpus %s: %w", filepath.Base(path), err)
	}
	return corpus, nil
}

// DefaultCorpus returns the embedded 50-case MCP baseline corpus.
func DefaultCorpus() (*Corpus, error) {
	data, err := packs.Read("attacks/baseline.yaml")
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes YAML or JSON corpus bytes with strict field checking.
func Parse(data []byte) (*Corpus, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var corpus Corpus
	if err := decoder.Decode(&corpus); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("evidence corpus is empty")
		}
		return nil, err
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err == nil {
		return nil, errors.New("evidence corpus contains multiple YAML documents")
	} else if !errors.Is(err, io.EOF) {
		return nil, err
	}
	if err := validateCorpus(&corpus); err != nil {
		return nil, err
	}
	normalizeCorpus(&corpus)
	return &corpus, nil
}

// Marshal returns a deterministic YAML corpus after validation and sorting.
func Marshal(corpus *Corpus) ([]byte, error) {
	if corpus == nil {
		return nil, errors.New("corpus is nil")
	}
	if err := validateCorpus(corpus); err != nil {
		return nil, err
	}
	normalizeCorpus(corpus)
	data, err := yaml.Marshal(corpus)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// FromTrace creates reviewable corpus candidates from observed tool calls. The
// expected effect is the current policy's decision, not a proof that the call is
// secure. Every generated case is tagged for human review.
func FromTrace(ir *policy.IR, records []trace.Record, source string) (*Corpus, error) {
	if ir == nil {
		return nil, errors.New("policy is required")
	}
	if len(records) == 0 {
		return nil, errors.New("trace contains no records")
	}
	if len(records) > MaxCases {
		return nil, fmt.Errorf("trace exceeds %d corpus candidates", MaxCases)
	}
	name := strings.TrimSuffix(filepath.Base(strings.TrimSpace(source)), filepath.Ext(source))
	if name == "" || name == "." {
		name = "trace-candidates"
	}
	corpus := &Corpus{
		Version:     Version,
		Name:        name + "-candidates",
		Description: "Generated from observed tool calls. Expectations capture current behavior and require review before use as a security gate.",
		Cases:       make([]Case, 0, len(records)),
	}
	for index, record := range records {
		record = trace.Normalize(record)
		if err := trace.Validate(record); err != nil {
			return nil, fmt.Errorf("record %d: %w", index+1, err)
		}
		var arguments map[string]any
		tags := []string{"trace-generated", "review-required"}
		if record.ArgumentsCaptured && len(record.RedactedFields) == 0 {
			arguments = record.Args
		} else if record.ArgumentsCaptured {
			tags = append(tags, "args-redacted")
		} else {
			tags = append(tags, "args-missing")
		}
		request := policy.Request{
			Subject:      record.Subject,
			Tool:         record.Tool,
			Capabilities: record.Capabilities,
			DataClass:    record.DataClass,
			Sink:         record.Sink,
			Args:         arguments,
			Provenance:   record.Provenance,
			Context: policy.RequestContext{
				Time:        record.Time,
				Environment: record.Environment,
			},
		}
		decision, err := policy.Evaluate(ir, request)
		if err != nil {
			return nil, fmt.Errorf("evaluate trace record %d: %w", index+1, err)
		}
		defaultValue := decision.Default
		corpus.Cases = append(corpus.Cases, Case{
			ID:          fmt.Sprintf("trace-%03d-%s", index+1, sanitizeID(record.Tool)),
			Description: fmt.Sprintf("Observed %s call from trace %s; review the expected decision before promoting this case", record.Tool, filepath.Base(source)),
			Tags:        tags,
			Severity:    traceSeverity(record),
			Path: []PathStep{{
				Tool:         record.Tool,
				Capabilities: append([]string(nil), record.Capabilities...),
				Sink:         record.Sink,
				Note:         "observed in trace",
			}},
			Request: request,
			Expect: Expectation{
				Effect:      decision.Effect,
				Rule:        decision.RuleID,
				Default:     &defaultValue,
				Obligations: append([]string(nil), decision.Obligations...),
			},
		})
	}
	normalizeCorpus(corpus)
	return corpus, nil
}

func traceSeverity(record trace.Record) string {
	sink := strings.ToLower(record.Sink)
	for _, highRisk := range []string{"email.send", "slack.send", "sms.send", "webhook.send", "http.post", "file.upload", "shell.exec", "storage.delete"} {
		if sink == highRisk {
			return "high"
		}
	}
	for _, capability := range record.Capabilities {
		switch capability {
		case "destructive", "execute", "finance.write", "finance.approve", "identity.write":
			return "high"
		}
	}
	return "medium"
}

func sanitizeID(value string) string {
	var builder strings.Builder
	for _, character := range strings.ToLower(value) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			builder.WriteRune(character)
		} else if builder.Len() > 0 && !strings.HasSuffix(builder.String(), "-") {
			builder.WriteByte('-')
		}
	}
	result := strings.Trim(builder.String(), "-")
	if result == "" {
		return "tool"
	}
	return result
}

func validateCorpus(corpus *Corpus) error {
	if corpus.Version != Version {
		return fmt.Errorf("version must be %d", Version)
	}
	if strings.TrimSpace(corpus.Name) == "" {
		return errors.New("name must not be empty")
	}
	if len(corpus.Cases) == 0 {
		return errors.New("cases must not be empty")
	}
	if len(corpus.Cases) > MaxCases {
		return fmt.Errorf("cases must not exceed %d entries", MaxCases)
	}
	seen := make(map[string]bool, len(corpus.Cases))
	for index := range corpus.Cases {
		item := &corpus.Cases[index]
		if strings.TrimSpace(item.ID) == "" {
			return fmt.Errorf("cases[%d].id must not be empty", index)
		}
		if seen[item.ID] {
			return fmt.Errorf("duplicate case id %q", item.ID)
		}
		seen[item.ID] = true
		if item.Severity == "" {
			item.Severity = "medium"
		}
		if _, ok := severityRank[item.Severity]; !ok {
			return fmt.Errorf("case %q severity must be info, low, medium, high, or critical", item.ID)
		}
		if strings.TrimSpace(item.Request.Subject) == "" {
			return fmt.Errorf("case %q request.subject must not be empty", item.ID)
		}
		if strings.TrimSpace(item.Request.Tool) == "" {
			return fmt.Errorf("case %q request.tool must not be empty", item.ID)
		}
		if !validEffects[item.Expect.Effect] {
			return fmt.Errorf("case %q expect.effect must be allow, deny, or require_approval", item.ID)
		}
		if err := validateStringList("case "+item.ID+" tags", item.Tags); err != nil {
			return err
		}
		if err := validateStringList("case "+item.ID+" request.capabilities", item.Request.Capabilities); err != nil {
			return err
		}
		if err := validateStringList("case "+item.ID+" request.dataClass", item.Request.DataClass); err != nil {
			return err
		}
		if err := validateStringList("case "+item.ID+" request.provenance", item.Request.Provenance); err != nil {
			return err
		}
		if err := validateStringList("case "+item.ID+" expect.obligations", item.Expect.Obligations); err != nil {
			return err
		}
		for _, obligation := range item.Expect.Obligations {
			if !validObligations[obligation] {
				return fmt.Errorf("case %q has unknown expected obligation %q", item.ID, obligation)
			}
		}
	}
	return nil
}

func validateStringList(label string, values []string) error {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s values must not be empty", label)
		}
		if seen[value] {
			return fmt.Errorf("%s contains duplicate %q", label, value)
		}
		seen[value] = true
	}
	return nil
}

func normalizeCorpus(corpus *Corpus) {
	for index := range corpus.Cases {
		item := &corpus.Cases[index]
		sort.Strings(item.Tags)
		sort.Strings(item.Request.Capabilities)
		sort.Strings(item.Request.DataClass)
		sort.Strings(item.Request.Provenance)
		sort.Strings(item.Expect.Obligations)
		for pathIndex := range item.Path {
			sort.Strings(item.Path[pathIndex].Capabilities)
		}
	}
	sort.SliceStable(corpus.Cases, func(i, j int) bool { return corpus.Cases[i].ID < corpus.Cases[j].ID })
}

// Run evaluates every case and optional invariants, baseline changes, and tool
// coverage. Results preserve corpus order after deterministic ID sorting.
func Run(ir *policy.IR, corpus *Corpus, options Options) (Result, error) {
	if ir == nil || corpus == nil {
		return Result{}, errors.New("policy and corpus are required")
	}
	result := Result{
		Version:         Version,
		Policy:          ir.Policy,
		Corpus:          corpus.Name,
		Cases:           make([]CaseResult, 0, len(corpus.Cases)),
		Invariants:      []InvariantResult{},
		BaselineChanges: []DecisionChange{},
	}
	for _, item := range corpus.Cases {
		request := item.Request
		if request.Context.Time.IsZero() {
			request.Context.Time = defaultRequestTime
		}
		decision, err := policy.Evaluate(ir, request)
		if err != nil {
			return Result{}, fmt.Errorf("evaluate case %q: %w", item.ID, err)
		}
		passed, reasons := expectationPassed(item.Expect, decision)
		result.Cases = append(result.Cases, CaseResult{
			ID:             item.ID,
			Description:    item.Description,
			Tags:           nonNil(item.Tags),
			Severity:       item.Severity,
			Path:           nonNilPath(item.Path),
			Expect:         item.Expect,
			Decision:       decision,
			Passed:         passed,
			FailureReasons: reasons,
		})
		if passed {
			result.PassedCount++
		} else {
			result.FailedCount++
		}
		if options.Baseline != nil {
			baseline, err := policy.Evaluate(options.Baseline, request)
			if err != nil {
				return Result{}, fmt.Errorf("evaluate baseline case %q: %w", item.ID, err)
			}
			if baseline.Effect != decision.Effect || baseline.RuleID != decision.RuleID || baseline.Default != decision.Default {
				result.BaselineChanges = append(result.BaselineChanges, DecisionChange{
					CaseID:     item.ID,
					OldEffect:  baseline.Effect,
					NewEffect:  decision.Effect,
					OldRuleID:  baseline.RuleID,
					NewRuleID:  decision.RuleID,
					OldDefault: baseline.Default,
					NewDefault: decision.Default,
				})
			}
		}
	}
	result.Total = len(result.Cases)

	delegation := checkDelegation(ir, corpus)
	result.Invariants = append(result.Invariants, delegation)
	if options.Lockfile != nil {
		subject := options.Subject
		if subject == "" {
			subject = "agent"
		}
		result.Coverage = CheckCoverage(ir, options.Lockfile, subject)
		for _, coverage := range result.Coverage {
			if !coverage.Covered {
				result.Invariants = append(result.Invariants, InvariantResult{
					Code:    "tool-coverage",
					Passed:  false,
					Checked: 1,
					Violations: []InvariantViolation{{
						Subject: subject,
						Message: fmt.Sprintf("tool %q on server %q has no tool- or capability-targeted rule", coverage.Tool, coverage.Server),
					}},
				})
			}
		}
	}

	result.Passed = result.FailedCount == 0
	for _, invariant := range result.Invariants {
		if !invariant.Passed {
			result.Passed = false
			break
		}
	}
	return result, nil
}

func expectationPassed(expect Expectation, decision policy.Decision) (bool, []string) {
	reasons := make([]string, 0)
	if decision.Effect != expect.Effect {
		reasons = append(reasons, fmt.Sprintf("effect %s, expected %s", decision.Effect, expect.Effect))
	}
	if expect.Rule != "" && decision.RuleID != expect.Rule {
		reasons = append(reasons, fmt.Sprintf("rule %q, expected %q", decision.RuleID, expect.Rule))
	}
	if expect.Default != nil && decision.Default != *expect.Default {
		reasons = append(reasons, fmt.Sprintf("default %t, expected %t", decision.Default, *expect.Default))
	}
	obligations := make(map[string]bool, len(decision.Obligations))
	for _, obligation := range decision.Obligations {
		obligations[obligation] = true
	}
	for _, obligation := range expect.Obligations {
		if !obligations[obligation] {
			reasons = append(reasons, "missing obligation "+obligation)
		}
	}
	return len(reasons) == 0, reasons
}

func checkDelegation(ir *policy.IR, corpus *Corpus) InvariantResult {
	result := InvariantResult{Code: "delegation-attenuation", Passed: true, Violations: []InvariantViolation{}}
	subjects := make(map[string]policy.Subject, len(ir.Subjects))
	for _, subject := range ir.Subjects {
		subjects[subject.ID] = subject
	}
	for _, item := range corpus.Cases {
		child, ok := subjects[item.Request.Subject]
		if !ok || child.Parent == "" || child.Delegation != policy.DelegationAttenuateOnly {
			continue
		}
		childDecision, err := policy.Evaluate(ir, item.Request)
		if err != nil {
			result.Passed = false
			result.Violations = append(result.Violations, InvariantViolation{CaseID: item.ID, Subject: child.ID, Parent: child.Parent, Message: err.Error()})
			continue
		}
		parentRequest := item.Request
		parentRequest.Subject = child.Parent
		parentDecision, err := policy.Evaluate(ir, parentRequest)
		if err != nil {
			result.Passed = false
			result.Violations = append(result.Violations, InvariantViolation{CaseID: item.ID, Subject: child.ID, Parent: child.Parent, Message: err.Error()})
			continue
		}
		result.Checked++
		if effectStrength(childDecision.Effect) < effectStrength(parentDecision.Effect) {
			result.Passed = false
			result.Violations = append(result.Violations, InvariantViolation{
				CaseID:       item.ID,
				Subject:      child.ID,
				Parent:       child.Parent,
				ChildEffect:  childDecision.Effect,
				ParentEffect: parentDecision.Effect,
				Message:      fmt.Sprintf("child effect %s exceeds parent effect %s", childDecision.Effect, parentDecision.Effect),
			})
		}
	}
	return result
}

func effectStrength(effect string) int {
	switch effect {
	case policy.EffectDeny:
		return 2
	case policy.EffectRequireApproval:
		return 1
	default:
		return 0
	}
}

// CheckCoverage identifies tools with no tool- or capability-targeted policy
// rule. Conditional provenance, argument, time, and sink selectors are retained
// in the matched rule but do not count against coverage.
func CheckCoverage(ir *policy.IR, file *lockfile.File, subject string) []ToolCoverage {
	coverage := make([]ToolCoverage, 0)
	if ir == nil || file == nil {
		return coverage
	}
	for _, server := range file.Servers {
		if server.Tools == nil {
			continue
		}
		for _, tool := range *server.Tools {
			entry := ToolCoverage{Server: server.Name, Tool: tool.Name, Subject: subject, RuleIDs: []string{}}
			for _, rule := range ir.Rules {
				if ruleCoversTool(&rule, subject, tool.Name, tool.Capabilities) {
					entry.Covered = true
					entry.RuleIDs = append(entry.RuleIDs, rule.ID)
					if rule.Match.HasConditionalSelectors() {
						entry.Conditional = true
					}
				}
			}
			sort.Strings(entry.RuleIDs)
			coverage = append(coverage, entry)
		}
	}
	sort.SliceStable(coverage, func(i, j int) bool {
		if coverage[i].Server != coverage[j].Server {
			return coverage[i].Server < coverage[j].Server
		}
		return coverage[i].Tool < coverage[j].Tool
	})
	return coverage
}

func ruleCoversTool(rule *policy.Rule, subject, tool string, capabilities []string) bool {
	if rule.Match == nil || len(rule.Match.Tool) == 0 && len(rule.Match.Capability) == 0 {
		return false
	}
	if rule.Match.Subject != "" && rule.Match.Subject != "*" && rule.Match.Subject != subject {
		return false
	}
	if len(rule.Match.Tool) > 0 && !containsOrWildcard(rule.Match.Tool, tool) {
		return false
	}
	if len(rule.Match.Capability) > 0 && !overlapsOrWildcard(rule.Match.Capability, capabilities) {
		return false
	}
	return true
}

func containsOrWildcard(values []string, actual string) bool {
	for _, value := range values {
		if value == "*" || value == actual {
			return true
		}
	}
	return false
}

func overlapsOrWildcard(values, actual []string) bool {
	set := make(map[string]bool, len(actual))
	for _, value := range actual {
		set[value] = true
	}
	for _, value := range values {
		if value == "*" || set[value] {
			return true
		}
	}
	return false
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonNilPath(values []PathStep) []PathStep {
	if values == nil {
		return []PathStep{}
	}
	return values
}
