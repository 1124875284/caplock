// Package attackgraph builds a bounded, conservative source-to-sink graph from
// an MCP lockfile and evaluates each candidate sink request against Policy IR.
// The graph is a review aid, not a proof of dataflow.
package attackgraph

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/1124875284/caplock/internal/inventory"
	"github.com/1124875284/caplock/internal/lockfile"
	"github.com/1124875284/caplock/internal/policy"
)

const (
	// Version is the graph report format version.
	Version = 1
	// DefaultMaxPaths bounds combinatorial growth.
	DefaultMaxPaths = 100
	// MaxPaths is the absolute path cap accepted by this build.
	MaxPaths = 1_000
)

// DefaultEvaluationTime keeps graph decisions reproducible.
var DefaultEvaluationTime = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// Options controls graph construction.
type Options struct {
	Subject  string
	At       time.Time
	MaxPaths int
}

// Step is one observed tool node in a candidate attack path.
type Step struct {
	Server       string   `json:"server" yaml:"server"`
	Tool         string   `json:"tool" yaml:"tool"`
	Capabilities []string `json:"capabilities" yaml:"capabilities"`
	Sink         string   `json:"sink,omitempty" yaml:"sink,omitempty"`
	Role         string   `json:"role" yaml:"role"`
	Note         string   `json:"note,omitempty" yaml:"note,omitempty"`
}

// Decision is the deterministic policy result for the sink request.
type Decision struct {
	Effect      string   `json:"effect" yaml:"effect"`
	RuleID      string   `json:"ruleId,omitempty" yaml:"ruleId,omitempty"`
	Default     bool     `json:"default" yaml:"default"`
	Obligations []string `json:"obligations" yaml:"obligations"`
}

// Path is one candidate source-to-sink route.
type Path struct {
	ID                string   `json:"id" yaml:"id"`
	Severity          string   `json:"severity" yaml:"severity"`
	SourceLabels      []string `json:"sourceLabels" yaml:"sourceLabels"`
	DataClass         []string `json:"dataClass,omitempty" yaml:"dataClass,omitempty"`
	Provenance        []string `json:"provenance,omitempty" yaml:"provenance,omitempty"`
	Sink              string   `json:"sink" yaml:"sink"`
	Steps             []Step   `json:"steps" yaml:"steps"`
	Decision          Decision `json:"decision" yaml:"decision"`
	Status            string   `json:"status" yaml:"status"`
	Controlled        bool     `json:"controlled" yaml:"controlled"`
	ArgumentDependent bool     `json:"argumentDependent" yaml:"argumentDependent"`
}

// Summary aggregates candidate paths.
type Summary struct {
	Servers           int  `json:"servers" yaml:"servers"`
	Tools             int  `json:"tools" yaml:"tools"`
	Sources           int  `json:"sources" yaml:"sources"`
	Sinks             int  `json:"sinks" yaml:"sinks"`
	Paths             int  `json:"paths" yaml:"paths"`
	Blocked           int  `json:"blocked" yaml:"blocked"`
	ApprovalRequired  int  `json:"approvalRequired" yaml:"approvalRequired"`
	Allowed           int  `json:"allowed" yaml:"allowed"`
	ArgumentDependent int  `json:"argumentDependent" yaml:"argumentDependent"`
	Truncated         bool `json:"truncated" yaml:"truncated"`
}

// Result is the deterministic attack-graph report.
type Result struct {
	Version        int      `json:"version" yaml:"version"`
	Policy         string   `json:"policy" yaml:"policy"`
	Subject        string   `json:"subject" yaml:"subject"`
	EvaluationTime string   `json:"evaluationTime" yaml:"evaluationTime"`
	Summary        Summary  `json:"summary" yaml:"summary"`
	Paths          []Path   `json:"paths" yaml:"paths"`
	Limitations    []string `json:"limitations" yaml:"limitations"`
}

type toolNode struct {
	server       string
	name         string
	capabilities []string
	sink         string
	source       sourceFacts
	sinkClass    string
}

type sourceFacts struct {
	labels     []string
	provenance []string
	dataClass  []string
}

// Build maps lockfile tools to conservative source/sink roles and evaluates
// bounded direct and one-intermediate paths. Context-sensitive argument rules
// cannot be proven without captured values and are marked argumentDependent.
func Build(ir *policy.IR, locked *lockfile.File, options Options) (Result, error) {
	if ir == nil {
		return Result{}, errors.New("policy is required")
	}
	if locked == nil {
		return Result{}, errors.New("lockfile is required")
	}
	subject := strings.TrimSpace(options.Subject)
	if subject == "" {
		subject = "agent"
	}
	at := options.At
	if at.IsZero() {
		at = DefaultEvaluationTime
	}
	maxPaths := options.MaxPaths
	if maxPaths <= 0 {
		maxPaths = DefaultMaxPaths
	}
	if maxPaths > MaxPaths {
		return Result{}, fmt.Errorf("max paths must not exceed %d", MaxPaths)
	}

	nodes := collectNodes(locked)
	if len(nodes) == 0 {
		return Result{}, errors.New("lockfile has no captured tools; run `caplock lock --connect` first")
	}
	sources := make([]toolNode, 0)
	sinks := make([]toolNode, 0)
	intermediates := make([]toolNode, 0)
	for _, node := range nodes {
		if len(node.source.labels) > 0 {
			sources = append(sources, node)
		}
		if node.sinkClass != "" {
			sinks = append(sinks, node)
		}
		if len(node.source.labels) == 0 && node.sinkClass == "" && canTransform(node) {
			intermediates = append(intermediates, node)
		}
	}

	result := Result{
		Version:        Version,
		Policy:         ir.Policy,
		Subject:        subject,
		EvaluationTime: at.Format(time.RFC3339),
		Paths:          make([]Path, 0),
		Limitations: []string{
			"Paths are inferred from tool names and capability labels derived from descriptions and MCP annotations; they are heuristic, not content-level dataflow proof.",
			"Argument selectors are evaluated with empty arguments, so paths touching argument-dependent rules are marked argumentDependent.",
			"Only direct and one-intermediate paths are searched; deeper agent planning and model reasoning are out of scope.",
		},
	}
	result.Summary.Servers = countServers(nodes)
	result.Summary.Tools = len(nodes)
	result.Summary.Sources = len(sources)
	result.Summary.Sinks = len(sinks)

	seen := make(map[string]bool)
	addPath := func(source, sink toolNode, intermediate *toolNode) error {
		if len(result.Paths) >= maxPaths {
			result.Summary.Truncated = true
			return nil
		}
		steps := make([]Step, 0, 3)
		steps = append(steps, Step{Server: source.server, Tool: source.name, Capabilities: nonNil(source.capabilities), Role: "source", Note: strings.Join(source.source.labels, ",")})
		if intermediate != nil {
			steps = append(steps, Step{Server: intermediate.server, Tool: intermediate.name, Capabilities: nonNil(intermediate.capabilities), Role: "intermediate"})
		}
		steps = append(steps, Step{Server: sink.server, Tool: sink.name, Capabilities: nonNil(sink.capabilities), Sink: sink.sink, Role: "sink"})
		keyParts := make([]string, 0, len(steps))
		for _, step := range steps {
			keyParts = append(keyParts, step.Server+"\x00"+step.Tool)
		}
		key := strings.Join(keyParts, "\x01") + "\x02" + strings.Join(source.source.labels, ",")
		if seen[key] {
			return nil
		}
		seen[key] = true
		request := policy.Request{
			Subject:      subject,
			Tool:         sink.name,
			Capabilities: sink.capabilities,
			DataClass:    append([]string(nil), source.source.dataClass...),
			Sink:         sink.sink,
			Provenance:   append([]string(nil), source.source.provenance...),
			Context:      policy.RequestContext{Time: at},
		}
		decision, err := policy.Evaluate(ir, request)
		if err != nil {
			return err
		}
		status := "allowed"
		controlled := false
		switch decision.Effect {
		case policy.EffectDeny:
			status = "blocked"
			controlled = true
			result.Summary.Blocked++
		case policy.EffectRequireApproval:
			status = "approval_required"
			controlled = true
			result.Summary.ApprovalRequired++
		default:
			result.Summary.Allowed++
		}
		argumentDependent := false
		for _, rule := range ir.Rules {
			if rule.ID == decision.RuleID && rule.Match != nil && len(rule.Match.Args) > 0 {
				argumentDependent = true
			}
		}
		if argumentDependent {
			result.Summary.ArgumentDependent++
		}
		severity := pathSeverity(source, sink)
		idParts := make([]string, 0, len(steps))
		for _, step := range steps {
			idParts = append(idParts, sanitize(step.Server+"-"+step.Tool))
		}
		result.Paths = append(result.Paths, Path{
			ID:                strings.Join(idParts, "-to-"),
			Severity:          severity,
			SourceLabels:      nonNil(append([]string(nil), source.source.labels...)),
			DataClass:         nonNil(append([]string(nil), source.source.dataClass...)),
			Provenance:        nonNil(append([]string(nil), source.source.provenance...)),
			Sink:              sink.sink,
			Steps:             steps,
			Decision:          Decision{Effect: decision.Effect, RuleID: decision.RuleID, Default: decision.Default, Obligations: nonNil(decision.Obligations)},
			Status:            status,
			Controlled:        controlled,
			ArgumentDependent: argumentDependent,
		})
		return nil
	}

	for _, source := range sources {
		for _, sink := range sinks {
			if err := addPath(source, sink, nil); err != nil {
				return Result{}, err
			}
		}
	}
	for _, source := range sources {
		for _, sink := range sinks {
			for index := range intermediates {
				if err := addPath(source, sink, &intermediates[index]); err != nil {
					return Result{}, err
				}
			}
		}
	}
	sort.SliceStable(result.Paths, func(i, j int) bool {
		if result.Paths[i].Severity != result.Paths[j].Severity {
			return severityRank(result.Paths[i].Severity) > severityRank(result.Paths[j].Severity)
		}
		return result.Paths[i].ID < result.Paths[j].ID
	})
	result.Summary.Paths = len(result.Paths)
	return result, nil
}

func collectNodes(locked *lockfile.File) []toolNode {
	nodes := make([]toolNode, 0)
	for _, server := range locked.Servers {
		if server.Tools == nil {
			continue
		}
		for _, tool := range *server.Tools {
			capabilities := append([]string(nil), tool.Capabilities...)
			sort.Strings(capabilities)
			node := toolNode{server: server.Name, name: tool.Name, capabilities: capabilities}
			node.sink = inventory.Sink(tool.Name, capabilities)
			node.source = sourceFor(tool.Name, capabilities)
			node.sinkClass = sinkClass(node.sink, capabilities)
			nodes = append(nodes, node)
		}
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].server != nodes[j].server {
			return nodes[i].server < nodes[j].server
		}
		return nodes[i].name < nodes[j].name
	})
	return nodes
}

func sourceFor(name string, capabilities []string) sourceFacts {
	lowerName := strings.ToLower(name)
	has := func(capability string) bool {
		for _, value := range capabilities {
			if value == capability {
				return true
			}
		}
		return false
	}
	facts := sourceFacts{}
	if has("external.read") || has("external") && has("read") {
		facts.labels = append(facts.labels, "external_web")
		facts.provenance = append(facts.provenance, "external_web")
	}
	if termsContain(lowerName, "secret", "token", "credential", "password", "key") && (has("read") || has("identity")) {
		facts.labels = append(facts.labels, "secret_store")
		facts.dataClass = append(facts.dataClass, "secret")
	}
	if has("identity") && has("read") && len(facts.dataClass) == 0 {
		facts.labels = append(facts.labels, "identity_store")
		facts.dataClass = append(facts.dataClass, "identity")
	}
	facts.labels = unique(facts.labels)
	facts.provenance = unique(facts.provenance)
	facts.dataClass = unique(facts.dataClass)
	return facts
}

func sinkClass(sink string, capabilities []string) string {
	switch sink {
	case "email.send", "slack.send", "sms.send", "webhook.send", "http.post", "file.upload":
		return "egress"
	case "shell.exec":
		return "execution"
	case "storage.delete":
		return "destructive"
	}
	for _, capability := range capabilities {
		if capability == "destructive" || capability == "execute" {
			return capability
		}
	}
	return ""
}

func canTransform(node toolNode) bool {
	for _, capability := range node.capabilities {
		switch capability {
		case "read", "write", "network", "external", "identity", "finance":
			return true
		}
	}
	return false
}

func pathSeverity(source, sink toolNode) string {
	hasSecret := false
	for _, dataClass := range source.source.dataClass {
		if dataClass == "secret" {
			hasSecret = true
		}
	}
	switch sink.sinkClass {
	case "egress", "execution":
		if hasSecret {
			return "critical"
		}
		return "high"
	case "destructive":
		return "high"
	default:
		return "medium"
	}
}

func countServers(nodes []toolNode) int {
	seen := make(map[string]bool)
	for _, node := range nodes {
		seen[node.server] = true
	}
	return len(seen)
}

func termsContain(value string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(value, term) {
			return true
		}
	}
	return false
}

func unique(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	sort.Strings(values)
	result := values[:1]
	for _, value := range values[1:] {
		if result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func sanitize(value string) string {
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

// Render emits text, JSON, or YAML.
func Render(value Result, format string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "text", "txt":
		return renderText(value), nil
	case "json":
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(data, '\n'), nil
	case "yaml", "yml":
		return yaml.Marshal(value)
	default:
		return nil, fmt.Errorf("unsupported graph format %q; use text, json, or yaml", format)
	}
}

func renderText(value Result) []byte {
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "Caplock attack graph\n")
	fmt.Fprintf(&buffer, "Policy: %s\nSubject: %s\nEvaluation time: %s\n", textCell(value.Policy), textCell(value.Subject), textCell(value.EvaluationTime))
	fmt.Fprintf(&buffer, "Summary: servers=%d tools=%d sources=%d sinks=%d paths=%d blocked=%d approval_required=%d allowed=%d argument_dependent=%d truncated=%t\n",
		value.Summary.Servers, value.Summary.Tools, value.Summary.Sources, value.Summary.Sinks, value.Summary.Paths,
		value.Summary.Blocked, value.Summary.ApprovalRequired, value.Summary.Allowed, value.Summary.ArgumentDependent, value.Summary.Truncated)
	if len(value.Paths) == 0 {
		fmt.Fprintf(&buffer, "\nNo candidate paths found. This does not prove absence of dataflow.\n")
		return buffer.Bytes()
	}
	fmt.Fprintf(&buffer, "\nCandidate paths:\n")
	for _, path := range value.Paths {
		fmt.Fprintf(&buffer, "  [%s] %s -> %s status=%s rule=%s\n", strings.ToUpper(path.Severity), path.ID, textCell(path.Sink), path.Status, textCell(ruleOrDefault(path.Decision)))
		for index, step := range path.Steps {
			arrow := "    "
			if index > 0 {
				arrow = "    -> "
			}
			fmt.Fprintf(&buffer, "%s%s/%s %s %s\n", arrow, textCell(step.Server), textCell(step.Tool), textCell(strings.Join(step.Capabilities, ",")), step.Role)
		}
		if path.ArgumentDependent {
			fmt.Fprintf(&buffer, "       note: argument-dependent rule evaluated with empty arguments\n")
		}
	}
	fmt.Fprintf(&buffer, "\nLimitations:\n")
	for _, limitation := range value.Limitations {
		fmt.Fprintf(&buffer, "  - %s\n", limitation)
	}
	return buffer.Bytes()
}

func ruleOrDefault(decision Decision) string {
	if decision.RuleID != "" {
		return decision.RuleID
	}
	if decision.Default {
		return "(default)"
	}
	return ""
}

func severityRank(value string) int {
	switch value {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	default:
		return 0
	}
}

func textCell(value string) string {
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Sprintf("%q", value)
		}
	}
	return value
}
