// Package matrix renders a deterministic subject-by-tool permission matrix.
package matrix

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/1124875284/caplock/internal/evidence"
	"github.com/1124875284/caplock/internal/lockfile"
	"github.com/1124875284/caplock/internal/policy"
)

// Version identifies the matrix output schema.
const Version = 1

// DefaultEvaluationTime keeps matrix output reproducible when no time is given.
var DefaultEvaluationTime = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// Options controls subject and evaluation facts.
type Options struct {
	Subject string
	At      time.Time
}

// CandidateRule is a tool- or capability-targeted rule that may apply when its
// conditional selectors are satisfied.
type CandidateRule struct {
	ID          string `json:"id" yaml:"id"`
	Effect      string `json:"effect" yaml:"effect"`
	Conditional bool   `json:"conditional" yaml:"conditional"`
}

// Entry is one server/tool row in the matrix.
type Entry struct {
	Server         string          `json:"server" yaml:"server"`
	Tool           string          `json:"tool" yaml:"tool"`
	Capabilities   []string        `json:"capabilities" yaml:"capabilities"`
	Effect         string          `json:"effect" yaml:"effect"`
	RuleID         string          `json:"ruleId,omitempty" yaml:"ruleId,omitempty"`
	Default        bool            `json:"default" yaml:"default"`
	Conditional    bool            `json:"conditional" yaml:"conditional"`
	CandidateRules []CandidateRule `json:"candidateRules" yaml:"candidateRules"`
}

// Summary counts the baseline decision for each tool.
type Summary struct {
	Tools            int `json:"tools" yaml:"tools"`
	Allowed          int `json:"allowed" yaml:"allowed"`
	ApprovalRequired int `json:"approvalRequired" yaml:"approvalRequired"`
	Denied           int `json:"denied" yaml:"denied"`
	Defaulted        int `json:"defaulted" yaml:"defaulted"`
	Conditional      int `json:"conditional" yaml:"conditional"`
}

// Matrix is the reviewable subject-by-tool authorization artifact.
type Matrix struct {
	Version        int     `json:"version" yaml:"version"`
	Policy         string  `json:"policy" yaml:"policy"`
	Subject        string  `json:"subject" yaml:"subject"`
	EvaluationTime string  `json:"evaluationTime" yaml:"evaluationTime"`
	DefaultEffect  string  `json:"defaultEffect" yaml:"defaultEffect"`
	Summary        Summary `json:"summary" yaml:"summary"`
	Entries        []Entry `json:"entries" yaml:"entries"`
}

// Build evaluates every captured tool for one subject. The baseline request
// carries the locked capability inventory and no optional data classes, args,
// provenance, or sink facts; candidate rules expose where extra conditions can
// change the decision.
func Build(ir *policy.IR, file *lockfile.File, options Options) (Matrix, error) {
	if ir == nil || file == nil {
		return Matrix{}, fmt.Errorf("policy and lockfile are required")
	}
	subject := strings.TrimSpace(options.Subject)
	if subject == "" {
		subject = "agent"
	}
	at := options.At
	if at.IsZero() {
		at = DefaultEvaluationTime
	}
	coverage := evidence.CheckCoverage(ir, file, subject)
	if len(coverage) == 0 {
		return Matrix{}, fmt.Errorf("lockfile has no captured tools; run `caplock lock --connect` first")
	}
	capabilities := toolCapabilities(file)
	rules := make(map[string]policy.Rule, len(ir.Rules))
	for _, rule := range ir.Rules {
		rules[rule.ID] = rule
	}
	result := Matrix{
		Version:        Version,
		Policy:         ir.Policy,
		Subject:        subject,
		EvaluationTime: at.Format(time.RFC3339),
		DefaultEffect:  ir.Defaults.Effect,
		Entries:        make([]Entry, 0, len(coverage)),
	}
	for _, item := range coverage {
		request := policy.Request{
			Subject:      subject,
			Tool:         item.Tool,
			Capabilities: capabilities[item.Server+"\x00"+item.Tool],
			Context:      policy.RequestContext{Time: at},
		}
		decision, err := policy.Evaluate(ir, request)
		if err != nil {
			return Matrix{}, fmt.Errorf("evaluate %s/%s: %w", item.Server, item.Tool, err)
		}
		entry := Entry{
			Server:         item.Server,
			Tool:           item.Tool,
			Capabilities:   nonNil(capabilities[item.Server+"\x00"+item.Tool]),
			Effect:         decision.Effect,
			RuleID:         decision.RuleID,
			Default:        decision.Default,
			Conditional:    item.Conditional,
			CandidateRules: make([]CandidateRule, 0, len(item.RuleIDs)),
		}
		for _, id := range item.RuleIDs {
			rule, ok := rules[id]
			if !ok {
				continue
			}
			entry.CandidateRules = append(entry.CandidateRules, CandidateRule{
				ID:          rule.ID,
				Effect:      rule.Effect,
				Conditional: rule.Match != nil && rule.Match.HasConditionalSelectors(),
			})
		}
		result.Entries = append(result.Entries, entry)
		result.Summary.Tools++
		if entry.Conditional {
			result.Summary.Conditional++
		}
		if entry.Default {
			result.Summary.Defaulted++
		}
		switch entry.Effect {
		case policy.EffectAllow:
			result.Summary.Allowed++
		case policy.EffectRequireApproval:
			result.Summary.ApprovalRequired++
		default:
			result.Summary.Denied++
		}
	}
	return result, nil
}

func toolCapabilities(file *lockfile.File) map[string][]string {
	result := make(map[string][]string)
	for _, server := range file.Servers {
		if server.Tools == nil {
			continue
		}
		for _, tool := range *server.Tools {
			result[server.Name+"\x00"+tool.Name] = append([]string(nil), tool.Capabilities...)
		}
	}
	return result
}

// Render emits text, JSON, YAML, or CSV.
func Render(value Matrix, format string) ([]byte, error) {
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
	case "csv":
		return renderCSV(value)
	default:
		return nil, fmt.Errorf("unsupported matrix format %q; use text, json, yaml, or csv", format)
	}
}

func renderText(value Matrix) []byte {
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "Caplock permission matrix\n")
	fmt.Fprintf(&buffer, "Policy: %s\nSubject: %s\nEvaluation time: %s\nDefault effect: %s\n",
		textCell(value.Policy), textCell(value.Subject), textCell(value.EvaluationTime), textCell(value.DefaultEffect))
	fmt.Fprintf(&buffer, "Summary: tools=%d allowed=%d approval_required=%d denied=%d defaulted=%d conditional=%d\n\n",
		value.Summary.Tools, value.Summary.Allowed, value.Summary.ApprovalRequired, value.Summary.Denied, value.Summary.Defaulted, value.Summary.Conditional)
	writer := tabwriter.NewWriter(&buffer, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(writer, "SERVER\tTOOL\tCAPABILITIES\tBASE EFFECT\tRULE\tCONDITIONAL")
	for _, entry := range value.Entries {
		rule := entry.RuleID
		if entry.Default {
			rule = "(default)"
		}
		_, _ = fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%t\n",
			textCell(entry.Server), textCell(entry.Tool), textCell(strings.Join(entry.Capabilities, ",")),
			textCell(entry.Effect), textCell(rule), entry.Conditional)
	}
	_ = writer.Flush()
	return buffer.Bytes()
}

func renderCSV(value Matrix) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{"server", "tool", "capabilities", "baseEffect", "ruleId", "default", "conditional", "candidateRules"}); err != nil {
		return nil, err
	}
	for _, entry := range value.Entries {
		candidates := make([]string, 0, len(entry.CandidateRules))
		for _, candidate := range entry.CandidateRules {
			candidates = append(candidates, candidate.ID)
		}
		if err := writer.Write([]string{
			entry.Server,
			entry.Tool,
			strings.Join(entry.Capabilities, "|"),
			entry.Effect,
			entry.RuleID,
			strconv.FormatBool(entry.Default),
			strconv.FormatBool(entry.Conditional),
			strings.Join(candidates, "|"),
		}); err != nil {
			return nil, err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func textCell(value string) string {
	for _, character := range value {
		if unicode.IsControl(character) {
			return strconv.QuoteToGraphic(value)
		}
	}
	return value
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	return sorted
}
