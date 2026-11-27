// Package report renders deterministic text, JSON, HTML, and SARIF evidence.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"sort"
	"strings"
	"unicode"

	"github.com/1124875284/caplock/internal/evidence"
	"github.com/1124875284/caplock/internal/policy"
)

// Version identifies the report output schema.
const Version = 1

// Summary is the top-level evidence count.
type Summary struct {
	Total            int `json:"total"`
	Passed           int `json:"passed"`
	Failed           int `json:"failed"`
	Blocked          int `json:"blocked"`
	ApprovalRequired int `json:"approvalRequired"`
	Allowed          int `json:"allowed"`
	CriticalGaps     int `json:"criticalGaps"`
	CoveredTools     int `json:"coveredTools"`
	UncoveredTools   int `json:"uncoveredTools"`
}

// BlastRadius summarizes the high- and critical-severity surface that remains
// reachable under the evaluated policy. It reports concrete scope instead of an
// ungrounded numeric risk score.
type BlastRadius struct {
	HighRiskCases            int      `json:"highRiskCases"`
	HighRiskAllowed          int      `json:"highRiskAllowed"`
	HighRiskApprovalRequired int      `json:"highRiskApprovalRequired"`
	HighRiskBlocked          int      `json:"highRiskBlocked"`
	ExposedCases             []string `json:"exposedCases"`
	ExposedTools             []string `json:"exposedTools"`
	ExposedCapabilities      []string `json:"exposedCapabilities"`
	ExposedSinks             []string `json:"exposedSinks"`
}

// PathFinding is one evaluated attack path or authorization scenario.
type PathFinding struct {
	CaseID      string              `json:"caseId"`
	Description string              `json:"description,omitempty"`
	Tags        []string            `json:"tags"`
	Severity    string              `json:"severity"`
	Path        []evidence.PathStep `json:"path"`
	Status      string              `json:"status"`
	Effect      string              `json:"effect"`
	RuleID      string              `json:"ruleId,omitempty"`
	Default     bool                `json:"default"`
	Obligations []string            `json:"obligations"`
	Passed      bool                `json:"passed"`
}

// Gap is a failed expectation or a broken invariant.
type Gap struct {
	Kind     string        `json:"kind"`
	Code     string        `json:"code"`
	CaseID   string        `json:"caseId,omitempty"`
	Severity string        `json:"severity"`
	Message  string        `json:"message"`
	Source   policy.Source `json:"source"`
}

// Report is Caplock's deterministic attack-path and policy-gap artifact.
type Report struct {
	Version         int                        `json:"version"`
	Policy          string                     `json:"policy"`
	Corpus          string                     `json:"corpus"`
	Passed          bool                       `json:"passed"`
	Summary         Summary                    `json:"summary"`
	BlastRadius     BlastRadius                `json:"blastRadius"`
	Paths           []PathFinding              `json:"paths"`
	Gaps            []Gap                      `json:"gaps"`
	Invariants      []evidence.InvariantResult `json:"invariants"`
	Coverage        []evidence.ToolCoverage    `json:"coverage,omitempty"`
	BaselineChanges []evidence.DecisionChange  `json:"baselineChanges,omitempty"`
}

// Build converts an evidence result into a human- and machine-readable report.
func Build(result evidence.Result) Report {
	report := Report{
		Version:         Version,
		Policy:          result.Policy,
		Corpus:          result.Corpus,
		Passed:          result.Passed,
		Paths:           make([]PathFinding, 0, len(result.Cases)),
		Gaps:            []Gap{},
		Invariants:      result.Invariants,
		Coverage:        result.Coverage,
		BaselineChanges: result.BaselineChanges,
	}
	for _, item := range result.Cases {
		report.Summary.Total++
		if item.Passed {
			report.Summary.Passed++
		} else {
			report.Summary.Failed++
			report.Gaps = append(report.Gaps, Gap{
				Kind:     "regression",
				Code:     "case-failure",
				CaseID:   item.ID,
				Severity: item.Severity,
				Message:  strings.Join(item.FailureReasons, "; "),
				Source:   decisionSource(item.Decision),
			})
		}
		status := "allowed"
		switch item.Decision.Effect {
		case policy.EffectDeny:
			status = "blocked"
			report.Summary.Blocked++
		case policy.EffectRequireApproval:
			status = "approval_required"
			report.Summary.ApprovalRequired++
		default:
			report.Summary.Allowed++
		}
		report.Paths = append(report.Paths, PathFinding{
			CaseID:      item.ID,
			Description: item.Description,
			Tags:        nonNil(item.Tags),
			Severity:    item.Severity,
			Path:        nonNilPath(item.Path),
			Status:      status,
			Effect:      item.Decision.Effect,
			RuleID:      item.Decision.RuleID,
			Default:     item.Decision.Default,
			Obligations: nonNil(item.Decision.Obligations),
			Passed:      item.Passed,
		})
	}
	for _, invariant := range result.Invariants {
		for _, violation := range invariant.Violations {
			report.Gaps = append(report.Gaps, Gap{
				Kind:     "invariant",
				Code:     invariant.Code,
				CaseID:   violation.CaseID,
				Severity: "high",
				Message:  violation.Message,
				Source:   policy.Source{File: "caplock.yaml", Line: 1},
			})
		}
	}
	for _, tool := range result.Coverage {
		if tool.Covered {
			report.Summary.CoveredTools++
		} else {
			report.Summary.UncoveredTools++
			report.Gaps = append(report.Gaps, Gap{
				Kind:     "coverage",
				Code:     "tool-coverage",
				Severity: "high",
				Message:  fmt.Sprintf("tool %q on server %q has no tool- or capability-targeted rule", tool.Tool, tool.Server),
				Source:   policy.Source{File: "caplock.yaml", Line: 1},
			})
		}
	}
	sort.SliceStable(report.Paths, func(i, j int) bool {
		left, right := severityRank(report.Paths[i].Severity), severityRank(report.Paths[j].Severity)
		if left != right {
			return left > right
		}
		return report.Paths[i].CaseID < report.Paths[j].CaseID
	})
	sort.SliceStable(report.Gaps, func(i, j int) bool {
		left, right := severityRank(report.Gaps[i].Severity), severityRank(report.Gaps[j].Severity)
		if left != right {
			return left > right
		}
		if report.Gaps[i].Kind != report.Gaps[j].Kind {
			return report.Gaps[i].Kind < report.Gaps[j].Kind
		}
		if report.Gaps[i].CaseID != report.Gaps[j].CaseID {
			return report.Gaps[i].CaseID < report.Gaps[j].CaseID
		}
		return report.Gaps[i].Message < report.Gaps[j].Message
	})
	for _, gap := range report.Gaps {
		if gap.Severity == "critical" {
			report.Summary.CriticalGaps++
		}
	}
	report.BlastRadius = buildBlastRadius(report.Paths)
	return report
}

func buildBlastRadius(paths []PathFinding) BlastRadius {
	result := BlastRadius{
		ExposedCases:        []string{},
		ExposedTools:        []string{},
		ExposedCapabilities: []string{},
		ExposedSinks:        []string{},
	}
	cases := make(map[string]struct{})
	tools := make(map[string]struct{})
	capabilities := make(map[string]struct{})
	sinks := make(map[string]struct{})
	for _, path := range paths {
		if severityRank(path.Severity) < severityRank("high") {
			continue
		}
		result.HighRiskCases++
		switch path.Effect {
		case policy.EffectDeny:
			result.HighRiskBlocked++
			continue
		case policy.EffectRequireApproval:
			result.HighRiskApprovalRequired++
			continue
		default:
			result.HighRiskAllowed++
		}
		cases[path.CaseID] = struct{}{}
		for _, step := range path.Path {
			if step.Tool != "" {
				tools[step.Tool] = struct{}{}
			}
			if step.Sink != "" {
				sinks[step.Sink] = struct{}{}
			}
			for _, capability := range step.Capabilities {
				if capability != "" {
					capabilities[capability] = struct{}{}
				}
			}
		}
	}
	result.ExposedCases = sortedKeys(cases)
	result.ExposedTools = sortedKeys(tools)
	result.ExposedCapabilities = sortedKeys(capabilities)
	result.ExposedSinks = sortedKeys(sinks)
	return result
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys
}

func decisionSource(decision policy.Decision) policy.Source {
	for _, rule := range decision.MatchedRules {
		if rule.ID == decision.RuleID {
			return rule.Source
		}
	}
	return policy.Source{File: "caplock.yaml", Line: 1}
}

// JSON renders the stable report contract.
func JSON(report Report) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Text renders a terminal-friendly attack-path and gap report.
func Text(report Report) []byte {
	var buffer bytes.Buffer
	status := "PASS"
	if !report.Passed {
		status = "FAIL"
	}
	fmt.Fprintf(&buffer, "Caplock evidence report\n")
	fmt.Fprintf(&buffer, "Policy: %s\nCorpus: %s\nResult: %s (%d/%d cases)\n", clean(report.Policy), clean(report.Corpus), status, report.Summary.Passed, report.Summary.Total)
	fmt.Fprintf(&buffer, "Effects: blocked=%d approval_required=%d allowed=%d\n", report.Summary.Blocked, report.Summary.ApprovalRequired, report.Summary.Allowed)
	if report.BlastRadius.HighRiskCases == 0 {
		fmt.Fprintf(&buffer, "Blast radius: no high/critical cases\n")
	} else {
		fmt.Fprintf(&buffer, "Blast radius (high/critical): cases=%d allowed=%d approval_required=%d blocked=%d\n",
			report.BlastRadius.HighRiskCases,
			report.BlastRadius.HighRiskAllowed,
			report.BlastRadius.HighRiskApprovalRequired,
			report.BlastRadius.HighRiskBlocked,
		)
		writeTextList(&buffer, "exposed cases", report.BlastRadius.ExposedCases)
		writeTextList(&buffer, "exposed tools", report.BlastRadius.ExposedTools)
		writeTextList(&buffer, "exposed capabilities", report.BlastRadius.ExposedCapabilities)
		writeTextList(&buffer, "exposed sinks", report.BlastRadius.ExposedSinks)
	}
	if len(report.Coverage) > 0 {
		fmt.Fprintf(&buffer, "Tool coverage: covered=%d uncovered=%d\n", report.Summary.CoveredTools, report.Summary.UncoveredTools)
	}
	fmt.Fprintf(&buffer, "\nAttack paths:\n")
	for _, path := range report.Paths {
		fmt.Fprintf(&buffer, "  [%s] %-6s %s: %s", strings.ToUpper(path.Status), path.Severity, clean(path.CaseID), clean(path.Description))
		if path.RuleID != "" {
			fmt.Fprintf(&buffer, " (rule %s)", clean(path.RuleID))
		} else if path.Default {
			fmt.Fprintf(&buffer, " (default)")
		}
		if !path.Passed {
			fmt.Fprintf(&buffer, " [EXPECTATION FAILED]")
		}
		buffer.WriteByte('\n')
		for _, step := range path.Path {
			if step.Tool != "" || step.Note != "" {
				fmt.Fprintf(&buffer, "    -> %s %s\n", clean(step.Tool), clean(step.Note))
			}
		}
	}
	if len(report.Gaps) == 0 {
		fmt.Fprintf(&buffer, "\nPolicy gaps: none\n")
	} else {
		fmt.Fprintf(&buffer, "\nPolicy gaps:\n")
		for _, gap := range report.Gaps {
			location := clean(gap.Source.File)
			if gap.Source.Line > 0 {
				location += fmt.Sprintf(":%d", gap.Source.Line)
			}
			fmt.Fprintf(&buffer, "  - %s %s %s: %s\n", strings.ToUpper(gap.Severity), clean(gap.Code), location, clean(gap.Message))
		}
	}
	if len(report.BaselineChanges) > 0 {
		fmt.Fprintf(&buffer, "\nBaseline changes:\n")
		for _, change := range report.BaselineChanges {
			fmt.Fprintf(&buffer, "  - %s: %s -> %s\n", clean(change.CaseID), clean(change.OldEffect), clean(change.NewEffect))
		}
	}
	return buffer.Bytes()
}

func writeTextList(buffer *bytes.Buffer, label string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(buffer, "  %s: %s\n", label, clean(strings.Join(values, ", ")))
}

// HTML renders a dependency-free local report.
func HTML(report Report) ([]byte, error) {
	var buffer bytes.Buffer
	if err := htmlTemplate.Execute(&buffer, report); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// SARIF renders policy gaps as SARIF 2.1.0 results.
func SARIF(report Report) ([]byte, error) {
	results := make([]sarifResult, 0, len(report.Gaps))
	for _, gap := range report.Gaps {
		line := gap.Source.Line
		if line < 1 {
			line = 1
		}
		results = append(results, sarifResult{
			RuleID:  "caplock.policy-regression",
			Level:   sarifLevel(gap.Severity),
			Message: sarifMessage{Text: gap.Code + ": " + gap.Message},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: gap.Source.File},
				Region:           sarifRegion{StartLine: line},
			}}},
			Properties: map[string]any{"caseId": gap.CaseID, "severity": gap.Severity, "kind": gap.Kind},
		})
	}
	document := sarifDocument{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "Caplock",
				InformationURI: "https://caplock.dev",
				Rules: []sarifRule{{
					ID:               "caplock.policy-regression",
					Name:             "PolicyRegressionGap",
					ShortDescription: sarifMessage{Text: "A policy regression or invariant gap"},
				}},
			}},
			Results: results,
		}},
	}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func severityRank(value string) int {
	switch value {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func sarifLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonNilPath(values []evidence.PathStep) []evidence.PathStep {
	if values == nil {
		return []evidence.PathStep{}
	}
	return values
}

func clean(value string) string {
	var builder strings.Builder
	for _, character := range value {
		switch character {
		case '\n':
			builder.WriteString(`\n`)
		case '\r':
			builder.WriteString(`\r`)
		case '\t':
			builder.WriteString(`\t`)
		default:
			if unicode.IsControl(character) || unicode.In(character, unicode.Cf, unicode.Zl, unicode.Zp) {
				_, _ = fmt.Fprintf(&builder, `\u%04x`, character)
				continue
			}
			builder.WriteRune(character)
		}
	}
	return builder.String()
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper": strings.ToUpper,
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Caplock evidence report</title>
  <style>
    body { font: 15px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 1100px; padding: 0 1rem; color: #1f2937; }
    h1, h2 { line-height: 1.2; }
    .pass { color: #047857; } .fail { color: #b91c1c; }
    table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
    th, td { border: 1px solid #d1d5db; padding: .5rem; text-align: left; vertical-align: top; }
    th { background: #f3f4f6; }
    code { background: #f3f4f6; padding: .1rem .25rem; border-radius: .2rem; }
    .blocked { color: #047857; } .approval_required { color: #b45309; } .allowed { color: #b91c1c; }
  </style>
</head>
<body>
  <h1>Caplock evidence report</h1>
  <p>Policy <code>{{.Policy}}</code> · corpus <code>{{.Corpus}}</code></p>
  <p class="{{if .Passed}}pass{{else}}fail{{end}}"><strong>{{if .Passed}}PASS{{else}}FAIL{{end}}</strong> — {{.Summary.Passed}}/{{.Summary.Total}} cases passed.</p>
  <p>Blocked {{.Summary.Blocked}} · approval required {{.Summary.ApprovalRequired}} · allowed {{.Summary.Allowed}} · critical gaps {{.Summary.CriticalGaps}}</p>
  <h2>Blast radius</h2>
  {{if .BlastRadius.HighRiskCases}}
  <p>High/critical cases {{.BlastRadius.HighRiskCases}}: allowed {{.BlastRadius.HighRiskAllowed}} · approval required {{.BlastRadius.HighRiskApprovalRequired}} · blocked {{.BlastRadius.HighRiskBlocked}}</p>
  {{if .BlastRadius.ExposedCases}}<p><strong>Exposed cases:</strong> {{range .BlastRadius.ExposedCases}}<code>{{.}}</code> {{end}}</p>{{end}}
  {{if .BlastRadius.ExposedTools}}<p><strong>Exposed tools:</strong> {{range .BlastRadius.ExposedTools}}<code>{{.}}</code> {{end}}</p>{{end}}
  {{if .BlastRadius.ExposedCapabilities}}<p><strong>Exposed capabilities:</strong> {{range .BlastRadius.ExposedCapabilities}}<code>{{.}}</code> {{end}}</p>{{end}}
  {{if .BlastRadius.ExposedSinks}}<p><strong>Exposed sinks:</strong> {{range .BlastRadius.ExposedSinks}}<code>{{.}}</code> {{end}}</p>{{end}}
  {{else}}<p>No high/critical cases.</p>{{end}}
  {{if .Coverage}}<p>Tool coverage: {{.Summary.CoveredTools}} covered, {{.Summary.UncoveredTools}} uncovered.</p>{{end}}

  <h2>Attack paths</h2>
  <table>
    <thead><tr><th>Case</th><th>Severity</th><th>Status</th><th>Rule</th><th>Path</th></tr></thead>
    <tbody>
    {{range .Paths}}
      <tr>
        <td><code>{{.CaseID}}</code><br>{{.Description}}{{if not .Passed}}<br><strong class="fail">expectation failed</strong>{{end}}</td>
        <td>{{upper .Severity}}</td>
        <td class="{{.Status}}">{{.Status}}{{if .Default}} (default){{end}}</td>
        <td>{{if .RuleID}}<code>{{.RuleID}}</code>{{else}}—{{end}}</td>
        <td>{{range .Path}}{{if .Tool}}<code>{{.Tool}}</code> {{end}}{{.Note}}<br>{{end}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>

  <h2>Policy gaps</h2>
  {{if .Gaps}}
  <ul>{{range .Gaps}}<li><strong>{{upper .Severity}}</strong> <code>{{.Code}}</code> {{.Message}} <small>({{.Source.File}}:{{.Source.Line}})</small></li>{{end}}</ul>
  {{else}}<p>None.</p>{{end}}

  {{if .BaselineChanges}}
  <h2>Baseline changes</h2>
  <ul>{{range .BaselineChanges}}<li><code>{{.CaseID}}</code>: {{.OldEffect}} → {{.NewEffect}}</li>{{end}}</ul>
  {{end}}
</body>
</html>`))

type sarifDocument struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}
