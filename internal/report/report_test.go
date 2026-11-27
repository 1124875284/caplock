package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/1124875284/caplock/internal/evidence"
	"github.com/1124875284/caplock/internal/policy"
)

func TestBuildPassingReport(t *testing.T) {
	result := evidence.Result{
		Version:     evidence.Version,
		Policy:      "demo",
		Corpus:      "baseline",
		Passed:      true,
		Total:       1,
		PassedCount: 1,
		Cases: []evidence.CaseResult{{
			ID:          "injection-email",
			Description: "external to email",
			Tags:        []string{"exfiltration"},
			Severity:    "high",
			Path:        []evidence.PathStep{{Tool: "email.send", Note: "egress"}},
			Decision: policy.Decision{
				Effect:      policy.EffectRequireApproval,
				RuleID:      "approve-egress",
				Obligations: []string{"human_approval"},
			},
			Passed: true,
		}},
		Invariants: []evidence.InvariantResult{{Code: "delegation-attenuation", Passed: true, Violations: []evidence.InvariantViolation{}}},
	}
	document := Build(result)
	if !document.Passed || document.Summary.ApprovalRequired != 1 || len(document.Paths) != 1 || len(document.Gaps) != 0 {
		t.Fatalf("report = %#v", document)
	}
	if document.BlastRadius.HighRiskCases != 1 || document.BlastRadius.HighRiskApprovalRequired != 1 || document.BlastRadius.HighRiskAllowed != 0 {
		t.Fatalf("blast radius = %#v", document.BlastRadius)
	}
	data, err := JSON(document)
	if err != nil {
		t.Fatalf("JSON() error = %v", err)
	}
	if !strings.HasSuffix(string(data), "\n") || !strings.Contains(string(data), `"status": "approval_required"`) || !strings.Contains(string(data), `"blastRadius"`) {
		t.Fatalf("JSON = %s", data)
	}
	if text := string(Text(document)); !strings.Contains(text, "Policy gaps: none") || !strings.Contains(text, "Blast radius (high/critical)") {
		t.Fatalf("text = %s", text)
	}
	html, err := HTML(document)
	if err != nil {
		t.Fatalf("HTML() error = %v", err)
	}
	if !strings.Contains(string(html), "Caplock evidence report") || !strings.Contains(string(html), "approval_required") {
		t.Fatalf("HTML = %s", html)
	}
}

func TestReportGapsAndSARIF(t *testing.T) {
	defaultDecision := policy.Decision{Effect: policy.EffectAllow, Default: true, Obligations: []string{}, MatchedRules: []policy.MatchedRule{}}
	result := evidence.Result{
		Policy: "demo",
		Corpus: "baseline",
		Cases: []evidence.CaseResult{{
			ID:          "unsafe-allow",
			Description: "<script>alert(1)</script>",
			Severity:    "critical",
			Path: []evidence.PathStep{{
				Tool:         "database.delete",
				Capabilities: []string{"destructive", "write"},
				Sink:         "database.production",
			}},
			Decision:       defaultDecision,
			Passed:         false,
			FailureReasons: []string{"effect allow, expected deny"},
		}},
		Invariants: []evidence.InvariantResult{{
			Code:   "delegation-attenuation",
			Passed: false,
			Violations: []evidence.InvariantViolation{{
				CaseID:  "unsafe-allow",
				Subject: "child",
				Parent:  "parent",
				Message: "child effect allow exceeds parent effect deny",
			}},
		}},
		Coverage: []evidence.ToolCoverage{{Server: "demo", Tool: "mystery", Covered: false}},
	}
	document := Build(result)
	if document.Passed {
		t.Fatalf("Passed must be false: %#v", document)
	}
	if len(document.Gaps) != 3 || document.Summary.CriticalGaps != 1 || document.Summary.UncoveredTools != 1 {
		t.Fatalf("summary=%#v gaps=%#v", document.Summary, document.Gaps)
	}
	if document.BlastRadius.HighRiskCases != 1 || document.BlastRadius.HighRiskAllowed != 1 || len(document.BlastRadius.ExposedSinks) != 1 || document.BlastRadius.ExposedSinks[0] != "database.production" {
		t.Fatalf("blast radius = %#v", document.BlastRadius)
	}
	html, err := HTML(document)
	if err != nil {
		t.Fatalf("HTML() error = %v", err)
	}
	if strings.Contains(string(html), "<script>alert(1)</script>") {
		t.Fatalf("HTML did not escape case description: %s", html)
	}
	sarif, err := SARIF(document)
	if err != nil {
		t.Fatalf("SARIF() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(sarif, &decoded); err != nil {
		t.Fatalf("decode SARIF: %v\n%s", err, sarif)
	}
	runs := decoded["runs"].([]any)
	results := runs[0].(map[string]any)["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("SARIF results = %d, want 3", len(results))
	}
}

func TestTextEscapesControlCharacters(t *testing.T) {
	document := Build(evidence.Result{Policy: "safe\npolicy", Corpus: "corpus", Cases: []evidence.CaseResult{}, Invariants: []evidence.InvariantResult{}})
	if text := string(Text(document)); !strings.Contains(text, `safe\npolicy`) {
		t.Fatalf("text = %q", text)
	}
}
