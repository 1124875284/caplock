package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const validPolicy = `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: finance-agent
  owner: security
spec:
  defaults:
    effect: deny
  subjects:
    - id: orchestrator
    - id: finance-analyst
      parent: orchestrator
      delegation: attenuate-only
  rules:
    - id: finance-write-after-hours
      effect: deny
      match:
        capability: [finance.write, finance.approve]
        context:
          time:
            outside: "Mon-Fri 09:00-18:00 Asia/Shanghai"
      obligations: [audit, alert]
    - id: external-to-email
      effect: require_approval
      match:
        sink: email.send
        provenance:
          contains: external_web
      obligations: [human_approval, redact]
`

func TestCompileNormalizesPolicy(t *testing.T) {
	ir, err := Compile([]byte(validPolicy), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if got, want := ir.Policy, "finance-agent"; got != want {
		t.Fatalf("policy = %q, want %q", got, want)
	}
	if got, want := ir.Subjects[0].ID, "finance-analyst"; got != want {
		t.Fatalf("first subject = %q, want %q", got, want)
	}
	if got, want := ir.Rules[0].Match.Capability, []string{"finance.approve", "finance.write"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %#v, want %#v", got, want)
	}
	if got, want := ir.Rules[0].Obligations, []string{"alert", "audit"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("obligations = %#v, want %#v", got, want)
	}
	if got, want := ir.Rules[1].Match.Provenance.Contains, (StringList{"external_web"}); !reflect.DeepEqual(got, want) {
		t.Fatalf("provenance = %#v, want %#v", got, want)
	}
	if got, want := ir.Rules[0].Source.Line, 15; got != want {
		t.Fatalf("source line = %d, want %d", got, want)
	}
	if ir.Rules[0].Source.File != "caplock.yaml" {
		t.Fatalf("source file = %q", ir.Rules[0].Source.File)
	}

	first, err := json.MarshalIndent(ir, "", "  ")
	if err != nil {
		t.Fatalf("marshal IR: %v", err)
	}
	for range 10 {
		next, err := Compile([]byte(validPolicy), "caplock.yaml")
		if err != nil {
			t.Fatalf("Compile() error = %v", err)
		}
		nextJSON, err := json.MarshalIndent(next, "", "  ")
		if err != nil {
			t.Fatalf("marshal IR: %v", err)
		}
		if !bytes.Equal(first, nextJSON) {
			t.Fatalf("policy compilation is not deterministic:\n%s\n%s", first, nextJSON)
		}
	}
}

func TestCompileAcceptsJSONAndEmptyRules(t *testing.T) {
	source := `{"apiVersion":"caplock/v1alpha1","kind":"PolicySet","metadata":{"name":"json-policy"},"spec":{"defaults":{"effect":"deny"},"rules":[]}}`
	ir, err := Compile([]byte(source), "policy.json")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if ir.Rules == nil || len(ir.Rules) != 0 {
		t.Fatalf("rules = %#v, want empty array", ir.Rules)
	}
	if ir.Subjects == nil || len(ir.Subjects) != 0 {
		t.Fatalf("subjects = %#v, want empty array", ir.Subjects)
	}
}

func TestCompileExampleGolden(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "examples", "policy", "caplock.yaml"))
	if err != nil {
		t.Fatalf("read example policy: %v", err)
	}
	golden, err := os.ReadFile(filepath.Join("..", "..", "examples", "policy", "policy.ir.json"))
	if err != nil {
		t.Fatalf("read example IR: %v", err)
	}
	ir, err := Compile(source, Name)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if issues := Lint(ir, Name); len(issues) != 0 {
		t.Fatalf("example policy lint findings = %#v", issues)
	}
	got, err := json.MarshalIndent(ir, "", "  ")
	if err != nil {
		t.Fatalf("marshal IR: %v", err)
	}
	got = append(got, '\n')
	if !bytes.Equal(got, golden) {
		t.Fatalf("example IR does not match golden file:\n--- got ---\n%s\n--- want ---\n%s", got, golden)
	}
}

func TestCompileRejectsInvalidPolicies(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{name: "empty", source: "", want: "policy is empty"},
		{name: "wrong api", source: strings.Replace(validPolicy, "caplock/v1alpha1", "caplock/v2", 1), want: "apiVersion"},
		{name: "wrong kind", source: strings.Replace(validPolicy, "PolicySet", "Policy", 1), want: "kind"},
		{name: "missing spec", source: "apiVersion: caplock/v1alpha1\nkind: PolicySet\nmetadata:\n  name: x\n", want: "spec is required"},
		{name: "missing rules", source: "apiVersion: caplock/v1alpha1\nkind: PolicySet\nmetadata:\n  name: x\nspec:\n  defaults:\n    effect: deny\n", want: "spec.rules must be an array"},
		{name: "bad default", source: strings.Replace(validPolicy, "effect: deny", "effect: sometimes", 1), want: "defaults.effect"},
		{name: "unknown top field", source: validPolicy + "\nextra: true\n", want: "field extra not found"},
		{name: "duplicate rule", source: strings.Replace(validPolicy, "external-to-email", "finance-write-after-hours", 1), want: "duplicate rule id"},
		{name: "bad priority", source: minimalPolicy("rules:\n    - id: bad\n      effect: deny\n      priority: -1\n      match:\n        tool: [read_file]\n"), want: "priority"},
		{name: "empty match", source: minimalPolicy("rules:\n    - id: empty\n      effect: deny\n      match:\n        capability: []\n"), want: "at least one condition"},
		{name: "bad obligation", source: strings.Replace(validPolicy, "obligations: [audit, alert]", "obligations: [audit, panic]", 1), want: "unknown obligation"},
		{name: "empty provenance", source: strings.Replace(validPolicy, "contains: external_web", "contains: []", 1), want: "provenance.contains"},
		{name: "multiple documents", source: validPolicy + "\n---\n" + validPolicy, want: "multiple YAML documents"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile([]byte(test.source), "caplock.yaml")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Compile() error = %v, want it to contain %q", err, test.want)
			}
		})
	}
}

func minimalPolicy(spec string) string {
	return "apiVersion: caplock/v1alpha1\nkind: PolicySet\nmetadata:\n  name: test\nspec:\n  defaults:\n    effect: deny\n  " + spec
}

func TestLintPolicy(t *testing.T) {
	ir, err := Compile([]byte(validPolicy), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if issues := Lint(ir, "caplock.yaml"); len(issues) != 0 {
		t.Fatalf("valid policy lint findings = %#v", issues)
	}
}

func TestLintFindsReviewIssues(t *testing.T) {
	source := `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: risky
spec:
  defaults:
    effect: allow
  subjects:
    - id: root
      parent: child
      delegation: attenuate-only
    - id: child
      parent: root
  rules:
    - id: broad
      effect: allow
      match:
        subject: missing
    - id: wildcard
      effect: deny
      match:
        capability: ["*"]
    - id: conflict-a
      effect: allow
      match:
        tool: [read_file]
    - id: conflict-b
      effect: deny
      match:
        tool: [read_file]
`
	ir, err := Compile([]byte(source), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	issues := Lint(ir, "caplock.yaml")
	codes := make(map[string]bool)
	for _, issue := range issues {
		codes[issue.Code] = true
	}
	for _, code := range []string{"default-allow", "subject-cycle", "unknown-rule-subject", "wildcard-match", "broad-allow", "conflicting-effects"} {
		if !codes[code] {
			t.Fatalf("missing %q in findings: %#v", code, issues)
		}
	}
	if !HasErrors(issues) {
		t.Fatal("HasErrors() = false")
	}
	if issues[0].Severity != SeverityError {
		t.Fatalf("first finding = %#v, want error first", issues[0])
	}
}

func TestLintUnknownParentAndOrphanDelegation(t *testing.T) {
	source := `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: delegation
spec:
  defaults:
    effect: deny
  subjects:
    - id: child
      parent: missing
      delegation: attenuate-only
    - id: orphan
      delegation: attenuate-only
  rules: []
`
	ir, err := Compile([]byte(source), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	issues := Lint(ir, "caplock.yaml")
	seen := make(map[string]bool)
	for _, issue := range issues {
		seen[issue.Code] = true
	}
	if !seen["unknown-parent"] || !seen["orphan-delegation"] {
		t.Fatalf("findings = %#v", issues)
	}
}

func TestLintFindsShadowedAndEmptyRules(t *testing.T) {
	source := `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: shadows
spec:
  defaults:
    effect: deny
  rules:
    - id: deny-reads
      effect: deny
      match:
        capability: [read]
    - id: allow-read
      effect: allow
      match:
        capability: [read]
`
	ir, err := Compile([]byte(source), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	ir.Rules = append(ir.Rules, Rule{ID: "catch-all", Effect: EffectRequireApproval, Match: &Match{}, Source: Source{File: "caplock.yaml", Line: 30}})
	issues := Lint(ir, "caplock.yaml")
	seen := make(map[string][]Issue)
	for _, issue := range issues {
		seen[issue.Code] = append(seen[issue.Code], issue)
	}
	if len(seen["shadowed-rule"]) == 0 || seen["shadowed-rule"][0].RuleID != "allow-read" {
		t.Fatalf("shadowed findings = %#v", issues)
	}
	if len(seen["empty-match"]) == 0 {
		t.Fatalf("empty-match findings = %#v", issues)
	}
}

func FuzzCompile(f *testing.F) {
	f.Add([]byte(validPolicy))
	f.Add([]byte(`{"apiVersion":"caplock/v1alpha1","kind":"PolicySet","metadata":{"name":"x"},"spec":{"defaults":{"effect":"deny"},"rules":[]}}`))
	f.Add([]byte("{"))
	f.Fuzz(func(_ *testing.T, input []byte) {
		_, _ = Compile(input, "caplock.yaml")
	})
}
