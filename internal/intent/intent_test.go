package intent

import (
	"bytes"
	"strings"
	"testing"

	"github.com/1124875284/caplock/internal/policy"
)

func TestCompileEnglishBrief(t *testing.T) {
	brief := `# Finance agent
Child agents must not exceed their parent permissions.
Deny destructive tool calls.
Deny shell command execution.
Deny secret data from leaving through email, network, or upload tools.
Finance tools are forbidden outside Mon-Fri 09:00-18:00 Asia/Shanghai.
External web content must not flow to email tools.
Require approval for all write operations.
Allow read-only operations.
`
	result, err := Compile([]byte(brief), Options{Name: "finance-draft", Subject: "finance-analyst", Parent: "orchestrator"})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if result.Document.Metadata.Name != "finance-draft" || result.Document.Spec == nil {
		t.Fatalf("document = %#v", result.Document)
	}
	if len(*result.Document.Spec.Rules) != 7 {
		t.Fatalf("rule count = %d, want 7", len(*result.Document.Spec.Rules))
	}
	if len(result.Document.Spec.Subjects) != 2 {
		t.Fatalf("subjects = %#v", result.Document.Spec.Subjects)
	}
	child := findSubject(t, result.Document.Spec.Subjects, "finance-analyst")
	if child.Parent != "orchestrator" || child.Delegation != policy.DelegationAttenuateOnly {
		t.Fatalf("child subject = %#v", child)
	}
	finance := findRule(t, *result.Document.Spec.Rules, "finance-write-after-hours")
	if finance.Match.Context == nil || finance.Match.Context.Time == nil || finance.Match.Context.Time.Outside != "Mon-Fri 09:00-18:00 Asia/Shanghai" {
		t.Fatalf("finance rule = %#v", finance)
	}
	egress := findRule(t, *result.Document.Spec.Rules, "deny-external-provenance-egress")
	if egress.Match.Sink != "email.send" || len(egress.Match.Provenance.Contains) != 1 || egress.Match.Provenance.Contains[0] != "external_web" {
		t.Fatalf("egress rule = %#v", egress)
	}
	assertGeneratedPolicyCompiles(t, result)
}

func TestCompileChineseBrief(t *testing.T) {
	brief := `子 Agent 权限不得超过父 Agent。
财务类工具禁止在非工作时间调用。
外部网页内容不得流入发邮件工具。
`
	result, err := Compile([]byte(brief), Options{Name: "cn-draft", Subject: "finance-analyst", Parent: "orchestrator"})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if len(*result.Document.Spec.Rules) != 2 {
		t.Fatalf("rules = %#v", *result.Document.Spec.Rules)
	}
	finance := findRule(t, *result.Document.Spec.Rules, "finance-write-after-hours")
	if finance.Match.Context.Time.Outside != DefaultWindow {
		t.Fatalf("default window = %q", finance.Match.Context.Time.Outside)
	}
	egress := findRule(t, *result.Document.Spec.Rules, "deny-external-provenance-egress")
	if egress.Match.Sink != "email.send" {
		t.Fatalf("sink = %q", egress.Match.Sink)
	}
	assertGeneratedPolicyCompiles(t, result)
}

func TestCompileTemplateOverrideAndErrors(t *testing.T) {
	brief := `@template require-approval-pii-egress
Personal data must be reviewed before it leaves the agent.
`
	result, err := Compile([]byte(brief), Options{})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	rule := findRule(t, *result.Document.Spec.Rules, "approve-pii-egress")
	if rule.Effect != policy.EffectRequireApproval || len(rule.Match.DataClass) != 1 || rule.Match.DataClass[0] != "pii" {
		t.Fatalf("rule = %#v", rule)
	}

	_, err = Compile([]byte("Make everything safe.\n"), Options{})
	if err == nil || !strings.Contains(err.Error(), "no template matched") {
		t.Fatalf("error = %v", err)
	}
}

func TestEveryTemplateBuildsValidPolicy(t *testing.T) {
	for _, info := range Templates() {
		t.Run(info.ID, func(t *testing.T) {
			brief := "@template " + info.ID + "\n" + info.Example + "\n"
			result, err := Compile([]byte(brief), Options{Name: "template-" + info.ID})
			if err != nil {
				t.Fatalf("Compile() error = %v", err)
			}
			assertGeneratedPolicyCompiles(t, result)
		})
	}
}

func TestTemplateExamplesAutoMatch(t *testing.T) {
	for _, info := range Templates() {
		t.Run(info.ID, func(t *testing.T) {
			result, err := Compile([]byte(info.Example+"\n"), Options{Name: "example-" + info.ID})
			if err != nil {
				t.Fatalf("Compile() error = %v", err)
			}
			if len(result.Matches) != 1 || result.Matches[0].Template != info.ID {
				t.Fatalf("matches = %#v, want template %q", result.Matches, info.ID)
			}
		})
	}
}

func TestCompileDeterministic(t *testing.T) {
	brief := []byte("Deny destructive tool calls.\nRequire approval for all write operations.\n")
	first, err := Compile(brief, Options{Name: "stable"})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	firstData, err := Render(first)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	for range 10 {
		next, err := Compile(brief, Options{Name: "stable"})
		if err != nil {
			t.Fatalf("Compile() error = %v", err)
		}
		nextData, err := Render(next)
		if err != nil {
			t.Fatalf("Render() error = %v", err)
		}
		if !bytes.Equal(firstData, nextData) {
			t.Fatal("draft output is not deterministic")
		}
	}
}

func assertGeneratedPolicyCompiles(t *testing.T, result Result) {
	t.Helper()
	data, err := Render(result)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	ir, err := policy.Compile(data, "draft.yaml")
	if err != nil {
		t.Fatalf("generated policy did not compile: %v\n%s", err, data)
	}
	issues := policy.Lint(ir, "draft.yaml")
	if policy.HasErrors(issues) {
		t.Fatalf("generated policy has lint errors: %#v\n%s", issues, data)
	}
}

func findRule(t *testing.T, rules []policy.Rule, id string) policy.Rule {
	t.Helper()
	for _, rule := range rules {
		if rule.ID == id {
			return rule
		}
	}
	t.Fatalf("rule %q not found in %#v", id, rules)
	return policy.Rule{}
}

func findSubject(t *testing.T, subjects []policy.Subject, id string) policy.Subject {
	t.Helper()
	for _, subject := range subjects {
		if subject.ID == id {
			return subject
		}
	}
	t.Fatalf("subject %q not found in %#v", id, subjects)
	return policy.Subject{}
}
