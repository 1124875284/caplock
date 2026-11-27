package policy

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEvaluateDefaultAndEffectPrecedence(t *testing.T) {
	ir, err := Compile([]byte(minimalPolicy(`rules:
  - id: allow-write
    effect: allow
    priority: 100
    match:
      tool: [write_file]
  - id: approve-write
    effect: require_approval
    priority: 50
    match:
      tool: [write_file]
  - id: deny-write-low
    effect: deny
    priority: 1
    match:
      tool: [write_file]
  - id: deny-write-high
    effect: deny
    priority: 2
    match:
      tool: [write_file]
`)), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	decision, err := Evaluate(ir, Request{Subject: "agent", Tool: "write_file"})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Effect != EffectDeny || decision.RuleID != "deny-write-high" || decision.Default {
		t.Fatalf("decision = %#v", decision)
	}
	if len(decision.MatchedRules) != 4 {
		t.Fatalf("matched rules = %#v", decision.MatchedRules)
	}

	decision, err = Evaluate(ir, Request{Subject: "agent", Tool: "read_file"})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Effect != EffectDeny || decision.RuleID != "" || !decision.Default {
		t.Fatalf("default decision = %#v", decision)
	}
	if decision.Obligations == nil || decision.MatchedRules == nil {
		t.Fatalf("default decision must use empty arrays: %#v", decision)
	}
}

func TestEvaluatePriorityTieUsesSourceOrder(t *testing.T) {
	ir, err := Compile([]byte(minimalPolicy(`rules:
  - id: first
    effect: deny
    match: {tool: [run]}
  - id: second
    effect: deny
    match: {tool: [run]}
`)), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	decision, err := Evaluate(ir, Request{Tool: "run"})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.RuleID != "first" {
		t.Fatalf("rule = %q, want first", decision.RuleID)
	}
}

func TestEvaluateSelectorsAndProvenance(t *testing.T) {
	ir, err := Compile([]byte(minimalPolicy(`rules:
  - id: external-egress
    effect: require_approval
    match:
      capability: [comms, external]
      dataClass: [public, secret]
      sink: "*"
      provenance:
        contains: external_web
`)), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	request := Request{
		Tool:         "email.send",
		Capabilities: []string{"comms", "network"},
		DataClass:    []string{"secret"},
		Sink:         "email.send",
		Provenance:   []string{"external_web"},
	}
	decision, err := Evaluate(ir, request)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Effect != EffectRequireApproval || decision.RuleID != "external-egress" {
		t.Fatalf("decision = %#v", decision)
	}
	request.Provenance = nil
	decision, err = Evaluate(ir, request)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !decision.Default {
		t.Fatalf("decision = %#v, want default", decision)
	}
}

func TestEvaluateArgumentSelectors(t *testing.T) {
	ir, err := Compile([]byte(minimalPolicy(`rules:
  - id: dangerous-command
    effect: deny
    match:
      args:
        command: {"$regex": "(?i)rm\\s+-rf"}
        path: {"$prefix": "/etc/"}
        files: {"$contains": "secrets"}
        role: {"$in": [admin, owner]}
        approved: {"$exists": true}
`)), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	request := Request{Args: map[string]any{
		"command":  "sudo rm -rf /tmp/work",
		"path":     "/etc/caplock/config",
		"files":    []any{"public.txt", "secrets.txt"},
		"role":     "admin",
		"approved": false,
	}}
	decision, err := Evaluate(ir, request)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Effect != EffectDeny || decision.RuleID != "dangerous-command" {
		t.Fatalf("decision = %#v", decision)
	}
	request.Args["role"] = "viewer"
	decision, err = Evaluate(ir, request)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !decision.Default {
		t.Fatalf("decision = %#v, want default", decision)
	}
}

func TestEvaluateTimeWindow(t *testing.T) {
	ir, err := Compile([]byte(validPolicy), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	request := Request{
		Tool:         "finance.approve",
		Capabilities: []string{"finance.approve"},
		Context: RequestContext{
			Time: time.Date(2026, time.November, 24, 20, 0, 0, 0, time.FixedZone("CST", 8*60*60)),
		},
	}
	decision, err := Evaluate(ir, request)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Effect != EffectDeny || decision.RuleID != "finance-write-after-hours" {
		t.Fatalf("after-hours decision = %#v", decision)
	}
	request.Context.Time = time.Date(2026, time.November, 24, 10, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	decision, err = Evaluate(ir, request)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if decision.Effect != EffectDeny || !decision.Default {
		t.Fatalf("business-hours decision = %#v, want default deny", decision)
	}
}

func TestEvaluateDeterministicTrace(t *testing.T) {
	ir, err := Compile([]byte(minimalPolicy(`rules:
  - id: one
    effect: require_approval
    match: {capability: [write, network]}
  - id: two
    effect: allow
    match: {tool: [write_file]}
`)), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	request := Request{Tool: "write_file", Capabilities: []string{"network", "write"}}
	first, err := Evaluate(ir, request)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	for range 20 {
		next, err := Evaluate(ir, request)
		if err != nil {
			t.Fatalf("Evaluate() error = %v", err)
		}
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("decisions differ:\n%#v\n%#v", first, next)
		}
	}
}

func TestCompileRejectsInvalidTimeAndArgumentSelectors(t *testing.T) {
	tests := []struct {
		name string
		rule string
		want string
	}{
		{name: "time", rule: `  - id: bad
    effect: deny
    match:
      context:
        time: {outside: "sometimes"}
`, want: "time window"},
		{name: "regex", rule: `  - id: bad
    effect: deny
    match:
      args:
        command: {"$regex": "("}
`, want: "regex"},
		{name: "operator", rule: `  - id: bad
    effect: deny
    match:
      args:
        command: {"$unknown": true}
`, want: "unknown argument operator"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Compile([]byte(minimalPolicy("rules:\n"+test.rule)), "caplock.yaml")
			if err == nil {
				t.Fatal("Compile() error = nil")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %q, want %q", err, test.want)
			}
		})
	}
}
