package proxy

import (
	"strings"
	"testing"
	"time"

	"github.com/1124875284/caplock/internal/policy"
)

const obligationPolicy = `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: obligations
spec:
  defaults:
    effect: deny
  rules:
    - id: allow-read-with-obligations
      effect: allow
      match:
        capability: [read]
      obligations: [rate_limit, alert]
`

func TestRateLimitObligationFailsClosedAndEnforcesBudget(t *testing.T) {
	ir, err := policy.Compile([]byte(obligationPolicy), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	withoutLimiter, err := NewEngine(Options{Policy: ir, Subject: "agent", AlertEnabled: true, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	decision, err := withoutLimiter.Decide("read_file", nil)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if decision.Forward || !decision.RuntimeBlocked || !strings.Contains(decision.Reason, "rate_limit") {
		t.Fatalf("without limiter = %#v", decision)
	}

	limiter, err := NewRateLimiter(1, time.Minute)
	if err != nil {
		t.Fatalf("NewRateLimiter() error = %v", err)
	}
	engine, err := NewEngine(Options{Policy: ir, Subject: "agent", AlertEnabled: true, RateLimiter: limiter, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	first, err := engine.Decide("read_file", nil)
	if err != nil {
		t.Fatalf("Decide(first) error = %v", err)
	}
	if !first.Forward || first.RuntimeBlocked {
		t.Fatalf("first decision = %#v", first)
	}
	second, err := engine.Decide("read_file", nil)
	if err != nil {
		t.Fatalf("Decide(second) error = %v", err)
	}
	if second.Forward || !second.RuntimeBlocked || !strings.Contains(second.Reason, "rate_limit exceeded") {
		t.Fatalf("second decision = %#v", second)
	}
}

func TestAlertObligationRequiresSink(t *testing.T) {
	ir, err := policy.Compile([]byte(obligationPolicy), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	limiter, _ := NewRateLimiter(10, time.Minute)
	withoutAlert, err := NewEngine(Options{Policy: ir, Subject: "agent", RateLimiter: limiter})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	decision, err := withoutAlert.Decide("read_file", nil)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if decision.Forward || !decision.RuntimeBlocked || !strings.Contains(decision.Reason, "alert obligation") {
		t.Fatalf("without alert = %#v", decision)
	}
	withAlert, err := NewEngine(Options{Policy: ir, Subject: "agent", RateLimiter: limiter, AlertEnabled: true})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	decision, err = withAlert.Decide("read_file", nil)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if !decision.Forward {
		t.Fatalf("with alert = %#v", decision)
	}
	record := withAlert.Alert(decision)
	if record.Tool != "read_file" || record.RuleID != "allow-read-with-obligations" || record.ArgsHash == "" {
		t.Fatalf("alert record = %#v", record)
	}
}

func TestTraceRecordRedactsExplicitFields(t *testing.T) {
	engine := testEngine(t, ApprovalBlock, nil)
	engine.traceRedact = []string{"token", "nested.password"}
	decision := Decision{Tool: "read_file", ArgsHash: "sha256:" + strings.Repeat("a", 64), Policy: policy.Decision{Effect: policy.EffectAllow, Obligations: []string{}}}
	record := engine.TraceRecord(decision, map[string]any{"token": "raw", "nested": map[string]any{"password": "raw", "safe": "ok"}}, true)
	if record.Args["token"] != "[REDACTED]" || record.Args["nested"].(map[string]any)["password"] != "[REDACTED]" {
		t.Fatalf("trace args = %#v", record.Args)
	}
	if len(record.RedactedFields) != 2 || record.RedactedFields[0] != "nested.password" || record.RedactedFields[1] != "token" {
		t.Fatalf("redacted fields = %#v", record.RedactedFields)
	}
}
