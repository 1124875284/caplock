package proxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/1124875284/caplock/internal/lockfile"
	"github.com/1124875284/caplock/internal/policy"
)

const enginePolicy = `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: proxy-test
spec:
  defaults:
    effect: deny
  subjects:
    - id: agent
  rules:
    - id: allow-read
      effect: allow
      match:
        capability: [read]
    - id: deny-destructive
      effect: deny
      match:
        capability: [destructive]
    - id: approve-email
      effect: require_approval
      match:
        sink: email.send
      obligations: [audit, human_approval, redact]
`

func testEngine(t *testing.T, mode ApprovalMode, lock *lockfile.File) *Engine {
	t.Helper()
	return testEngineWithRedaction(t, mode, lock, nil)
}

func testEngineWithRedaction(t *testing.T, mode ApprovalMode, lock *lockfile.File, redactionKeys []string) *Engine {
	t.Helper()
	ir, err := policy.Compile([]byte(enginePolicy), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	engine, err := NewEngine(Options{Policy: ir, Lockfile: lock, Subject: "agent", ApprovalMode: mode, AuditEnabled: true, RedactionKeys: redactionKeys})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return engine
}

func TestDecideAllowsReadOnlyHeuristically(t *testing.T) {
	engine := testEngine(t, ApprovalBlock, nil)
	decision, err := engine.Decide("read_file", map[string]any{"path": "/workspace/readme.md"})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if !decision.Forward || decision.Policy.Effect != policy.EffectAllow || decision.Policy.RuleID != "allow-read" {
		t.Fatalf("decision = %#v", decision)
	}
	if decision.ArgsHash == "" || strings.Contains(decision.ArgsHash, "readme") {
		t.Fatalf("ArgsHash = %q", decision.ArgsHash)
	}
}

func TestDecideDeniesDestructiveHeuristically(t *testing.T) {
	engine := testEngine(t, ApprovalBlock, nil)
	decision, err := engine.Decide("delete_repository", nil)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if decision.Forward || decision.Policy.Effect != policy.EffectDeny || decision.Policy.RuleID != "deny-destructive" {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestRequireApprovalBlocksByDefaultAndCanForward(t *testing.T) {
	blocked := testEngine(t, ApprovalBlock, nil)
	decision, err := blocked.Decide("send_email", map[string]any{"to": "outside@example.com"})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if decision.Forward || decision.Policy.Effect != policy.EffectRequireApproval {
		t.Fatalf("blocked decision = %#v", decision)
	}
	if len(decision.UnenforcedObligations) != 1 || decision.UnenforcedObligations[0] != "redact" {
		t.Fatalf("unenforced = %#v", decision.UnenforcedObligations)
	}

	forwarded := testEngineWithRedaction(t, ApprovalForward, nil, []string{"to"})
	decision, err = forwarded.Decide("send_email", map[string]any{"to": "outside@example.com"})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if !decision.Forward {
		t.Fatalf("forward decision = %#v", decision)
	}
	if len(decision.UnenforcedObligations) != 1 || decision.UnenforcedObligations[0] != "human_approval" {
		t.Fatalf("unenforced with redaction = %#v", decision.UnenforcedObligations)
	}
	if decision.ForwardArguments["to"] != "[REDACTED]" || len(decision.RedactedFields) != 1 || decision.RedactedFields[0] != "to" {
		t.Fatalf("redaction = args=%#v fields=%#v", decision.ForwardArguments, decision.RedactedFields)
	}
}

func TestLockfileMissFailsClosed(t *testing.T) {
	lock := &lockfile.File{Version: lockfile.Version, Servers: []lockfile.Server{{
		Name: "files", Source: ".mcp.json", Transport: "stdio", Args: []string{}, EnvKeys: []string{}, HeaderKeys: []string{}, ConfigHash: "sha256:" + strings.Repeat("0", 64),
		Tools: &[]lockfile.Tool{{Name: "read_file", DescriptionHash: "sha256:" + strings.Repeat("1", 64), InputSchemaHash: "sha256:" + strings.Repeat("2", 64), Capabilities: []string{"read"}}},
	}}}
	engine := testEngine(t, ApprovalBlock, lock)
	decision, err := engine.Decide("write_file", nil)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if decision.Forward || decision.Policy.Effect != policy.EffectDeny || decision.CapabilitySource != "lockfile-missing" {
		t.Fatalf("decision = %#v", decision)
	}
	if decision.Reason != "tool is not present in the lockfile" {
		t.Fatalf("reason = %q", decision.Reason)
	}
}

func TestLockfileCapabilitiesOverrideHeuristics(t *testing.T) {
	lock := &lockfile.File{Version: lockfile.Version, Servers: []lockfile.Server{{
		Name: "mail", Source: ".mcp.json", Transport: "stdio", Args: []string{}, EnvKeys: []string{}, HeaderKeys: []string{}, ConfigHash: "sha256:" + strings.Repeat("0", 64),
		Tools: &[]lockfile.Tool{{Name: "delete_repository", DescriptionHash: "sha256:" + strings.Repeat("1", 64), InputSchemaHash: "sha256:" + strings.Repeat("2", 64), Capabilities: []string{"read"}}},
	}}}
	engine := testEngine(t, ApprovalBlock, lock)
	decision, err := engine.Decide("delete_repository", nil)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if !decision.Forward || decision.CapabilitySource != "lockfile" || decision.Policy.RuleID != "allow-read" {
		t.Fatalf("decision = %#v", decision)
	}
	if got, want := strings.Join(decision.Servers, ","), "mail"; got != want {
		t.Fatalf("servers = %q, want %q", got, want)
	}
}

func TestAuditRecordExcludesArguments(t *testing.T) {
	engine := testEngine(t, ApprovalBlock, nil)
	decision, err := engine.Decide("send_email", map[string]any{"body": "top-secret-token"})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	record := engine.Record(decision)
	var buffer bytes.Buffer
	audit := NewJSONLAudit(&buffer)
	if err := audit.Write(record); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	output := buffer.String()
	if strings.Contains(output, "top-secret-token") {
		t.Fatalf("audit leaked arguments: %s", output)
	}
	var decoded AuditRecord
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("decode audit: %v\n%s", err, output)
	}
	if decoded.Tool != "send_email" || decoded.ArgsHash == "" || decoded.Forwarded {
		t.Fatalf("audit = %#v", decoded)
	}
}

func TestHashArgumentsIsDeterministic(t *testing.T) {
	first, err := HashArguments(map[string]any{"b": 2, "a": map[string]any{"z": 1, "y": 2}})
	if err != nil {
		t.Fatalf("HashArguments() error = %v", err)
	}
	second, err := HashArguments(map[string]any{"a": map[string]any{"y": 2, "z": 1}, "b": 2})
	if err != nil {
		t.Fatalf("HashArguments() error = %v", err)
	}
	if first != second {
		t.Fatalf("hash not deterministic: %q != %q", first, second)
	}
}

func TestAuditObligationFailsClosedWithoutSink(t *testing.T) {
	ir, err := policy.Compile([]byte(`apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: audit-test
spec:
  defaults:
    effect: deny
  rules:
    - id: allow-audited-read
      effect: allow
      match:
        capability: [read]
      obligations: [audit]
`), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	withoutAudit, err := NewEngine(Options{Policy: ir, Subject: "agent"})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	decision, err := withoutAudit.Decide("read_file", nil)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if decision.Forward || decision.Reason != "audit obligation cannot be enforced without an audit sink" || len(decision.UnenforcedObligations) != 1 {
		t.Fatalf("decision = %#v", decision)
	}

	withAudit, err := NewEngine(Options{Policy: ir, Subject: "agent", AuditEnabled: true})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	decision, err = withAudit.Decide("read_file", nil)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if !decision.Forward || len(decision.UnenforcedObligations) != 0 {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestRequiresAudit(t *testing.T) {
	ir, err := policy.Compile([]byte(`apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: audit-required
spec:
  defaults:
    effect: deny
  rules:
    - id: audited-deny
      effect: deny
      match:
        capability: [destructive]
      obligations: [audit]
`), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if !RequiresAudit(ir) {
		t.Fatal("RequiresAudit() = false")
	}
	if RequiresAudit(nil) {
		t.Fatal("RequiresAudit(nil) = true")
	}
}
