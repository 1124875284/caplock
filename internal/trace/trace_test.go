package trace

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/caplock/caplock/internal/canonical"
	"github.com/caplock/caplock/internal/policy"
)

const validHash = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

var testTime = time.Date(2026, 1, 2, 12, 30, 0, 0, time.UTC)

func testRecord() Record {
	return Record{
		Version:           Version,
		Time:              testTime,
		Policy:            "trace-test",
		Subject:           "finance-analyst",
		Tool:              "send_email",
		Capabilities:      []string{"external", "comms", "comms"},
		CapabilitySource:  "lockfile",
		Servers:           []string{"comms", "comms"},
		Sink:              "email.send",
		Environment:       "production",
		DataClass:         []string{"secret", "pii", "secret"},
		Provenance:        []string{"external_web"},
		ArgumentsCaptured: true,
		Args:              map[string]any{"to": "outside@example.com"},
		ArgsHash:          validHash,
		Decision: Decision{
			Effect:       "require_approval",
			RuleID:       "approve-email",
			Default:      false,
			Obligations:  []string{"redact", "audit", "human_approval"},
			Forwarded:    false,
			Reason:       "approval required by policy rule",
			ApprovalMode: "block",
		},
	}
}

func TestJSONLWriterAndParse(t *testing.T) {
	var buffer bytes.Buffer
	writer := NewJSONLWriter(&buffer)
	if err := writer.Write(testRecord()); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	records, err := Parse(buffer.Bytes())
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	record := records[0]
	if !reflect.DeepEqual(record.Capabilities, []string{"comms", "external"}) {
		t.Fatalf("capabilities = %#v", record.Capabilities)
	}
	if !reflect.DeepEqual(record.DataClass, []string{"pii", "secret"}) {
		t.Fatalf("dataClass = %#v", record.DataClass)
	}
	if !reflect.DeepEqual(record.Decision.Obligations, []string{"audit", "human_approval", "redact"}) {
		t.Fatalf("obligations = %#v", record.Decision.Obligations)
	}
	if !record.ArgumentsCaptured || record.Args["to"] != "outside@example.com" {
		t.Fatalf("arguments = %#v captured=%t", record.Args, record.ArgumentsCaptured)
	}

	var second bytes.Buffer
	if err := NewJSONLWriter(&second).Write(record); err != nil {
		t.Fatalf("second Write() error = %v", err)
	}
	if !bytes.Equal(buffer.Bytes(), second.Bytes()) {
		t.Fatalf("writer is not deterministic:\n%s\n---\n%s", buffer.Bytes(), second.Bytes())
	}
}

func TestParseRejectsInvalidRecords(t *testing.T) {
	valid, err := json.Marshal(testRecord())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	validLine := string(valid)
	cases := []struct {
		name string
		data string
		want string
	}{
		{name: "empty", data: "\n  \n", want: "no records"},
		{name: "unknown field", data: strings.Replace(validLine, `"tool":`, `"extra":1,"tool":`, 1), want: "unknown field"},
		{name: "multiple values", data: validLine + " {}\n", want: "multiple JSON values"},
		{name: "version", data: strings.Replace(validLine, `"version":1`, `"version":2`, 1), want: "unsupported trace version"},
		{name: "time", data: strings.Replace(validLine, `"time":"2026-01-02T12:30:00Z"`, `"time":"0001-01-01T00:00:00Z"`, 1), want: "time is required"},
		{name: "policy", data: strings.Replace(validLine, `"policy":"trace-test"`, `"policy":""`, 1), want: "policy is required"},
		{name: "subject", data: strings.Replace(validLine, `"subject":"finance-analyst"`, `"subject":""`, 1), want: "subject is required"},
		{name: "tool", data: strings.Replace(validLine, `"tool":"send_email"`, `"tool":""`, 1), want: "tool is required"},
		{name: "effect", data: strings.Replace(validLine, `"effect":"require_approval"`, `"effect":"audit"`, 1), want: "invalid decision effect"},
		{name: "args not captured", data: strings.Replace(validLine, `"argumentsCaptured":true`, `"argumentsCaptured":false`, 1), want: "args must be empty"},
		{name: "bad hash", data: strings.Replace(validLine, validHash, "sha256:abc", 1), want: "argsHash must be"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Parse([]byte(test.data)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Parse() error = %v, want %q", err, test.want)
			}
		})
	}

	lines := make([]string, 0, MaxRecords+1)
	for range MaxRecords + 1 {
		lines = append(lines, validLine)
	}
	if _, err := Parse([]byte(strings.Join(lines, "\n"))); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("record-limit error = %v", err)
	}
}

func TestReadFileRejectsMissingAndEmpty(t *testing.T) {
	if _, err := ReadFile(t.TempDir() + "/missing.jsonl"); err == nil || !strings.Contains(err.Error(), "read trace") {
		t.Fatalf("ReadFile(missing) error = %v", err)
	}
}

func TestReplayReportsChanges(t *testing.T) {
	beforePolicy := `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: before
spec:
  defaults:
    effect: deny
  rules:
    - id: allow-read
      effect: allow
      match:
        capability: [read]
    - id: deny-destructive
      effect: deny
      match:
        capability: [destructive]
    - id: approve-write
      effect: require_approval
      match:
        capability: [write]
    - id: deny-admin-role
      effect: deny
      obligations: [audit, alert]
      match:
        capability: [identity]
        args:
          role: {"$in": [admin]}
`
	afterPolicy := `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: after
spec:
  defaults:
    effect: deny
  rules:
    - id: approve-read
      effect: require_approval
      match:
        capability: [read]
    - id: allow-destructive
      effect: allow
      match:
        capability: [destructive]
    - id: deny-write
      effect: deny
      match:
        capability: [write]
`
	record := func(tool string, capabilities []string, args map[string]any, captured bool, effect, rule string, isDefault bool, obligations []string) Record {
		hash := validHash
		if captured {
			hash, _ = canonical.HashArguments(args)
		}
		return Record{
			Version:           Version,
			Time:              testTime,
			Policy:            "before",
			Subject:           "finance-analyst",
			Tool:              tool,
			Capabilities:      capabilities,
			ArgumentsCaptured: captured,
			Args:              args,
			ArgsHash:          hash,
			Decision: Decision{
				Effect:      effect,
				RuleID:      rule,
				Default:     isDefault,
				Obligations: obligations,
			},
		}
	}
	records := []Record{
		record("read_file", []string{"read"}, nil, false, "allow", "allow-read", false, nil),
		record("delete_repository", []string{"destructive"}, nil, false, "deny", "deny-destructive", false, nil),
		record("write_file", []string{"write"}, nil, false, "require_approval", "approve-write", false, nil),
		record("assign_role", []string{"identity"}, map[string]any{"role": "admin"}, true, "deny", "deny-admin-role", false, []string{"alert", "audit"}),
		record("mystery_tool", []string{"unknown"}, nil, false, "deny", "", true, nil),
	}
	if _, err := Parse(mustMarshalRecords(t, records)); err != nil {
		t.Fatalf("test records do not parse: %v", err)
	}
	beforeIR := compileTracePolicy(t, beforePolicy)
	result, err := Replay(beforeIR, records, ReplayOptions{Source: "calls.jsonl"})
	if err != nil {
		t.Fatalf("Replay(before) error = %v", err)
	}
	if result.Changed != 0 || result.Unchanged != 5 {
		t.Fatalf("Replay(before) = %#v", result)
	}

	afterIR := compileTracePolicy(t, afterPolicy)
	result, err = Replay(afterIR, records, ReplayOptions{Source: "calls.jsonl"})
	if err != nil {
		t.Fatalf("Replay(after) error = %v", err)
	}
	if result.Total != 5 || result.Unchanged != 1 || result.Changed != 4 {
		t.Fatalf("Replay(after) summary = %#v", result)
	}
	if result.Weakened != 1 || result.Strengthened != 2 || result.ArgsMissing != 4 {
		t.Fatalf("Replay(after) counts = %#v", result)
	}
	if len(result.Changes) != 4 {
		t.Fatalf("changes = %#v", result.Changes)
	}
	byTool := make(map[string]Change)
	for _, change := range result.Changes {
		byTool[change.Tool] = change
	}
	if change := byTool["read_file"]; change.Direction != DirectionStrengthened || change.ArgumentsCaptured {
		t.Fatalf("read_file change = %#v", change)
	}
	if change := byTool["delete_repository"]; change.Direction != DirectionWeakened {
		t.Fatalf("delete_repository change = %#v", change)
	}
	if change := byTool["write_file"]; change.Direction != DirectionStrengthened {
		t.Fatalf("write_file change = %#v", change)
	}
	if change := byTool["assign_role"]; change.Direction != DirectionChanged || !change.ArgumentsCaptured || len(change.Before.Obligations) != 2 {
		t.Fatalf("assign_role change = %#v", change)
	}
}

func TestReplayUsesCapturedArguments(t *testing.T) {
	source := `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: args
spec:
  defaults:
    effect: allow
  rules:
    - id: deny-admin
      effect: deny
      match:
        capability: [identity]
        args:
          role: {"$in": [admin]}
`
	ir := compileTracePolicy(t, source)
	hash, err := canonical.HashArguments(map[string]any{"role": "admin"})
	if err != nil {
		t.Fatalf("hash arguments: %v", err)
	}
	record := Record{
		Version:           Version,
		Time:              testTime,
		Policy:            "args",
		Subject:           "agent",
		Tool:              "assign_role",
		Capabilities:      []string{"identity"},
		ArgumentsCaptured: true,
		Args:              map[string]any{"role": "admin"},
		ArgsHash:          hash,
		Decision: Decision{
			Effect:      "deny",
			RuleID:      "deny-admin",
			Obligations: []string{},
		},
	}
	result, err := Replay(ir, []Record{record}, ReplayOptions{})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if result.Changed != 0 {
		t.Fatalf("result = %#v", result)
	}
	record.ArgumentsCaptured = false
	record.Args = nil
	record.Decision.Effect = "allow"
	record.Decision.RuleID = ""
	record.Decision.Default = true
	result, err = Replay(ir, []Record{record}, ReplayOptions{})
	if err != nil {
		t.Fatalf("Replay(no args) error = %v", err)
	}
	if result.ArgsMissing != 1 || result.Changed != 0 {
		t.Fatalf("result without args = %#v", result)
	}
}

func TestRenderTextAndJSON(t *testing.T) {
	result := Result{
		Version:     ReplayVersion,
		Policy:      "after",
		Source:      "calls.jsonl",
		Total:       1,
		Changed:     1,
		Weakened:    1,
		ArgsMissing: 1,
		Changes: []Change{{
			Time:              testTime.Format(time.RFC3339Nano),
			Subject:           "agent",
			Tool:              "read_file\x1b[31m",
			ArgumentsCaptured: false,
			Direction:         DirectionWeakened,
			Before:            DecisionSummary{Effect: "deny", RuleID: "deny-read", Obligations: []string{"audit"}},
			After:             DecisionSummary{Effect: "allow", RuleID: "allow-read", Obligations: []string{}},
		}},
	}
	text, err := Render(result, "text")
	if err != nil {
		t.Fatalf("Render(text) error = %v", err)
	}
	for _, expected := range []string{"Caplock trace replay", "Records: total=1", "[WEAKENED]", "before: deny", "after:  allow"} {
		if !strings.Contains(string(text), expected) {
			t.Fatalf("text missing %q:\n%s", expected, text)
		}
	}
	if strings.ContainsRune(string(text), '\x1b') {
		t.Fatalf("text contains raw control character:\n%q", text)
	}
	jsonData, err := Render(result, "json")
	if err != nil {
		t.Fatalf("Render(json) error = %v", err)
	}
	var decoded Result
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if !reflect.DeepEqual(decoded, result) {
		t.Fatalf("JSON round trip = %#v, want %#v", decoded, result)
	}
	if _, err := Render(result, "yaml"); err == nil || !strings.Contains(err.Error(), "unsupported replay format") {
		t.Fatalf("Render(yaml) error = %v", err)
	}
}

func compileTracePolicy(t *testing.T, source string) *policy.IR {
	t.Helper()
	ir, err := policy.Compile([]byte(source), "caplock.yaml")
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return ir
}

func mustMarshalRecords(t *testing.T, records []Record) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := NewJSONLWriter(&buffer)
	for _, record := range records {
		if err := writer.Write(record); err != nil {
			t.Fatalf("write record: %v", err)
		}
	}
	return buffer.Bytes()
}
