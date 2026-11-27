package matrix

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/1124875284/caplock/internal/lockfile"
	"github.com/1124875284/caplock/internal/policy"
)

const testHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const matrixPolicy = `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: matrix-test
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
    - id: approve-external-email
      effect: require_approval
      match:
        capability: [comms, external]
        provenance:
          contains: external_web
    - id: finance-hours
      effect: deny
      match:
        capability: [finance.write]
        context:
          time:
            outside: "Mon-Fri 09:00-18:00 Asia/Shanghai"
`

func compilePolicy(t *testing.T, source string) *policy.IR {
	t.Helper()
	ir, err := policy.Compile([]byte(source), "caplock.yaml")
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	return ir
}

func tool(name string, capabilities ...string) lockfile.Tool {
	return lockfile.Tool{
		Name:            name,
		DescriptionHash: testHash,
		InputSchemaHash: testHash,
		Capabilities:    capabilities,
	}
}

func server(name string, tools ...lockfile.Tool) lockfile.Server {
	command := "example-mcp"
	return lockfile.Server{
		Name:       name,
		Source:     ".mcp.json",
		Transport:  "stdio",
		Command:    &command,
		Args:       []string{},
		EnvKeys:    []string{},
		HeaderKeys: []string{},
		ConfigHash: testHash,
		Tools:      &tools,
	}
}

func matrixFixture() *lockfile.File {
	return &lockfile.File{
		Version: lockfile.Version,
		Servers: []lockfile.Server{
			server("workspace",
				tool("read_file", "read"),
				tool("write_file", "write"),
				tool("delete_repository", "destructive", "write"),
			),
			server("comms", tool("send_email", "comms", "external")),
			server("finance", tool("transfer_funds", "finance.write")),
		},
	}
}

func TestBuildBaselineMatrix(t *testing.T) {
	ir := compilePolicy(t, matrixPolicy)
	value, err := Build(ir, matrixFixture(), Options{Subject: "finance-analyst"})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if value.Version != Version || value.Policy != "matrix-test" || value.Subject != "finance-analyst" {
		t.Fatalf("matrix header = %#v", value)
	}
	if value.EvaluationTime != "2026-01-01T12:00:00Z" {
		t.Fatalf("evaluation time = %q", value.EvaluationTime)
	}
	if value.DefaultEffect != policy.EffectDeny {
		t.Fatalf("default effect = %q", value.DefaultEffect)
	}
	wantSummary := Summary{Tools: 5, Allowed: 1, ApprovalRequired: 1, Denied: 3, Defaulted: 1, Conditional: 2}
	if value.Summary != wantSummary {
		t.Fatalf("summary = %#v, want %#v", value.Summary, wantSummary)
	}

	want := []Entry{
		{
			Server: "comms", Tool: "send_email", Capabilities: []string{"comms", "external"},
			Effect: policy.EffectDeny, Default: true, Conditional: true,
			CandidateRules: []CandidateRule{{ID: "approve-external-email", Effect: policy.EffectRequireApproval, Conditional: true}},
		},
		{
			Server: "finance", Tool: "transfer_funds", Capabilities: []string{"finance.write"},
			Effect: policy.EffectDeny, RuleID: "finance-hours", Conditional: true,
			CandidateRules: []CandidateRule{{ID: "finance-hours", Effect: policy.EffectDeny, Conditional: true}},
		},
		{
			Server: "workspace", Tool: "delete_repository", Capabilities: []string{"destructive", "write"},
			Effect: policy.EffectDeny, RuleID: "deny-destructive",
			CandidateRules: []CandidateRule{
				{ID: "approve-write", Effect: policy.EffectRequireApproval},
				{ID: "deny-destructive", Effect: policy.EffectDeny},
			},
		},
		{
			Server: "workspace", Tool: "read_file", Capabilities: []string{"read"},
			Effect: policy.EffectAllow, RuleID: "allow-read",
			CandidateRules: []CandidateRule{{ID: "allow-read", Effect: policy.EffectAllow}},
		},
		{
			Server: "workspace", Tool: "write_file", Capabilities: []string{"write"},
			Effect: policy.EffectRequireApproval, RuleID: "approve-write",
			CandidateRules: []CandidateRule{{ID: "approve-write", Effect: policy.EffectRequireApproval}},
		},
	}
	for index, expectation := range want {
		if !reflect.DeepEqual(value.Entries[index], expectation) {
			t.Fatalf("entry %d = %#v, want %#v", index, value.Entries[index], expectation)
		}
	}
}

func TestBuildDefaultEffectAndExplicitTime(t *testing.T) {
	ir := compilePolicy(t, `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: time-test
spec:
  defaults:
    effect: allow
  rules:
    - id: finance-hours
      effect: deny
      match:
        capability: [finance.write]
        context:
          time:
            outside: "Mon-Fri 09:00-18:00 Asia/Shanghai"
`)
	file := &lockfile.File{Version: lockfile.Version, Servers: []lockfile.Server{
		server("finance", tool("transfer_funds", "finance.write")),
	}}

	inside, err := Build(ir, file, Options{Subject: "agent", At: time.Date(2026, 1, 2, 12, 0, 0, 0, time.FixedZone("CST", 8*60*60))})
	if err != nil {
		t.Fatalf("Build() inside hours error = %v", err)
	}
	if entry := inside.Entries[0]; entry.Effect != policy.EffectAllow || !entry.Default || !entry.Conditional || len(entry.CandidateRules) != 1 {
		t.Fatalf("inside-hours entry = %#v", entry)
	}
	if inside.EvaluationTime != "2026-01-02T12:00:00+08:00" {
		t.Fatalf("inside-hours evaluation time = %q", inside.EvaluationTime)
	}

	outside, err := Build(ir, file, Options{Subject: "agent", At: time.Date(2026, 1, 2, 20, 0, 0, 0, time.FixedZone("CST", 8*60*60))})
	if err != nil {
		t.Fatalf("Build() outside hours error = %v", err)
	}
	if entry := outside.Entries[0]; entry.Effect != policy.EffectDeny || entry.Default || entry.RuleID != "finance-hours" {
		t.Fatalf("outside-hours entry = %#v", entry)
	}
}

func TestBuildRequiresCapturedTools(t *testing.T) {
	ir := compilePolicy(t, matrixPolicy)
	if _, err := Build(nil, matrixFixture(), Options{}); err == nil {
		t.Fatal("Build(nil) error = nil")
	}
	if _, err := Build(ir, nil, Options{}); err == nil {
		t.Fatal("Build(nil lockfile) error = nil")
	}
	if _, err := Build(ir, &lockfile.File{Version: lockfile.Version, Servers: []lockfile.Server{}}, Options{}); err == nil || !strings.Contains(err.Error(), "no captured tools") {
		t.Fatalf("Build(empty) error = %v", err)
	}
	if _, err := Build(ir, &lockfile.File{Version: lockfile.Version, Servers: []lockfile.Server{server("static")}}, Options{}); err == nil || !strings.Contains(err.Error(), "no captured tools") {
		t.Fatalf("Build(static lockfile) error = %v", err)
	}
}

func TestRenderFormatsAreDeterministic(t *testing.T) {
	ir := compilePolicy(t, matrixPolicy)
	value, err := Build(ir, matrixFixture(), Options{Subject: "finance-analyst"})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	text, err := Render(value, "text")
	if err != nil {
		t.Fatalf("Render(text) error = %v", err)
	}
	again, err := Render(value, "text")
	if err != nil {
		t.Fatalf("Render(text) second error = %v", err)
	}
	if !bytes.Equal(text, again) {
		t.Fatal("text rendering is not deterministic")
	}
	for _, expected := range []string{"Caplock permission matrix", "Summary: tools=5 allowed=1 approval_required=1 denied=3 defaulted=1 conditional=2", "send_email", "(default)"} {
		if !strings.Contains(string(text), expected) {
			t.Fatalf("text output missing %q:\n%s", expected, text)
		}
	}

	jsonData, err := Render(value, "json")
	if err != nil {
		t.Fatalf("Render(json) error = %v", err)
	}
	var decoded Matrix
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if !reflect.DeepEqual(decoded, value) {
		t.Fatalf("JSON round trip = %#v, want %#v", decoded, value)
	}
	if !bytes.HasSuffix(jsonData, []byte("\n")) {
		t.Fatal("JSON output does not end with a newline")
	}

	yamlData, err := Render(value, "yaml")
	if err != nil {
		t.Fatalf("Render(yaml) error = %v", err)
	}
	var fromYAML Matrix
	if err := yaml.Unmarshal(yamlData, &fromYAML); err != nil {
		t.Fatalf("decode YAML: %v", err)
	}
	if !reflect.DeepEqual(fromYAML, value) {
		t.Fatalf("YAML round trip = %#v, want %#v", fromYAML, value)
	}

	csvData, err := Render(value, "csv")
	if err != nil {
		t.Fatalf("Render(csv) error = %v", err)
	}
	records, err := csv.NewReader(bytes.NewReader(csvData)).ReadAll()
	if err != nil {
		t.Fatalf("decode CSV: %v", err)
	}
	if len(records) != 6 {
		t.Fatalf("CSV rows = %d, want 6", len(records))
	}
	wantHeader := []string{"server", "tool", "capabilities", "baseEffect", "ruleId", "default", "conditional", "candidateRules"}
	if !reflect.DeepEqual(records[0], wantHeader) {
		t.Fatalf("CSV header = %#v", records[0])
	}
	if got, want := records[1][1], "send_email"; got != want || records[1][4] != "" || records[1][7] != "approve-external-email" {
		t.Fatalf("CSV send_email row = %#v", records[1])
	}

	if _, err := Render(value, "xml"); err == nil || !strings.Contains(err.Error(), "unsupported matrix format") {
		t.Fatalf("Render(xml) error = %v", err)
	}
}

func TestRenderEscapesControlCharacters(t *testing.T) {
	ir := compilePolicy(t, matrixPolicy)
	file := &lockfile.File{Version: lockfile.Version, Servers: []lockfile.Server{
		server("bad\nserver", tool("read\x1b[31m", "read")),
	}}
	value, err := Build(ir, file, Options{Subject: "agent"})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	text, err := Render(value, "text")
	if err != nil {
		t.Fatalf("Render(text) error = %v", err)
	}
	if strings.ContainsRune(string(text), '\x1b') || strings.Contains(string(text), "bad\nserver") {
		t.Fatalf("text output contains raw control characters:\n%q", text)
	}

	jsonData, err := Render(value, "json")
	if err != nil {
		t.Fatalf("Render(json) error = %v", err)
	}
	var decoded Matrix
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if decoded.Entries[0].Server != "bad\nserver" || decoded.Entries[0].Tool != "read\x1b[31m" {
		t.Fatalf("JSON round trip lost names: %#v", decoded.Entries[0])
	}

	csvData, err := Render(value, "csv")
	if err != nil {
		t.Fatalf("Render(csv) error = %v", err)
	}
	records, err := csv.NewReader(bytes.NewReader(csvData)).ReadAll()
	if err != nil {
		t.Fatalf("decode CSV: %v", err)
	}
	if records[1][0] != "bad\nserver" || records[1][1] != "read\x1b[31m" {
		t.Fatalf("CSV round trip lost names: %#v", records[1])
	}
}
