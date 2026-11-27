package exporter

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/1124875284/caplock/internal/policy"
)

// TestOPAEvaluatorParity is an optional integration check. Set
// CAPLOCK_OPA_BIN=/path/to/opa to run it; otherwise it skips rather than making
// OPA a build dependency.
func TestOPAEvaluatorParity(t *testing.T) {
	opaBinary := os.Getenv("CAPLOCK_OPA_BIN")
	if opaBinary == "" {
		var err error
		opaBinary, err = exec.LookPath("opa")
		if err != nil {
			t.Skip("opa binary not found; set CAPLOCK_OPA_BIN to run parity test")
		}
	}
	ir, err := policy.LoadFile(filepath.Join("..", "..", "examples", "policy", "caplock.yaml"))
	if err != nil {
		t.Fatalf("load example policy: %v", err)
	}
	module, err := Render(ir, "rego")
	if err != nil {
		t.Fatalf("Render(rego) error = %v", err)
	}
	directory := t.TempDir()
	modulePath := filepath.Join(directory, "policy.rego")
	if err := os.WriteFile(modulePath, module, 0o644); err != nil {
		t.Fatalf("write module: %v", err)
	}

	location := time.FixedZone("CST", 8*60*60)
	baseTime := time.Date(2026, 1, 5, 10, 0, 0, 0, location) // Monday 10:00
	afterHours := time.Date(2026, 1, 5, 20, 0, 0, 0, location)
	cases := []policy.Request{
		{
			Subject:      "finance-analyst",
			Tool:         "email.send",
			Capabilities: []string{"comms", "external", "network"},
			Sink:         "email.send",
			Provenance:   []string{"external_web"},
			Context:      policy.RequestContext{Time: baseTime},
		},
		{
			Subject:      "finance-analyst",
			Tool:         "email.send",
			Capabilities: []string{"comms", "external", "network"},
			DataClass:    []string{"secret"},
			Sink:         "email.send",
			Context:      policy.RequestContext{Time: baseTime},
		},
		{Subject: "finance-analyst", Tool: "mystery", Context: policy.RequestContext{Time: baseTime}},
		{Subject: "finance-analyst", Tool: "read_file", Capabilities: []string{"read"}, Context: policy.RequestContext{Time: baseTime}},
		{
			Subject:      "finance-analyst",
			Tool:         "identity.assign_role",
			Capabilities: []string{"identity", "write"},
			Args:         map[string]any{"role": "admin"},
			Context:      policy.RequestContext{Time: baseTime},
		},
		{
			Subject:      "finance-analyst",
			Tool:         "finance.transfer",
			Capabilities: []string{"finance.write"},
			Context:      policy.RequestContext{Time: afterHours},
		},
		{
			Subject:      "finance-analyst",
			Tool:         "write_file",
			Capabilities: []string{"write"},
			Args:         map[string]any{"path": "/etc/passwd"},
			Context:      policy.RequestContext{Time: baseTime},
		},
	}
	for index, request := range cases {
		t.Run("case-"+strconv.Itoa(index+1), func(t *testing.T) {
			assertOPAMatchesGo(t, opaBinary, modulePath, directory, strconv.Itoa(index+1), ir, request)
		})
	}
}

func TestOPASelectorParity(t *testing.T) {
	opaBinary := os.Getenv("CAPLOCK_OPA_BIN")
	if opaBinary == "" {
		var err error
		opaBinary, err = exec.LookPath("opa")
		if err != nil {
			t.Skip("opa binary not found; set CAPLOCK_OPA_BIN to run parity test")
		}
	}
	ir, err := policy.Compile([]byte(selectorPolicy), "selector-policy.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	module, err := Render(ir, "rego")
	if err != nil {
		t.Fatalf("Render(rego) error = %v", err)
	}
	directory := t.TempDir()
	modulePath := filepath.Join(directory, "policy.rego")
	if err := os.WriteFile(modulePath, module, 0o644); err != nil {
		t.Fatalf("write module: %v", err)
	}
	at := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)
	tuesdayLate := time.Date(2026, 1, 6, 23, 0, 0, 0, time.UTC)
	wednesdayEarly := time.Date(2026, 1, 7, 2, 0, 0, 0, time.UTC)
	wednesdayMorning := time.Date(2026, 1, 7, 7, 0, 0, 0, time.UTC)
	mondayEarly := time.Date(2026, 1, 5, 2, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		request  policy.Request
		wantRule string
	}{
		{"exists-present", policy.Request{Tool: "exists", Args: map[string]any{"path": "/tmp/a"}, Context: policy.RequestContext{Time: at}}, "deny-exists"},
		{"exists-absent", policy.Request{Tool: "exists", Args: map[string]any{}, Context: policy.RequestContext{Time: at}}, ""},
		{"not-exists", policy.Request{Tool: "not-exists", Args: map[string]any{}, Context: policy.RequestContext{Time: at}}, "deny-not-exists"},
		{"ne-present", policy.Request{Tool: "ne", Args: map[string]any{"mode": "prod"}, Context: policy.RequestContext{Time: at}}, "deny-ne"},
		{"ne-absent", policy.Request{Tool: "ne", Args: map[string]any{}, Context: policy.RequestContext{Time: at}}, "deny-ne"},
		{"in", policy.Request{Tool: "in", Args: map[string]any{"role": "owner"}, Context: policy.RequestContext{Time: at}}, "deny-in"},
		{"contains-string", policy.Request{Tool: "contains", Args: map[string]any{"command": "sudo rm -rf /tmp/x"}, Context: policy.RequestContext{Time: at}}, "deny-contains-string"},
		{"contains-array", policy.Request{Tool: "contains-array", Args: map[string]any{"tags": []any{"prod", "eu"}}, Context: policy.RequestContext{Time: at}}, "deny-contains-array"},
		{"regex", policy.Request{Tool: "regex", Args: map[string]any{"path": "/etc/passwd"}, Context: policy.RequestContext{Time: at}}, "deny-regex"},
		{"suffix", policy.Request{Tool: "suffix", Args: map[string]any{"file": "signing.pem"}, Context: policy.RequestContext{Time: at}}, "deny-suffix"},
		{"dotted", policy.Request{Tool: "dotted", Args: map[string]any{"user": map[string]any{"role": "admin"}}, Context: policy.RequestContext{Time: at}}, "deny-dotted"},
		{"environment", policy.Request{Tool: "environment", Context: policy.RequestContext{Time: at, Environment: "production"}}, "deny-production"},
		{"attributes", policy.Request{Tool: "attributes", Context: policy.RequestContext{Time: at, Attributes: map[string]string{"tenant": "acme"}}}, "deny-tenant"},
		{"overnight-inside", policy.Request{Tool: "overnight", Context: policy.RequestContext{Time: tuesdayLate}}, ""},
		{"overnight-next-day", policy.Request{Tool: "overnight", Context: policy.RequestContext{Time: wednesdayEarly}}, ""},
		{"overnight-outside", policy.Request{Tool: "overnight", Context: policy.RequestContext{Time: wednesdayMorning}}, "deny-overnight"},
		{"overnight-sunday", policy.Request{Tool: "overnight", Context: policy.RequestContext{Time: mondayEarly}}, "deny-overnight"},
		{"default", policy.Request{Tool: "unmatched", Context: policy.RequestContext{Time: at}}, ""},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			want, err := policy.Evaluate(ir, item.request)
			if err != nil {
				t.Fatalf("Go evaluator error = %v", err)
			}
			if want.RuleID != item.wantRule {
				t.Fatalf("Go rule = %q, want %q", want.RuleID, item.wantRule)
			}
			assertOPAMatchesGo(t, opaBinary, modulePath, directory, item.name, ir, item.request)
		})
	}
}

const selectorPolicy = `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: selector-policy
spec:
  defaults:
    effect: deny
  subjects:
    - id: agent
  rules:
    - id: deny-exists
      effect: deny
      match: {tool: [exists], args: {path: {"$exists": true}}}
    - id: deny-not-exists
      effect: deny
      match: {tool: [not-exists], args: {path: {"$exists": false}}}
    - id: deny-ne
      effect: deny
      match: {tool: [ne], args: {mode: {"$ne": safe}}}
    - id: deny-in
      effect: deny
      match: {tool: [in], args: {role: {"$in": [admin, owner]}}}
    - id: deny-contains-string
      effect: deny
      match: {tool: [contains], args: {command: {"$contains": "rm -rf"}}}
    - id: deny-contains-array
      effect: deny
      match: {tool: [contains-array], args: {tags: {"$contains": [prod]}}}
    - id: deny-regex
      effect: deny
      match: {tool: [regex], args: {path: {"$regex": "^/etc/(passwd|shadow)$"}}}
    - id: deny-suffix
      effect: deny
      match: {tool: [suffix], args: {file: {"$suffix": ".pem"}}}
    - id: deny-dotted
      effect: deny
      match: {tool: [dotted], args: {"user.role": admin}}
    - id: deny-production
      effect: deny
      match: {tool: [environment], context: {environment: production}}
    - id: deny-tenant
      effect: deny
      match: {tool: [attributes], context: {attributes: {tenant: acme}}}
    - id: deny-overnight
      effect: deny
      match:
        tool: [overnight]
        context:
          time: {outside: "Mon-Fri 22:00-06:00 UTC"}
`

func assertOPAMatchesGo(t *testing.T, opaBinary, modulePath, directory, name string, ir *policy.IR, request policy.Request) {
	t.Helper()
	want, err := policy.Evaluate(ir, request)
	if err != nil {
		t.Fatalf("Go evaluator error = %v", err)
	}
	inputPath := filepath.Join(directory, "input-"+name+".json")
	input := regoInput(request)
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	if err := os.WriteFile(inputPath, data, 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	output, err := exec.Command(opaBinary, "eval", "--format=json", "--data", modulePath, "--input", inputPath, "data.caplock.decision").CombinedOutput()
	if err != nil {
		t.Fatalf("opa eval: %v\n%s", err, output)
	}
	var response struct {
		Result []struct {
			Expressions []struct {
				Value json.RawMessage `json:"value"`
			} `json:"expressions"`
		} `json:"result"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		t.Fatalf("decode opa output: %v\n%s", err, output)
	}
	if len(response.Result) != 1 || len(response.Result[0].Expressions) != 1 {
		t.Fatalf("unexpected opa output: %s", output)
	}
	var got policy.Decision
	if err := json.Unmarshal(response.Result[0].Expressions[0].Value, &got); err != nil {
		t.Fatalf("decode opa decision: %v\n%s", err, output)
	}
	if got.Effect != want.Effect || got.RuleID != want.RuleID || got.Default != want.Default {
		t.Fatalf("OPA %#v != Go %#v", got, want)
	}
	if !reflect.DeepEqual(sortedStrings(got.Obligations), sortedStrings(want.Obligations)) {
		t.Fatalf("OPA obligations %v != Go obligations %v", got.Obligations, want.Obligations)
	}
}

func regoInput(request policy.Request) map[string]any {
	at := request.Context.Time
	attributes := request.Context.Attributes
	if attributes == nil {
		attributes = map[string]string{}
	}
	return map[string]any{
		"subject":      request.Subject,
		"tool":         request.Tool,
		"capabilities": nonNilStrings(request.Capabilities),
		"dataClass":    nonNilStrings(request.DataClass),
		"sink":         request.Sink,
		"args":         nonNilAnyMap(request.Args),
		"provenance":   nonNilStrings(request.Provenance),
		"context": map[string]any{
			"environment": request.Context.Environment,
			"attributes":  attributes,
			"weekday":     int(at.Weekday()),
			"minute":      at.Hour()*60 + at.Minute(),
		},
	}
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonNilAnyMap(values map[string]any) map[string]any {
	if values == nil {
		return map[string]any{}
	}
	return values
}

func sortedStrings(values []string) []string {
	cloned := append([]string(nil), values...)
	sort.Strings(cloned)
	return cloned
}
