package exporter

import (
	"bytes"
	"strings"
	"testing"

	"github.com/caplock/caplock/internal/policy"
)

const exportPolicy = `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: export-test
spec:
  defaults:
    effect: deny
  subjects:
    - id: agent
  rules:
    - id: finance-after-hours
      effect: deny
      match:
        capability: [finance.write]
        context:
          time: {outside: "Mon-Fri 09:00-18:00 Asia/Shanghai"}
      obligations: [audit, alert]
    - id: safe-write
      effect: require_approval
      match:
        tool: [write_file]
        args:
          path: {"$prefix": "/workspace/"}
      obligations: [human_approval]
`

func TestRenderFormats(t *testing.T) {
	ir, err := policy.Compile([]byte(exportPolicy), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	jsonOutput, err := Render(ir, "json")
	if err != nil {
		t.Fatalf("Render(json) error = %v", err)
	}
	if !bytes.Contains(jsonOutput, []byte(`"policy": "export-test"`)) {
		t.Fatalf("JSON = %s", jsonOutput)
	}
	yamlOutput, err := Render(ir, "yaml")
	if err != nil {
		t.Fatalf("Render(yaml) error = %v", err)
	}
	if !bytes.Contains(yamlOutput, []byte("policy: export-test")) || bytes.Contains(yamlOutput, []byte("source:")) {
		t.Fatalf("YAML = %s", yamlOutput)
	}
	regoOutput, err := Render(ir, "rego")
	if err != nil {
		t.Fatalf("Render(rego) error = %v", err)
	}
	text := string(regoOutput)
	for _, expected := range []string{"package caplock", "decision :=", "rule_matches", `"days":[1,2,3,4,5]`, "startMinute", "% 7"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Rego output missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "%!") || strings.Contains(text, "%%") {
		t.Fatalf("Rego output contains a formatting error:\n%s", text)
	}
}

func TestRenderDeterministic(t *testing.T) {
	ir, err := policy.Compile([]byte(exportPolicy), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	first, err := Render(ir, "rego")
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	for range 10 {
		next, err := Render(ir, "rego")
		if err != nil {
			t.Fatalf("Render() error = %v", err)
		}
		if !bytes.Equal(first, next) {
			t.Fatal("Rego export is not deterministic")
		}
	}
}

func TestRenderRejectsUnknownFormat(t *testing.T) {
	ir, err := policy.Compile([]byte(exportPolicy), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if _, err := Render(ir, "biscuit"); err == nil {
		t.Fatal("Render() error = nil")
	}
}

func TestRenderCedarConservativeSubset(t *testing.T) {
	source := `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: cedar-test
spec:
  defaults:
    effect: deny
  rules:
    - id: block-secret-email
      effect: deny
      match:
        tool: [send_email]
        capability: [comms]
        dataClass: [secret]
        sink: email.send
        args:
          channel: external
    - id: approve-write
      effect: require_approval
      match:
        capability: [write]
`
	ir, err := policy.Compile([]byte(source), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	data, err := Render(ir, "cedar")
	if err != nil {
		t.Fatalf("Render(cedar) error = %v", err)
	}
	text := string(data)
	for _, expected := range []string{
		"defaults.effect=deny",
		"forbid (principal, action, resource) when",
		`context.tool == "send_email"`,
		`context.capabilities.contains("comms")`,
		`context.dataClass.contains("secret")`,
		`context.sink == "email.send"`,
		`context.args has "channel"`,
		"// require_approval is exported as forbid",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("Cedar output missing %q:\n%s", expected, text)
		}
	}
}

func TestRenderCedarRejectsUnsupportedSelectors(t *testing.T) {
	ir, err := policy.Compile([]byte(exportPolicy), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if _, err := Render(ir, "cedar"); err == nil || !strings.Contains(err.Error(), "time windows") {
		t.Fatalf("Render(cedar) error = %v", err)
	}
}
