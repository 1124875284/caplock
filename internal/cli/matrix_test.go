package cli

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caplock/caplock/internal/lockfile"
)

const matrixCLIHash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

const matrixCLIPolicy = `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: matrix-cli
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

func matrixCLITool(name string, capabilities ...string) lockfile.Tool {
	return lockfile.Tool{
		Name:            name,
		DescriptionHash: matrixCLIHash,
		InputSchemaHash: matrixCLIHash,
		Capabilities:    capabilities,
	}
}

func writeMatrixCLIFixture(t *testing.T, tools bool) (string, string) {
	t.Helper()
	root := t.TempDir()
	policyPath := filepath.Join(root, "caplock.yaml")
	if err := os.WriteFile(policyPath, []byte(matrixCLIPolicy), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	command := "example-mcp"
	locked := []lockfile.Tool{
		matrixCLITool("read_file", "read"),
		matrixCLITool("write_file", "write"),
		matrixCLITool("delete_repository", "destructive", "write"),
		matrixCLITool("send_email", "comms", "external"),
		matrixCLITool("transfer_funds", "finance.write"),
	}
	server := lockfile.Server{
		Name:       "fixture",
		Source:     ".mcp.json",
		Transport:  "stdio",
		Command:    &command,
		Args:       []string{},
		EnvKeys:    []string{},
		HeaderKeys: []string{},
		ConfigHash: matrixCLIHash,
	}
	if tools {
		server.Tools = &locked
	}
	lockPath := filepath.Join(root, "caplock.lock")
	if err := lockfile.Write(lockPath, &lockfile.File{Version: lockfile.Version, Servers: []lockfile.Server{server}}); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}
	return policyPath, lockPath
}

func TestMatrixCommandTextAndCSV(t *testing.T) {
	policyPath, lockPath := writeMatrixCLIFixture(t, true)

	stdout, stderr, code := run(t, "matrix", policyPath, "--lockfile", lockPath, "--subject", "finance-analyst")
	if code != 0 {
		t.Fatalf("matrix text exit code = %d, stderr = %q", code, stderr)
	}
	for _, expected := range []string{
		"Subject: finance-analyst",
		"Summary: tools=5 allowed=1 approval_required=1 denied=3 defaulted=1 conditional=2",
		"delete_repository",
		"send_email",
		"transfer_funds",
	} {
		if !strings.Contains(stdout, expected) {
			t.Fatalf("matrix text missing %q:\n%s", expected, stdout)
		}
	}

	stdout, stderr, code = run(t, "matrix", policyPath, "--lockfile", lockPath, "--subject", "finance-analyst", "--format", "csv")
	if code != 0 {
		t.Fatalf("matrix csv exit code = %d, stderr = %q", code, stderr)
	}
	records, err := csv.NewReader(bytes.NewBufferString(stdout)).ReadAll()
	if err != nil {
		t.Fatalf("decode CSV: %v", err)
	}
	if len(records) != 6 {
		t.Fatalf("CSV rows = %d, want 6", len(records))
	}
	if records[1][1] != "delete_repository" || records[1][3] != "deny" || records[1][4] != "deny-destructive" {
		t.Fatalf("delete_repository row = %#v", records[1])
	}
	if records[3][1] != "send_email" || records[3][6] != "true" {
		t.Fatalf("send_email row = %#v", records[3])
	}
}

func TestMatrixCommandTimeSubjectAndOutputFile(t *testing.T) {
	policyPath, lockPath := writeMatrixCLIFixture(t, true)
	outputPath := filepath.Join(t.TempDir(), "matrix.json")
	stdout, stderr, code := run(t, "matrix", policyPath,
		"--lockfile", lockPath,
		"--subject", "finance-analyst",
		"--time", "2026-01-02T12:00:00+08:00",
		"--format", "json",
		"--output", outputPath,
	)
	if code != 0 {
		t.Fatalf("matrix output exit code = %d, stderr = %q", code, stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("matrix --output wrote to stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "wrote") || !strings.Contains(stderr, "5 tools") {
		t.Fatalf("matrix --output stderr = %q", stderr)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read matrix output: %v", err)
	}
	var document struct {
		Subject        string `json:"subject"`
		EvaluationTime string `json:"evaluationTime"`
		DefaultEffect  string `json:"defaultEffect"`
		Summary        struct {
			Tools       int `json:"tools"`
			Denied      int `json:"denied"`
			Conditional int `json:"conditional"`
		} `json:"summary"`
		Entries []struct {
			Tool        string `json:"tool"`
			Effect      string `json:"effect"`
			RuleID      string `json:"ruleId"`
			Default     bool   `json:"default"`
			Conditional bool   `json:"conditional"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode matrix output: %v\n%s", err, data)
	}
	if document.Subject != "finance-analyst" || document.EvaluationTime != "2026-01-02T12:00:00+08:00" || document.DefaultEffect != "deny" {
		t.Fatalf("matrix header = %#v", document)
	}
	if document.Summary.Tools != 5 || document.Summary.Denied != 3 || document.Summary.Conditional != 2 {
		t.Fatalf("matrix summary = %#v", document.Summary)
	}
	found := false
	for _, entry := range document.Entries {
		if entry.Tool == "transfer_funds" {
			found = true
			if entry.Effect != "deny" || !entry.Default || entry.RuleID != "" || !entry.Conditional {
				t.Fatalf("transfer_funds entry = %#v", entry)
			}
		}
	}
	if !found {
		t.Fatal("matrix output is missing transfer_funds")
	}
}

func TestMatrixCommandErrors(t *testing.T) {
	policyPath, lockPath := writeMatrixCLIFixture(t, true)
	_, stderr, code := run(t, "matrix", policyPath, "--lockfile", filepath.Join(t.TempDir(), "missing.lock"))
	if code != 2 || !strings.Contains(stderr, "read lockfile") {
		t.Fatalf("missing lockfile exit code = %d, stderr = %q", code, stderr)
	}
	_, stderr, code = run(t, "matrix", policyPath, "--lockfile", lockPath, "--time", "tomorrow")
	if code != 2 || !strings.Contains(stderr, "RFC3339") {
		t.Fatalf("invalid time exit code = %d, stderr = %q", code, stderr)
	}
	_, stderr, code = run(t, "matrix", policyPath, "--lockfile", lockPath, "--format", "xml")
	if code != 2 || !strings.Contains(stderr, "unsupported matrix format") {
		t.Fatalf("invalid format exit code = %d, stderr = %q", code, stderr)
	}
	_, staticLockPath := writeMatrixCLIFixture(t, false)
	_, stderr, code = run(t, "matrix", policyPath, "--lockfile", staticLockPath)
	if code != 2 || !strings.Contains(stderr, "no captured tools") {
		t.Fatalf("static lockfile exit code = %d, stderr = %q", code, stderr)
	}
}
