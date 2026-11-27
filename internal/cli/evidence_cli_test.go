package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repoPath(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, parts...)...)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("repo fixture %s: %v", path, err)
	}
	return path
}

func writeUnsafePolicy(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "caplock.yaml")
	content := `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: unsafe
spec:
  defaults:
    effect: allow
  rules: []
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func TestTestCommandEmbeddedBaseline(t *testing.T) {
	path := repoPath(t, "examples", "policy", "caplock.yaml")
	stdout, stderr, code := run(t, "test", path)
	if code != 0 {
		t.Fatalf("test exit code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "PASS (50/50 cases)") {
		t.Fatalf("test output = %s", stdout)
	}

	stdout, stderr, code = run(t, "test", path, "--json")
	if code != 0 {
		t.Fatalf("test --json exit code = %d, stderr = %s", code, stderr)
	}
	var result struct {
		Passed      bool `json:"passed"`
		Total       int  `json:"total"`
		FailedCount int  `json:"failedCount"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("decode test JSON: %v\n%s", err, stdout)
	}
	if !result.Passed || result.Total != 50 || result.FailedCount != 0 {
		t.Fatalf("test result = %#v", result)
	}
}

func TestTestCommandFailsUnsafePolicy(t *testing.T) {
	path := writeUnsafePolicy(t)
	stdout, stderr, code := run(t, "test", path)
	if code != 1 {
		t.Fatalf("test exit code = %d, want 1; stdout = %s, stderr = %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "FAIL (0/50 cases)") {
		t.Fatalf("test output = %s", stdout)
	}
	_, stderr, code = run(t, "test", path, "--allow-failures")
	if code != 0 {
		t.Fatalf("--allow-failures exit code = %d, stderr = %s", code, stderr)
	}
}

func TestReportFormats(t *testing.T) {
	good := repoPath(t, "examples", "policy", "caplock.yaml")
	stdout, stderr, code := run(t, "report", good, "--format", "sarif")
	if code != 0 {
		t.Fatalf("report sarif exit code = %d, stderr = %s", code, stderr)
	}
	var sarif map[string]any
	if err := json.Unmarshal([]byte(stdout), &sarif); err != nil {
		t.Fatalf("decode SARIF: %v\n%s", err, stdout)
	}
	if sarif["version"] != "2.1.0" {
		t.Fatalf("SARIF = %#v", sarif)
	}

	stdout, stderr, code = run(t, "report", good, "--format", "html")
	if code != 0 || !strings.Contains(stdout, "<!doctype html>") {
		t.Fatalf("html exit code = %d, stderr = %s, stdout = %s", code, stderr, stdout)
	}

	unsafe := writeUnsafePolicy(t)
	stdout, stderr, code = run(t, "report", unsafe, "--format", "json", "--fail-on-gaps")
	if code != 1 {
		t.Fatalf("fail-on-gaps exit code = %d, want 1; stderr = %s", code, stderr)
	}
	var document struct {
		Passed bool  `json:"passed"`
		Gaps   []any `json:"gaps"`
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("decode report JSON: %v\n%s", err, stdout)
	}
	if document.Passed || len(document.Gaps) == 0 {
		t.Fatalf("report = %#v", document)
	}
}

func TestReportAndExportWriteFiles(t *testing.T) {
	path := repoPath(t, "examples", "policy", "caplock.yaml")
	root := t.TempDir()
	reportPath := filepath.Join(root, "report.json")
	_, stderr, code := run(t, "report", path, "--format", "json", "--output", reportPath)
	if code != 0 {
		t.Fatalf("report exit code = %d, stderr = %s", code, stderr)
	}
	if data, err := os.ReadFile(reportPath); err != nil || !strings.Contains(string(data), `"summary"`) {
		t.Fatalf("report file = %v, %s", err, data)
	}

	exportPath := filepath.Join(root, "policy.rego")
	_, stderr, code = run(t, "export", path, "--format", "rego", "--output", exportPath)
	if code != 0 {
		t.Fatalf("export exit code = %d, stderr = %s", code, stderr)
	}
	if data, err := os.ReadFile(exportPath); err != nil || !strings.Contains(string(data), "package caplock") {
		t.Fatalf("export file = %v, %s", err, data)
	}
}

func TestExportFormats(t *testing.T) {
	path := repoPath(t, "examples", "policy", "caplock.yaml")
	for _, format := range []string{"rego", "yaml", "json"} {
		t.Run(format, func(t *testing.T) {
			stdout, stderr, code := run(t, "export", path, "--format", format)
			if code != 0 {
				t.Fatalf("export %s exit code = %d, stderr = %s", format, code, stderr)
			}
			switch format {
			case "rego":
				if !strings.Contains(stdout, "package caplock") {
					t.Fatalf("rego = %s", stdout)
				}
			case "yaml":
				if !strings.Contains(stdout, "policy: finance-agent") {
					t.Fatalf("yaml = %s", stdout)
				}
			case "json":
				var document map[string]any
				if err := json.Unmarshal([]byte(stdout), &document); err != nil {
					t.Fatalf("json = %v\n%s", err, stdout)
				}
			}
		})
	}
	_, _, code := run(t, "export", path, "--format", "cedar")
	if code != 2 {
		t.Fatalf("unknown export format exit code = %d, want 2", code)
	}
}

func TestProxyRequiresSubjectAndTarget(t *testing.T) {
	_, stderr, code := run(t, "proxy", "--", "echo")
	if code != 2 || !strings.Contains(stderr, "subject") {
		t.Fatalf("proxy exit code = %d, stderr = %s", code, stderr)
	}
	_, stderr, code = run(t, "proxy", "http", "--subject", "agent")
	if code != 2 || !strings.Contains(stderr, "target") {
		t.Fatalf("proxy http exit code = %d, stderr = %s", code, stderr)
	}
}

func TestProxyRejectsUnsafeAuditPaths(t *testing.T) {
	path := repoPath(t, "examples", "policy", "caplock.yaml")
	alertPath := filepath.Join(t.TempDir(), "alert.jsonl")
	_, stderr, code := run(t, "proxy", "--policy", path, "--subject", "agent", "--audit", t.TempDir(), "--alert", alertPath, "--", "echo")
	if code != 3 {
		t.Fatalf("directory audit exit code = %d, stderr = %s", code, stderr)
	}
	if runtime.GOOS == "windows" {
		return
	}
	root := t.TempDir()
	realPath := filepath.Join(root, "real.jsonl")
	if err := os.WriteFile(realPath, nil, 0o600); err != nil {
		t.Fatalf("write audit target: %v", err)
	}
	linkPath := filepath.Join(root, "audit.jsonl")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	_, stderr, code = run(t, "proxy", "--policy", path, "--subject", "agent", "--audit", linkPath, "--alert", alertPath, "--", "echo")
	if code != 3 || !strings.Contains(stderr, "symlink") {
		t.Fatalf("symlink audit exit code = %d, stderr = %s", code, stderr)
	}
}

func TestProxyTraceOptionsAndUnsafePaths(t *testing.T) {
	path := repoPath(t, "examples", "policy", "caplock.yaml")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	alertPath := filepath.Join(t.TempDir(), "alert.jsonl")
	_, stderr, code := run(t, "proxy", "--policy", path, "--subject", "agent", "--audit", auditPath, "--alert", alertPath, "--trace-arguments", "full", "--", "echo")
	if code != 2 || !strings.Contains(stderr, "--trace") {
		t.Fatalf("trace arguments without trace exit code = %d, stderr = %s", code, stderr)
	}
	_, stderr, code = run(t, "proxy", "--policy", path, "--subject", "agent", "--audit", auditPath, "--alert", alertPath, "--trace-arguments", "raw", "--trace", filepath.Join(t.TempDir(), "trace.jsonl"), "--", "echo")
	if code != 2 || !strings.Contains(stderr, "trace-arguments") {
		t.Fatalf("invalid trace arguments exit code = %d, stderr = %s", code, stderr)
	}
	_, stderr, code = run(t, "proxy", "--policy", path, "--subject", "agent", "--audit", auditPath, "--alert", alertPath, "--trace", t.TempDir(), "--", "echo")
	if code != 3 {
		t.Fatalf("directory trace exit code = %d, stderr = %s", code, stderr)
	}
	if runtime.GOOS == "windows" {
		return
	}
	root := t.TempDir()
	realPath := filepath.Join(root, "real.jsonl")
	if err := os.WriteFile(realPath, nil, 0o600); err != nil {
		t.Fatalf("write trace target: %v", err)
	}
	linkPath := filepath.Join(root, "trace.jsonl")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	_, stderr, code = run(t, "proxy", "--policy", path, "--subject", "agent", "--audit", auditPath, "--alert", alertPath, "--trace", linkPath, "--", "echo")
	if code != 3 || !strings.Contains(stderr, "symlink") {
		t.Fatalf("symlink trace exit code = %d, stderr = %s", code, stderr)
	}
}
