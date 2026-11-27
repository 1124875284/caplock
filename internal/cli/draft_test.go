package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDraftCreatesLintablePolicy(t *testing.T) {
	root := t.TempDir()
	briefPath := filepath.Join(root, "finance-agent.txt")
	brief := `Child agents must not exceed their parent permissions.
Deny secret data from leaving through email.
Finance tools are forbidden outside Mon-Fri 09:00-18:00 Asia/Shanghai.
Require approval for all write operations.
Allow read-only operations.
`
	if err := os.WriteFile(briefPath, []byte(brief), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}
	policyPath := filepath.Join(root, "caplock.yaml")
	stdout, stderr, code := run(t, "draft", briefPath, "--output", policyPath, "--subject", "finance-analyst", "--parent", "orchestrator")
	if code != 0 {
		t.Fatalf("draft exit code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "wrote") || !strings.Contains(stdout, "4 rules") {
		t.Fatalf("draft stdout = %q", stdout)
	}
	stdout, stderr, code = run(t, "lint", policyPath)
	if code != 0 || !strings.Contains(stdout, "No policy lint findings") {
		t.Fatalf("lint exit code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	_, stderr, code = run(t, "draft", briefPath, "--output", policyPath)
	if code != 2 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("second draft exit code = %d, stderr = %q", code, stderr)
	}
	if _, stderr, code = run(t, "draft", briefPath, "--output", policyPath, "--force"); code != 0 {
		t.Fatalf("forced draft exit code = %d, stderr = %q", code, stderr)
	}
}

func TestDraftListsTemplates(t *testing.T) {
	stdout, stderr, code := run(t, "draft", "--list-templates")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	for _, expected := range []string{"TEMPLATE", "deny-secret-egress", "delegation-attenuate-only", "require-approval-pii-egress"} {
		if !strings.Contains(stdout, expected) {
			t.Fatalf("template list missing %q:\n%s", expected, stdout)
		}
	}
}

func TestDraftRejectsUnknownStatement(t *testing.T) {
	root := t.TempDir()
	briefPath := filepath.Join(root, "bad.txt")
	if err := os.WriteFile(briefPath, []byte("Make the agent secure.\n"), 0o644); err != nil {
		t.Fatalf("write brief: %v", err)
	}
	_, stderr, code := run(t, "draft", briefPath)
	if code != 2 || !strings.Contains(stderr, "no template matched") {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
}
