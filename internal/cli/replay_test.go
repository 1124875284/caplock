package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1124875284/caplock/internal/canonical"
	"github.com/1124875284/caplock/internal/trace"
)

const replayHash = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

func writeReplayFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	policyPath := filepath.Join(root, "caplock.yaml")
	policySource := `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: replay-policy
spec:
  defaults:
    effect: deny
  rules:
    - id: allow-destructive
      effect: allow
      match:
        capability: [destructive]
    - id: allow-read
      effect: allow
      match:
        capability: [read]
`
	if err := os.WriteFile(policyPath, []byte(policySource), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	tracePath := filepath.Join(root, "calls.jsonl")
	file, err := os.OpenFile(tracePath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("create trace: %v", err)
	}
	writer := trace.NewJSONLWriter(file)
	argumentsHash, err := canonical.HashArguments(map[string]any{"path": "/workspace/a"})
	if err != nil {
		t.Fatalf("hash arguments: %v", err)
	}
	records := []trace.Record{
		{
			Version:      trace.Version,
			Time:         time.Date(2026, 1, 3, 10, 0, 0, 0, time.UTC),
			Policy:       "old-policy",
			Subject:      "finance-analyst",
			Tool:         "delete_repository",
			Capabilities: []string{"destructive"},
			ArgsHash:     replayHash,
			Decision: trace.Decision{
				Effect:      "deny",
				RuleID:      "deny-destructive",
				Obligations: []string{"audit"},
			},
		},
		{
			Version:           trace.Version,
			Time:              time.Date(2026, 1, 3, 10, 5, 0, 0, time.UTC),
			Policy:            "old-policy",
			Subject:           "finance-analyst",
			Tool:              "read_file",
			Capabilities:      []string{"read"},
			ArgumentsCaptured: true,
			Args:              map[string]any{"path": "/workspace/a"},
			ArgsHash:          argumentsHash,
			Decision: trace.Decision{
				Effect: "allow",
				RuleID: "allow-read",
			},
		},
	}
	for _, record := range records {
		if err := writer.Write(record); err != nil {
			_ = file.Close()
			t.Fatalf("write trace: %v", err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close trace: %v", err)
	}
	return policyPath, tracePath
}

func TestReplayCommandReportsChanges(t *testing.T) {
	policyPath, tracePath := writeReplayFixture(t)
	stdout, stderr, code := run(t, "replay", tracePath, "--policy", policyPath)
	if code != 0 {
		t.Fatalf("replay exit code = %d, stderr = %q", code, stderr)
	}
	for _, expected := range []string{
		"Caplock trace replay",
		"Records: total=2 unchanged=1 changed=1 weakened=1 strengthened=0 args_missing=1 args_redacted=0",
		"[WEAKENED]",
		"delete_repository",
	} {
		if !strings.Contains(stdout, expected) {
			t.Fatalf("replay output missing %q:\n%s", expected, stdout)
		}
	}

	stdout, stderr, code = run(t, "replay", tracePath, "--policy", policyPath, "--format", "json")
	if code != 0 {
		t.Fatalf("replay JSON exit code = %d, stderr = %q", code, stderr)
	}
	var result trace.Result
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("decode replay JSON: %v\n%s", err, stdout)
	}
	if result.Total != 2 || result.Changed != 1 || result.Weakened != 1 || result.ArgsMissing != 1 || len(result.Changes) != 1 {
		t.Fatalf("replay result = %#v", result)
	}
	if result.Changes[0].Direction != trace.DirectionWeakened || result.Changes[0].Before.Effect != "deny" || result.Changes[0].After.Effect != "allow" {
		t.Fatalf("replay change = %#v", result.Changes[0])
	}
}

func TestReplayCommandExitCodesAndOutputFile(t *testing.T) {
	policyPath, tracePath := writeReplayFixture(t)
	for _, args := range [][]string{
		{"replay", tracePath, "--policy", policyPath, "--fail-on-change"},
		{"replay", tracePath, "--policy", policyPath, "--fail-on-weakened"},
		{"replay", tracePath, "--policy", policyPath, "--strict-args"},
	} {
		_, stderr, code := run(t, args...)
		if code != 1 {
			t.Fatalf("%v exit code = %d, want 1; stderr = %q", args, code, stderr)
		}
	}

	outputPath := filepath.Join(t.TempDir(), "replay.json")
	stdout, stderr, code := run(t, "replay", tracePath, "--policy", policyPath, "--format", "json", "--output", outputPath)
	if code != 0 {
		t.Fatalf("replay --output exit code = %d, stderr = %q", code, stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("replay --output wrote to stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "wrote") || !strings.Contains(stderr, "1 changes") {
		t.Fatalf("replay --output stderr = %q", stderr)
	}
	if data, err := os.ReadFile(outputPath); err != nil || !strings.Contains(string(data), `"weakened": 1`) {
		t.Fatalf("replay output file = %v, %s", err, data)
	}
}

func TestReplayCommandRejectsInvalidTrace(t *testing.T) {
	policyPath, _ := writeReplayFixture(t)
	path := filepath.Join(t.TempDir(), "bad.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write bad trace: %v", err)
	}
	_, stderr, code := run(t, "replay", path, "--policy", policyPath)
	if code != 2 || !strings.Contains(stderr, "parse trace") {
		t.Fatalf("invalid trace exit code = %d, stderr = %q", code, stderr)
	}
}
