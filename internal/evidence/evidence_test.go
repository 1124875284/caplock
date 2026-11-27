package evidence

import (
	"strings"
	"testing"
	"time"

	"github.com/1124875284/caplock/internal/lockfile"
	"github.com/1124875284/caplock/internal/policy"
)

const testPolicy = `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: evidence-test
spec:
  defaults:
    effect: deny
  subjects:
    - id: parent
    - id: child
      parent: parent
      delegation: attenuate-only
  rules:
    - id: read
      effect: allow
      match:
        capability: [read]
    - id: destructive
      effect: deny
      match:
        capability: [destructive]
`

const testCorpus = `version: 1
name: unit
cases:
  - id: read-file
    severity: low
    tags: [safe, read]
    path:
      - tool: read_file
        capabilities: [read]
    request:
      subject: child
      tool: read_file
      capabilities: [read]
      context:
        time: "2026-11-26T10:00:00+08:00"
    expect:
      effect: allow
      rule: read
  - id: delete-file
    severity: high
    path:
      - tool: delete_file
        capabilities: [destructive, write]
    request:
      subject: child
      tool: delete_file
      capabilities: [destructive, write]
    expect:
      effect: deny
      rule: destructive
`

func TestParseCorpusAndRun(t *testing.T) {
	corpus, err := Parse([]byte(testCorpus))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got, want := corpus.Cases[0].ID, "delete-file"; got != want {
		t.Fatalf("first case = %q, want %q", got, want)
	}
	if got := corpus.Cases[1].Request.Context.Time; got.IsZero() || got.Location() == time.UTC {
		t.Fatalf("time was not decoded with its offset: %v", got)
	}
	ir, err := policy.Compile([]byte(testPolicy), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	result, err := Run(ir, corpus, Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !result.Passed || result.Total != 2 || result.PassedCount != 2 || result.FailedCount != 0 {
		t.Fatalf("result = %#v", result)
	}
	if len(result.Invariants) != 1 || !result.Invariants[0].Passed || result.Invariants[0].Checked != 2 {
		t.Fatalf("invariants = %#v", result.Invariants)
	}
}

func TestRunUsesDeterministicDefaultTime(t *testing.T) {
	ir, err := policy.Compile([]byte(`apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: time-default
spec:
  defaults:
    effect: allow
  rules:
    - id: deny-thursday-noon
      effect: deny
      match:
        capability: [finance.write]
        context:
          time:
            outside: "Thu 12:00-13:00 UTC"
`), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	corpus, err := Parse([]byte(`version: 1
name: time-default
cases:
  - id: no-explicit-time
    severity: low
    request:
      subject: agent
      tool: transfer_funds
      capabilities: [finance.write]
    expect:
      effect: allow
      default: true
`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	for range 2 {
		result, err := Run(ir, corpus, Options{})
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if !result.Passed || result.Cases[0].Decision.Effect != policy.EffectAllow {
			t.Fatalf("result = %#v", result)
		}
	}
}

func TestRunDetectsExpectationBaselineAndDelegationFailure(t *testing.T) {
	corpus, err := Parse([]byte(testCorpus))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	current, err := policy.Compile([]byte(testPolicy), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	baseline, err := policy.Compile([]byte(strings.ReplaceAll(testPolicy,
		"    - id: destructive\n      effect: deny\n      match:\n        capability: [destructive]\n",
		"    - id: destructive\n      effect: allow\n      match:\n        capability: [destructive]\n",
	)), "baseline.yaml")
	if err != nil {
		t.Fatalf("baseline Compile() error = %v", err)
	}
	result, err := Run(current, corpus, Options{Baseline: baseline})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.BaselineChanges) != 1 || result.BaselineChanges[0].CaseID != "delete-file" {
		t.Fatalf("baseline changes = %#v", result.BaselineChanges)
	}
	if !result.Passed {
		t.Fatalf("current policy should pass: %#v", result)
	}

	childOverride := strings.Replace(testPolicy,
		"    - id: read\n      effect: allow\n      match:\n        capability: [read]\n",
		"    - id: read\n      effect: allow\n      match:\n        subject: child\n        capability: [read]\n", 1)
	bad, err := policy.Compile([]byte(childOverride), "child.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	result, err = Run(bad, corpus, Options{})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Invariants[0].Passed {
		t.Fatalf("delegation invariant passed unexpectedly: %#v", result.Invariants[0])
	}
	if result.Invariants[0].Violations[0].CaseID != "read-file" {
		t.Fatalf("violations = %#v", result.Invariants[0].Violations)
	}
}

func TestParseCorpusRejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte("version: 1\nname: bad\nunexpected: true\ncases: []\n"))
	if err == nil || !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestCheckCoverage(t *testing.T) {
	ir, err := policy.Compile([]byte(testPolicy), "caplock.yaml")
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	capabilities := []string{"read"}
	tools := []lockfile.Tool{{Name: "read_file", Capabilities: capabilities}, {Name: "mystery_tool", Capabilities: []string{"unknown"}}}
	file := &lockfile.File{Version: lockfile.Version, Servers: []lockfile.Server{{Name: "demo", Tools: &tools}}}
	coverage := CheckCoverage(ir, file, "child")
	if len(coverage) != 2 || coverage[0].Tool != "mystery_tool" || coverage[0].Covered || !coverage[1].Covered {
		t.Fatalf("coverage = %#v", coverage)
	}
}
