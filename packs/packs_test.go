package packs_test

import (
	"testing"

	"github.com/1124875284/caplock/internal/evidence"
	"github.com/1124875284/caplock/internal/policy"
	"github.com/1124875284/caplock/packs"
)

func TestEmbeddedFinancePolicyPassesBaselineCorpus(t *testing.T) {
	policySource, err := packs.Read("policies/finance.yaml")
	if err != nil {
		t.Fatalf("read finance policy: %v", err)
	}
	corpusSource, err := packs.Read("attacks/baseline.yaml")
	if err != nil {
		t.Fatalf("read baseline corpus: %v", err)
	}
	ir, err := policy.Compile(policySource, "caplock.yaml")
	if err != nil {
		t.Fatalf("compile finance policy: %v", err)
	}
	if issues := policy.Lint(ir, "caplock.yaml"); policy.HasErrors(issues) || len(issues) != 0 {
		t.Fatalf("finance policy lint findings = %#v", issues)
	}
	corpus, err := evidence.Parse(corpusSource)
	if err != nil {
		t.Fatalf("parse baseline corpus: %v", err)
	}
	if len(corpus.Cases) != 50 {
		t.Fatalf("baseline cases = %d, want 50", len(corpus.Cases))
	}
	result, err := evidence.Run(ir, corpus, evidence.Options{})
	if err != nil {
		t.Fatalf("run baseline corpus: %v", err)
	}
	for _, item := range result.Cases {
		if !item.Passed {
			t.Errorf("case %s failed: %v", item.ID, item.FailureReasons)
		}
	}
	for _, invariant := range result.Invariants {
		if !invariant.Passed {
			t.Errorf("invariant %s failed: %#v", invariant.Code, invariant.Violations)
		}
	}
	if !result.Passed || result.PassedCount != 50 {
		t.Fatalf("result = passed=%t passedCount=%d", result.Passed, result.PassedCount)
	}
}

func TestEmbeddedTemplateLibraryCompiles(t *testing.T) {
	source, err := packs.Read("templates/rules.yaml")
	if err != nil {
		t.Fatalf("read template library: %v", err)
	}
	ir, err := policy.Compile(source, "rules.yaml")
	if err != nil {
		t.Fatalf("compile template library: %v", err)
	}
	if got, want := len(ir.Rules), 15; got != want {
		t.Fatalf("template rules = %d, want %d", got, want)
	}
	if issues := policy.Lint(ir, "rules.yaml"); policy.HasErrors(issues) {
		t.Fatalf("template library lint errors = %#v", issues)
	}
}
