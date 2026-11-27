package policy

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Request is the deterministic authorization input consumed by the evaluator.
// Time is an instant; policy time windows resolve it in their own IANA zone.
type Request struct {
	Subject      string         `json:"subject" yaml:"subject"`
	Tool         string         `json:"tool" yaml:"tool"`
	Capabilities []string       `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	DataClass    []string       `json:"dataClass,omitempty" yaml:"dataClass,omitempty"`
	Sink         string         `json:"sink,omitempty" yaml:"sink,omitempty"`
	Args         map[string]any `json:"args,omitempty" yaml:"args,omitempty"`
	Context      RequestContext `json:"context,omitempty" yaml:"context,omitempty"`
	Provenance   []string       `json:"provenance,omitempty" yaml:"provenance,omitempty"`
}

// RequestContext carries non-tool inputs used by policy selectors.
type RequestContext struct {
	Time        time.Time         `json:"time,omitempty" yaml:"time,omitempty"`
	Environment string            `json:"environment,omitempty" yaml:"environment,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty" yaml:"attributes,omitempty"`
}

// MatchedRule is one rule that matched a request, retained as decision evidence.
type MatchedRule struct {
	ID          string   `json:"id"`
	Effect      string   `json:"effect"`
	Priority    int      `json:"priority"`
	Obligations []string `json:"obligations"`
	Reasons     []string `json:"reasons"`
	Source      Source   `json:"source"`
}

// Decision is the deterministic result of evaluating one request.
type Decision struct {
	Effect       string        `json:"effect"`
	RuleID       string        `json:"ruleId,omitempty"`
	Default      bool          `json:"default"`
	Obligations  []string      `json:"obligations"`
	MatchedRules []MatchedRule `json:"matchedRules"`
}

type indexedMatch struct {
	rule    Rule
	index   int
	reasons []string
}

// Evaluate applies deny > require_approval > allow precedence, then explicit
// priority, then source order. A zero request time is evaluated at the current
// instant; callers that need reproducible results must set Context.Time.
func Evaluate(ir *IR, request Request) (Decision, error) {
	if ir == nil {
		return Decision{}, errors.New("policy is nil")
	}
	if !validEffect(ir.Defaults.Effect) {
		return Decision{}, fmt.Errorf("policy has invalid default effect %q", ir.Defaults.Effect)
	}
	at := request.Context.Time
	if at.IsZero() {
		at = time.Now()
	}

	matches := make([]indexedMatch, 0)
	for index := range ir.Rules {
		rule := &ir.Rules[index]
		matched, reasons, err := matchRule(rule, request, at)
		if err != nil {
			return Decision{}, fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		if matched {
			matches = append(matches, indexedMatch{rule: *rule, index: index, reasons: reasons})
		}
	}

	trace := make([]MatchedRule, 0, len(matches))
	for _, match := range matches {
		priority := 0
		if match.rule.Priority != nil {
			priority = *match.rule.Priority
		}
		trace = append(trace, MatchedRule{
			ID:          match.rule.ID,
			Effect:      match.rule.Effect,
			Priority:    priority,
			Obligations: nonNilStrings(match.rule.Obligations),
			Reasons:     nonNilStrings(match.reasons),
			Source:      match.rule.Source,
		})
	}
	if len(matches) == 0 {
		return Decision{
			Effect:       ir.Defaults.Effect,
			Default:      true,
			Obligations:  []string{},
			MatchedRules: []MatchedRule{},
		}, nil
	}

	for _, effect := range []string{EffectDeny, EffectRequireApproval, EffectAllow} {
		selected, ok := selectMatch(matches, effect)
		if !ok {
			continue
		}
		return Decision{
			Effect:       selected.rule.Effect,
			RuleID:       selected.rule.ID,
			Default:      false,
			Obligations:  nonNilStrings(selected.rule.Obligations),
			MatchedRules: trace,
		}, nil
	}
	return Decision{}, errors.New("matching rules did not produce a decision")
}

func selectMatch(matches []indexedMatch, effect string) (indexedMatch, bool) {
	var selected indexedMatch
	found := false
	selectedPriority := 0
	for _, match := range matches {
		if match.rule.Effect != effect {
			continue
		}
		priority := 0
		if match.rule.Priority != nil {
			priority = *match.rule.Priority
		}
		if !found || priority > selectedPriority || priority == selectedPriority && match.index < selected.index {
			selected = match
			selectedPriority = priority
			found = true
		}
	}
	return selected, found
}

func matchRule(rule *Rule, request Request, at time.Time) (bool, []string, error) {
	if rule.Match == nil {
		return false, nil, errors.New("match is required")
	}
	match := rule.Match
	reasons := make([]string, 0, 8)

	if match.Subject != "" {
		if !matchesScalar(match.Subject, request.Subject) {
			return false, nil, nil
		}
		reasons = append(reasons, "subject="+match.Subject)
	}
	if len(match.Tool) > 0 {
		if !matchesStringSelector(match.Tool, request.Tool) {
			return false, nil, nil
		}
		reasons = append(reasons, "tool="+firstMatchingSelector(match.Tool, request.Tool))
	}
	if len(match.Capability) > 0 {
		selected := firstOverlappingSelector(match.Capability, request.Capabilities)
		if selected == "" {
			return false, nil, nil
		}
		reasons = append(reasons, "capability="+selected)
	}
	if len(match.DataClass) > 0 {
		selected := firstOverlappingSelector(match.DataClass, request.DataClass)
		if selected == "" {
			return false, nil, nil
		}
		reasons = append(reasons, "dataClass="+selected)
	}
	if match.Sink != "" {
		if !matchesScalar(match.Sink, request.Sink) {
			return false, nil, nil
		}
		reasons = append(reasons, "sink="+match.Sink)
	}
	if match.Context != nil {
		if match.Context.Time != nil {
			window, err := parseTimeWindow(match.Context.Time.Outside)
			if err != nil {
				return false, nil, err
			}
			if !window.outside(at) {
				return false, nil, nil
			}
			reasons = append(reasons, "time.outside="+match.Context.Time.Outside)
		}
		if match.Context.Environment != "" {
			if !matchesScalar(match.Context.Environment, request.Context.Environment) {
				return false, nil, nil
			}
			reasons = append(reasons, "environment="+match.Context.Environment)
		}
		if len(match.Context.Attributes) > 0 {
			keys := sortedMapKeys(match.Context.Attributes)
			for _, key := range keys {
				actual, ok := request.Context.Attributes[key]
				if !ok || !matchesScalar(match.Context.Attributes[key], actual) {
					return false, nil, nil
				}
				reasons = append(reasons, "attribute."+key)
			}
		}
	}
	if match.Provenance != nil {
		selected := firstOverlappingSelector([]string(match.Provenance.Contains), request.Provenance)
		if selected == "" {
			return false, nil, nil
		}
		reasons = append(reasons, "provenance="+selected)
	}
	if len(match.Args) > 0 {
		ok, argReasons, err := matchArgumentSelectors(request.Args, match.Args)
		if err != nil {
			return false, nil, err
		}
		if !ok {
			return false, nil, nil
		}
		reasons = append(reasons, argReasons...)
	}
	return true, reasons, nil
}

func matchesScalar(selector, actual string) bool {
	return selector == "*" || selector == actual
}

func matchesStringSelector(selectors []string, actual string) bool {
	if len(selectors) == 0 {
		return true
	}
	for _, selector := range selectors {
		if selector == "*" || actual != "" && selector == actual {
			return true
		}
	}
	return false
}

func firstMatchingSelector(selectors []string, actual string) string {
	for _, selector := range selectors {
		if selector == "*" || selector == actual {
			return selector
		}
	}
	return ""
}

func firstOverlappingSelector(selectors, actual []string) string {
	for _, selector := range selectors {
		if selector == "*" {
			return selector
		}
	}
	set := make(map[string]bool, len(actual))
	for _, value := range actual {
		set[value] = true
	}
	for _, selector := range selectors {
		if set[selector] {
			return selector
		}
	}
	return ""
}

func sortedMapKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
