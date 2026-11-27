package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Severity is the effect of a lint finding.
type Severity string

const (
	// SeverityError means the policy should not be accepted.
	SeverityError Severity = "error"
	// SeverityWarning means the policy compiles but deserves review.
	SeverityWarning Severity = "warning"
)

// Issue is one deterministic policy lint finding.
type Issue struct {
	Severity Severity `json:"severity"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
	RuleID   string   `json:"ruleId,omitempty"`
	Source   *Source  `json:"source,omitempty"`
}

// Lint checks structural and review invariants that are not required to
// serialize Policy IR. sourceName is used for findings without a rule location.
func Lint(ir *IR, sourceName string) []Issue {
	if sourceName == "" {
		sourceName = Name
	}
	issues := make([]Issue, 0)
	fallback := &Source{File: sourceName, Line: 1}

	if ir.Defaults.Effect == EffectAllow {
		issues = append(issues, Issue{
			Severity: SeverityWarning,
			Code:     "default-allow",
			Message:  "defaults.effect is allow; confirm that unmatched requests should be allowed",
			Source:   fallback,
		})
	}

	subjectIndex := make(map[string]Subject, len(ir.Subjects))
	for _, subject := range ir.Subjects {
		subjectIndex[subject.ID] = subject
	}
	for _, subject := range ir.Subjects {
		if subject.Parent == "" {
			if subject.Delegation == DelegationAttenuateOnly {
				issues = append(issues, Issue{
					Severity: SeverityWarning,
					Code:     "orphan-delegation",
					Message:  fmt.Sprintf("subject %q declares attenuate-only delegation without a parent", subject.ID),
					Source:   fallback,
				})
			}
			continue
		}
		if subject.Parent == subject.ID {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Code:     "subject-self-parent",
				Message:  fmt.Sprintf("subject %q is its own parent", subject.ID),
				Source:   fallback,
			})
			continue
		}
		if _, exists := subjectIndex[subject.Parent]; !exists {
			issues = append(issues, Issue{
				Severity: SeverityError,
				Code:     "unknown-parent",
				Message:  fmt.Sprintf("subject %q references unknown parent %q", subject.ID, subject.Parent),
				Source:   fallback,
			})
		}
	}
	issues = append(issues, detectSubjectCycles(ir.Subjects, fallback)...)

	for _, rule := range ir.Rules {
		source := rule.Source
		if rule.Match.Subject != "" {
			if _, exists := subjectIndex[rule.Match.Subject]; !exists {
				issues = append(issues, Issue{
					Severity: SeverityError,
					Code:     "unknown-rule-subject",
					Message:  fmt.Sprintf("rule %q references unknown subject %q", rule.ID, rule.Match.Subject),
					RuleID:   rule.ID,
					Source:   &source,
				})
			}
		}
		if rule.Effect == EffectAllow && matchIsSubjectOnly(rule.Match) {
			issues = append(issues, Issue{
				Severity: SeverityWarning,
				Code:     "broad-allow",
				Message:  fmt.Sprintf("allow rule %q selects only a subject; add a tool, capability, sink, or argument condition", rule.ID),
				RuleID:   rule.ID,
				Source:   &source,
			})
		}
		if rule.Match != nil && !rule.Match.hasCriteria() {
			issues = append(issues, Issue{
				Severity: SeverityWarning,
				Code:     "empty-match",
				Message:  fmt.Sprintf("rule %q has no match criteria and applies to every request", rule.ID),
				RuleID:   rule.ID,
				Source:   &source,
			})
		}
		if wildcard := wildcardLocation(rule.Match); wildcard != "" {
			issues = append(issues, Issue{
				Severity: SeverityWarning,
				Code:     "wildcard-match",
				Message:  fmt.Sprintf("rule %q uses wildcard %q in %s", rule.ID, "*", wildcard),
				RuleID:   rule.ID,
				Source:   &source,
			})
		}
	}

	issues = append(issues, detectShadowedRules(ir.Rules)...)
	issues = append(issues, detectRuleConflicts(ir.Rules)...)
	sort.SliceStable(issues, func(i, j int) bool {
		leftRank := severityRank(issues[i].Severity)
		rightRank := severityRank(issues[j].Severity)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		leftLine := issueLine(issues[i])
		rightLine := issueLine(issues[j])
		if leftLine != rightLine {
			return leftLine < rightLine
		}
		if issues[i].Code != issues[j].Code {
			return issues[i].Code < issues[j].Code
		}
		return issues[i].Message < issues[j].Message
	})
	return issues
}

func detectShadowedRules(rules []Rule) []Issue {
	issues := make([]Issue, 0)
	for targetIndex, target := range rules {
		if target.Match == nil {
			continue
		}
		for coverIndex, cover := range rules {
			if targetIndex == coverIndex || cover.Match == nil {
				continue
			}
			if !rulePrecedes(cover, target, coverIndex < targetIndex) || !matchCovers(cover.Match, target.Match) {
				continue
			}
			source := target.Source
			issues = append(issues, Issue{
				Severity: SeverityWarning,
				Code:     "shadowed-rule",
				Message:  fmt.Sprintf("rule %q is unreachable for requests matched by rule %q", target.ID, cover.ID),
				RuleID:   target.ID,
				Source:   &source,
			})
			break
		}
	}
	return issues
}

func rulePrecedes(cover, target Rule, coverEarlier bool) bool {
	coverRank := effectPrecedence(cover.Effect)
	targetRank := effectPrecedence(target.Effect)
	if coverRank != targetRank {
		return coverRank > targetRank
	}
	coverPriority := 0
	if cover.Priority != nil {
		coverPriority = *cover.Priority
	}
	targetPriority := 0
	if target.Priority != nil {
		targetPriority = *target.Priority
	}
	if coverPriority != targetPriority {
		return coverPriority > targetPriority
	}
	return coverEarlier
}

func effectPrecedence(effect string) int {
	switch effect {
	case EffectDeny:
		return 2
	case EffectRequireApproval:
		return 1
	default:
		return 0
	}
}

func matchCovers(cover, target *Match) bool {
	if cover == nil || target == nil {
		return false
	}
	if !scalarCovers(cover.Subject, target.Subject) || !scalarCovers(cover.Sink, target.Sink) {
		return false
	}
	if !selectorCovers(cover.Tool, target.Tool) ||
		!selectorCovers(cover.Capability, target.Capability) ||
		!selectorCovers(cover.DataClass, target.DataClass) {
		return false
	}
	if cover.Provenance != nil && (target.Provenance == nil || !selectorCovers([]string(cover.Provenance.Contains), []string(target.Provenance.Contains))) {
		return false
	}
	if cover.Context != nil {
		if target.Context == nil || !contextCovers(cover.Context, target.Context) {
			return false
		}
	}
	return argsCover(cover.Args, target.Args)
}

func scalarCovers(cover, target string) bool {
	if cover == "" || cover == "*" {
		return true
	}
	return target != "" && target != "*" && cover == target
}

func selectorCovers(cover, target []string) bool {
	if len(cover) == 0 {
		return true
	}
	for _, value := range cover {
		if value == "*" {
			return true
		}
	}
	if len(target) == 0 {
		return false
	}
	set := make(map[string]bool, len(cover))
	for _, value := range cover {
		set[value] = true
	}
	for _, value := range target {
		if value == "*" || !set[value] {
			return false
		}
	}
	return true
}

func contextCovers(cover, target *Context) bool {
	if cover.Environment != "" && cover.Environment != "*" {
		if target.Environment == "" || target.Environment == "*" || target.Environment != cover.Environment {
			return false
		}
	}
	if cover.Time != nil {
		if target.Time == nil || target.Time.Outside != cover.Time.Outside {
			return false
		}
	}
	if len(cover.Attributes) > 0 {
		for key, value := range cover.Attributes {
			targetValue, ok := target.Attributes[key]
			if !ok || value != "*" && value != targetValue {
				return false
			}
		}
	}
	return true
}

func argsCover(cover, target map[string]any) bool {
	if len(cover) == 0 {
		return true
	}
	for key, value := range cover {
		targetValue, ok := target[key]
		if !ok {
			return false
		}
		coverJSON, coverErr := json.Marshal(value)
		targetJSON, targetErr := json.Marshal(targetValue)
		if coverErr != nil || targetErr != nil || string(coverJSON) != string(targetJSON) {
			return false
		}
	}
	return true
}

// HasErrors reports whether any finding has error severity.
func HasErrors(issues []Issue) bool {
	for _, issue := range issues {
		if issue.Severity == SeverityError {
			return true
		}
	}
	return false
}

func detectSubjectCycles(subjects []Subject, fallback *Source) []Issue {
	index := make(map[string]Subject, len(subjects))
	for _, subject := range subjects {
		index[subject.ID] = subject
	}
	issues := make([]Issue, 0)
	reported := make(map[string]bool)
	for _, start := range subjects {
		path := make(map[string]bool)
		current := start.ID
		for current != "" {
			if path[current] {
				if !reported[current] {
					reported[current] = true
					issues = append(issues, Issue{
						Severity: SeverityError,
						Code:     "subject-cycle",
						Message:  fmt.Sprintf("subject %q participates in a delegation cycle", current),
						Source:   fallback,
					})
				}
				break
			}
			path[current] = true
			subject, exists := index[current]
			if !exists {
				break
			}
			current = subject.Parent
		}
	}
	return issues
}

func detectRuleConflicts(rules []Rule) []Issue {
	type group struct {
		rule   Rule
		effect string
	}
	groups := make(map[string][]group)
	order := make([]string, 0)
	for _, rule := range rules {
		canonical, err := json.Marshal(rule.Match)
		if err != nil {
			continue
		}
		key := string(canonical)
		if _, exists := groups[key]; !exists {
			order = append(order, key)
		}
		groups[key] = append(groups[key], group{rule: rule, effect: rule.Effect})
	}
	issues := make([]Issue, 0)
	for _, key := range order {
		items := groups[key]
		if len(items) < 2 {
			continue
		}
		effects := make(map[string]bool)
		ids := make([]string, 0, len(items))
		for _, item := range items {
			effects[item.effect] = true
			ids = append(ids, item.rule.ID)
		}
		sort.Strings(ids)
		source := items[0].rule.Source
		code := "duplicate-rule"
		message := fmt.Sprintf("rules %s have identical match selectors", strings.Join(ids, ", "))
		if len(effects) > 1 {
			code = "conflicting-effects"
			message = fmt.Sprintf("rules %s have identical match selectors but different effects", strings.Join(ids, ", "))
		}
		issues = append(issues, Issue{
			Severity: SeverityWarning,
			Code:     code,
			Message:  message,
			RuleID:   ids[0],
			Source:   &source,
		})
	}
	return issues
}

func matchIsSubjectOnly(match *Match) bool {
	return match != nil && match.Subject != "" && len(match.Tool) == 0 && len(match.Capability) == 0 && len(match.DataClass) == 0 && match.Sink == "" && len(match.Args) == 0 && match.Context == nil && match.Provenance == nil
}

func wildcardLocation(match *Match) string {
	for _, value := range match.Tool {
		if value == "*" {
			return "match.tool"
		}
	}
	for _, value := range match.Capability {
		if value == "*" {
			return "match.capability"
		}
	}
	for _, value := range match.DataClass {
		if value == "*" {
			return "match.dataClass"
		}
	}
	return ""
}

func severityRank(severity Severity) int {
	if severity == SeverityError {
		return 0
	}
	return 1
}

func issueLine(issue Issue) int {
	if issue.Source == nil {
		return 0
	}
	return issue.Source.Line
}
