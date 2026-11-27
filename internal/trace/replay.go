package trace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/caplock/caplock/internal/canonical"
	"github.com/caplock/caplock/internal/policy"
)

// ReplayVersion is the trace replay result version.
const ReplayVersion = 1

// Decision changes reported by replay.
const (
	DirectionWeakened     = "weakened"
	DirectionStrengthened = "strengthened"
	DirectionChanged      = "changed"
)

// ReplayOptions supplies report metadata.
type ReplayOptions struct {
	Source                   string
	SkipArgsHashVerification bool
}

// DecisionSummary is the comparable portion of a policy decision.
type DecisionSummary struct {
	Effect      string   `json:"effect"`
	RuleID      string   `json:"ruleId,omitempty"`
	Default     bool     `json:"default"`
	Obligations []string `json:"obligations"`
}

// Change is one trace record whose policy decision differs.
type Change struct {
	Time              string          `json:"time"`
	Subject           string          `json:"subject"`
	Tool              string          `json:"tool"`
	ArgumentsCaptured bool            `json:"argumentsCaptured"`
	RedactedFields    []string        `json:"redactedFields,omitempty"`
	Direction         string          `json:"direction"`
	Before            DecisionSummary `json:"before"`
	After             DecisionSummary `json:"after"`
}

// Result summarizes replay of a complete trace.
type Result struct {
	Version      int      `json:"version"`
	Policy       string   `json:"policy"`
	Source       string   `json:"source,omitempty"`
	Total        int      `json:"total"`
	Unchanged    int      `json:"unchanged"`
	Changed      int      `json:"changed"`
	Weakened     int      `json:"weakened"`
	Strengthened int      `json:"strengthened"`
	ArgsMissing  int      `json:"argsMissing"`
	ArgsRedacted int      `json:"argsRedacted"`
	Changes      []Change `json:"changes"`
}

// Replay evaluates every recorded request against the current Policy IR.
func Replay(ir *policy.IR, records []Record, options ReplayOptions) (Result, error) {
	if ir == nil {
		return Result{}, fmt.Errorf("policy is required")
	}
	if len(records) == 0 {
		return Result{}, fmt.Errorf("trace contains no records")
	}
	result := Result{
		Version: ReplayVersion,
		Policy:  ir.Policy,
		Source:  options.Source,
		Total:   len(records),
		Changes: make([]Change, 0),
	}
	for _, record := range records {
		record = Normalize(record)
		if err := Validate(record); err != nil {
			return Result{}, err
		}
		if !record.ArgumentsCaptured {
			result.ArgsMissing++
		}
		var arguments map[string]any
		if record.ArgumentsCaptured && len(record.RedactedFields) == 0 && record.ArgsHash != "" && !options.SkipArgsHashVerification {
			if err := canonical.VerifyArguments(record.ArgsHash, record.Args); err != nil {
				return Result{}, fmt.Errorf("replay %s at %s: %w", record.Tool, record.Time.Format(time.RFC3339), err)
			}
		}
		if record.ArgumentsCaptured && len(record.RedactedFields) == 0 {
			arguments = record.Args
		} else if record.ArgumentsCaptured && len(record.RedactedFields) > 0 {
			result.ArgsMissing++
			result.ArgsRedacted++
		}
		decision, err := policy.Evaluate(ir, policy.Request{
			Subject:      record.Subject,
			Tool:         record.Tool,
			Capabilities: record.Capabilities,
			DataClass:    record.DataClass,
			Sink:         record.Sink,
			Args:         arguments,
			Provenance:   record.Provenance,
			Context: policy.RequestContext{
				Time:        record.Time,
				Environment: record.Environment,
			},
		})
		if err != nil {
			return Result{}, fmt.Errorf("replay %s at %s: %w", record.Tool, record.Time.Format(time.RFC3339), err)
		}
		before := summaryFromDecision(record.Decision.Effect, record.Decision.RuleID, record.Decision.Default, record.Decision.Obligations)
		after := summaryFromDecision(decision.Effect, decision.RuleID, decision.Default, decision.Obligations)
		if equalSummary(before, after) {
			result.Unchanged++
			continue
		}
		direction := changeDirection(before.Effect, after.Effect)
		result.Changed++
		switch direction {
		case DirectionWeakened:
			result.Weakened++
		case DirectionStrengthened:
			result.Strengthened++
		}
		result.Changes = append(result.Changes, Change{
			Time:              record.Time.UTC().Format(time.RFC3339Nano),
			Subject:           record.Subject,
			Tool:              record.Tool,
			ArgumentsCaptured: record.ArgumentsCaptured,
			RedactedFields:    append([]string(nil), record.RedactedFields...),
			Direction:         direction,
			Before:            before,
			After:             after,
		})
	}
	return result, nil
}

// Render emits text or JSON.
func Render(result Result, format string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "text", "txt":
		return renderText(result), nil
	case "json":
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, err
		}
		return append(data, '\n'), nil
	default:
		return nil, fmt.Errorf("unsupported replay format %q; use text or json", format)
	}
}

func renderText(result Result) []byte {
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "Caplock trace replay\n")
	if result.Source != "" {
		fmt.Fprintf(&buffer, "Source: %s\n", textCell(result.Source))
	}
	fmt.Fprintf(&buffer, "Policy: %s\n", textCell(result.Policy))
	fmt.Fprintf(&buffer, "Records: total=%d unchanged=%d changed=%d weakened=%d strengthened=%d args_missing=%d args_redacted=%d\n",
		result.Total, result.Unchanged, result.Changed, result.Weakened, result.Strengthened, result.ArgsMissing, result.ArgsRedacted)
	if len(result.Changes) == 0 {
		fmt.Fprintf(&buffer, "\nNo policy decision changes.\n")
		return buffer.Bytes()
	}
	fmt.Fprintf(&buffer, "\nChanges:\n")
	for _, change := range result.Changes {
		fmt.Fprintf(&buffer, "  [%s] %s %s subject=%s args_captured=%t\n",
			strings.ToUpper(change.Direction), textCell(change.Time), textCell(change.Tool), textCell(change.Subject), change.ArgumentsCaptured)
		fmt.Fprintf(&buffer, "    before: %s\n", summaryText(change.Before))
		fmt.Fprintf(&buffer, "    after:  %s\n", summaryText(change.After))
	}
	return buffer.Bytes()
}

func summaryFromDecision(effect, ruleID string, isDefault bool, obligations []string) DecisionSummary {
	return DecisionSummary{
		Effect:      effect,
		RuleID:      ruleID,
		Default:     isDefault,
		Obligations: sortedUnique(obligations),
	}
}

func summaryText(summary DecisionSummary) string {
	rule := summary.RuleID
	if rule == "" {
		rule = "(default)"
	}
	obligations := "[]"
	if len(summary.Obligations) > 0 {
		obligations = "[" + strings.Join(summary.Obligations, ",") + "]"
	}
	return fmt.Sprintf("%s rule=%s default=%t obligations=%s", summary.Effect, textCell(rule), summary.Default, obligations)
}

func equalSummary(left, right DecisionSummary) bool {
	return left.Effect == right.Effect &&
		left.RuleID == right.RuleID &&
		left.Default == right.Default &&
		equalStrings(left.Obligations, right.Obligations)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func changeDirection(before, after string) string {
	beforeRank := effectRank(before)
	afterRank := effectRank(after)
	switch {
	case afterRank < beforeRank:
		return DirectionWeakened
	case afterRank > beforeRank:
		return DirectionStrengthened
	default:
		return DirectionChanged
	}
}

func effectRank(effect string) int {
	switch effect {
	case policy.EffectDeny:
		return 3
	case policy.EffectRequireApproval:
		return 2
	case policy.EffectAllow:
		return 1
	default:
		return 0
	}
}

func textCell(value string) string {
	for _, character := range value {
		if unicode.IsControl(character) {
			return strconv.QuoteToGraphic(value)
		}
	}
	return value
}
