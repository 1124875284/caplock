package proxy

import (
	"github.com/caplock/caplock/internal/canonical"
	"github.com/caplock/caplock/internal/trace"
)

// TraceFunc receives one replayable call record. It must be safe for concurrent
// use. Trace write failures are treated as fail-closed by the proxy.
type TraceFunc func(trace.Record) error

// TraceRecord projects an evaluated decision into the trace format.
func (e *Engine) TraceRecord(decision Decision, arguments map[string]any, captureArguments bool) trace.Record {
	at := decision.EvaluatedAt
	if at.IsZero() {
		at = e.now()
	}
	record := trace.Record{
		Version:          trace.Version,
		Time:             at.UTC(),
		Policy:           e.policy.Policy,
		Subject:          e.subject,
		Tool:             decision.Tool,
		Capabilities:     decision.Capabilities,
		CapabilitySource: decision.CapabilitySource,
		Servers:          decision.Servers,
		Sink:             decision.Sink,
		Environment:      e.environment,
		ArgsHash:         decision.ArgsHash,
		RedactedFields:   append([]string(nil), decision.RedactedFields...),
		Decision: trace.Decision{
			Effect:       decision.Policy.Effect,
			RuleID:       decision.Policy.RuleID,
			Default:      decision.Policy.Default,
			Obligations:  decision.Policy.Obligations,
			Forwarded:    decision.Forward,
			Reason:       decision.Reason,
			ApprovalMode: string(decision.ApprovalMode),
		},
	}
	if captureArguments {
		record.ArgumentsCaptured = true
		if arguments == nil {
			arguments = map[string]any{}
		}
		record.Args = arguments
		keys := append([]string(nil), e.traceRedact...)
		if contains(decision.Policy.Obligations, "redact") {
			keys = append(keys, e.redaction...)
		}
		if len(keys) > 0 {
			record.Args, record.RedactedFields = canonical.RedactArguments(arguments, keys)
		}
	}
	return trace.Normalize(record)
}

func writeTrace(callback TraceFunc, engine *Engine, decision Decision, arguments map[string]any, capture bool) error {
	if callback == nil {
		return nil
	}
	return callback(engine.TraceRecord(decision, arguments, capture))
}
