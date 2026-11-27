package proxy

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// AuditRecord is the privacy-preserving record written for every tool-call
// decision. Raw arguments, headers, and tool results are never included.
type AuditRecord struct {
	Version               int          `json:"version"`
	Time                  string       `json:"time"`
	Policy                string       `json:"policy"`
	Subject               string       `json:"subject"`
	Tool                  string       `json:"tool"`
	Effect                string       `json:"effect"`
	RuleID                string       `json:"ruleId,omitempty"`
	Default               bool         `json:"default"`
	Obligations           []string     `json:"obligations"`
	UnenforcedObligations []string     `json:"unenforcedObligations,omitempty"`
	Capabilities          []string     `json:"capabilities"`
	CapabilitySource      string       `json:"capabilitySource"`
	Servers               []string     `json:"servers,omitempty"`
	Sink                  string       `json:"sink,omitempty"`
	ArgsHash              string       `json:"argsHash"`
	RedactedFields        []string     `json:"redactedFields,omitempty"`
	RuntimeBlocked        bool         `json:"runtimeBlocked,omitempty"`
	Forwarded             bool         `json:"forwarded"`
	Reason                string       `json:"reason,omitempty"`
	ApprovalMode          ApprovalMode `json:"approvalMode"`
}

// AuditFunc receives one audit record. It must be safe for concurrent use.
type AuditFunc func(AuditRecord) error

// Record converts an engine decision into an audit record.
func (e *Engine) Record(decision Decision) AuditRecord {
	at := decision.EvaluatedAt
	if at.IsZero() {
		at = e.now().UTC()
	}
	return AuditRecord{
		Version:               Version,
		Time:                  at.UTC().Format(time.RFC3339Nano),
		Policy:                e.policy.Policy,
		Subject:               e.subject,
		Tool:                  decision.Tool,
		Effect:                decision.Policy.Effect,
		RuleID:                decision.Policy.RuleID,
		Default:               decision.Policy.Default,
		Obligations:           nonNil(decision.Policy.Obligations),
		UnenforcedObligations: nonNil(decision.UnenforcedObligations),
		Capabilities:          nonNil(decision.Capabilities),
		CapabilitySource:      decision.CapabilitySource,
		Servers:               nonNil(decision.Servers),
		Sink:                  decision.Sink,
		ArgsHash:              decision.ArgsHash,
		RedactedFields:        nonNil(decision.RedactedFields),
		RuntimeBlocked:        decision.RuntimeBlocked,
		Forwarded:             decision.Forward,
		Reason:                decision.Reason,
		ApprovalMode:          decision.ApprovalMode,
	}
}

// JSONLAudit writes newline-delimited JSON with a mutex.
type JSONLAudit struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

// NewJSONLAudit creates a concurrency-safe JSONL audit sink.
func NewJSONLAudit(writer io.Writer) *JSONLAudit {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return &JSONLAudit{encoder: encoder}
}

// Write appends one record.
func (a *JSONLAudit) Write(record AuditRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.encoder.Encode(record)
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
