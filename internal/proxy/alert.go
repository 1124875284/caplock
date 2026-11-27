package proxy

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// AlertRecord is emitted when a matched rule carries the alert obligation. It
// contains no raw arguments or tool output.
type AlertRecord struct {
	Version      int          `json:"version"`
	Time         string       `json:"time"`
	Policy       string       `json:"policy"`
	Subject      string       `json:"subject"`
	Tool         string       `json:"tool"`
	Effect       string       `json:"effect"`
	RuleID       string       `json:"ruleId,omitempty"`
	Default      bool         `json:"default"`
	Obligations  []string     `json:"obligations"`
	Capabilities []string     `json:"capabilities"`
	Sink         string       `json:"sink,omitempty"`
	ArgsHash     string       `json:"argsHash"`
	Reason       string       `json:"reason,omitempty"`
	ApprovalMode ApprovalMode `json:"approvalMode"`
}

// AlertFunc receives one alert record and must be safe for concurrent use.
type AlertFunc func(AlertRecord) error

// Alert converts an engine decision to a privacy-preserving alert.
func (e *Engine) Alert(decision Decision) AlertRecord {
	at := decision.EvaluatedAt
	if at.IsZero() {
		at = e.now().UTC()
	}
	return AlertRecord{
		Version:      Version,
		Time:         at.UTC().Format(time.RFC3339Nano),
		Policy:       e.policy.Policy,
		Subject:      e.subject,
		Tool:         decision.Tool,
		Effect:       decision.Policy.Effect,
		RuleID:       decision.Policy.RuleID,
		Default:      decision.Policy.Default,
		Obligations:  nonNil(decision.Policy.Obligations),
		Capabilities: nonNil(decision.Capabilities),
		Sink:         decision.Sink,
		ArgsHash:     decision.ArgsHash,
		Reason:       decision.Reason,
		ApprovalMode: decision.ApprovalMode,
	}
}

// JSONLAlerts writes newline-delimited JSON with a mutex.
type JSONLAlerts struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

// NewJSONLAlerts creates a concurrency-safe alert sink.
func NewJSONLAlerts(writer io.Writer) *JSONLAlerts {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return &JSONLAlerts{encoder: encoder}
}

// Write appends one alert.
func (a *JSONLAlerts) Write(record AlertRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.encoder.Encode(record)
}
