// Package trace captures privacy-preserving MCP tool-call decisions and replays
// them against policy revisions.
package trace

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/1124875284/caplock/internal/policy"
	"github.com/1124875284/caplock/internal/safefile"
)

const (
	// Version is the supported trace record version.
	Version = 1
	// MaxBytes bounds a trace file read by Caplock.
	MaxBytes = 16 << 20
	// MaxRecords bounds replay work and report size.
	MaxRecords = 10_000
)

// Decision is the observed policy outcome for one call.
type Decision struct {
	Effect       string   `json:"effect"`
	RuleID       string   `json:"ruleId,omitempty"`
	Default      bool     `json:"default"`
	Obligations  []string `json:"obligations"`
	Forwarded    bool     `json:"forwarded"`
	Reason       string   `json:"reason,omitempty"`
	ApprovalMode string   `json:"approvalMode,omitempty"`
}

// Record is one replayable tool-call observation. Arguments are included only
// when the caller explicitly enables full argument capture.
type Record struct {
	Version           int            `json:"version"`
	Time              time.Time      `json:"time"`
	Policy            string         `json:"policy"`
	Subject           string         `json:"subject"`
	Tool              string         `json:"tool"`
	Capabilities      []string       `json:"capabilities"`
	CapabilitySource  string         `json:"capabilitySource,omitempty"`
	Servers           []string       `json:"servers,omitempty"`
	Sink              string         `json:"sink,omitempty"`
	Environment       string         `json:"environment,omitempty"`
	DataClass         []string       `json:"dataClass,omitempty"`
	Provenance        []string       `json:"provenance,omitempty"`
	ArgumentsCaptured bool           `json:"argumentsCaptured"`
	Args              map[string]any `json:"args,omitempty"`
	ArgsHash          string         `json:"argsHash,omitempty"`
	RedactedFields    []string       `json:"redactedFields,omitempty"`
	Decision          Decision       `json:"decision"`
}

// JSONLWriter writes concurrency-safe newline-delimited JSON trace records.
type JSONLWriter struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

// NewJSONLWriter creates a trace sink.
func NewJSONLWriter(writer io.Writer) *JSONLWriter {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return &JSONLWriter{encoder: encoder}
}

// Write appends one normalized record.
func (w *JSONLWriter) Write(record Record) error {
	record = Normalize(record)
	if err := Validate(record); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.encoder.Encode(record)
}

// ReadFile reads and validates a JSONL trace.
func ReadFile(path string) ([]Record, error) {
	data, err := safefile.ReadFile(path, MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("read trace %s: %w", path, err)
	}
	records, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse trace %s: %w", path, err)
	}
	return records, nil
}

// Parse reads strict JSONL records. Blank lines are ignored.
func Parse(data []byte) ([]Record, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), MaxBytes)
	records := make([]Record, 0)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var record Record
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("line %d: multiple JSON values", lineNumber)
		}
		record = Normalize(record)
		if err := Validate(record); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		records = append(records, record)
		if len(records) > MaxRecords {
			return nil, fmt.Errorf("trace exceeds %d records", MaxRecords)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("trace contains no records")
	}
	return records, nil
}

// Normalize sorts and fills non-semantic fields without changing decisions.
func Normalize(record Record) Record {
	record.Capabilities = sortedUnique(record.Capabilities)
	record.Servers = sortedUnique(record.Servers)
	record.DataClass = sortedUnique(record.DataClass)
	record.Provenance = sortedUnique(record.Provenance)
	record.Decision.Obligations = sortedUnique(record.Decision.Obligations)
	record.RedactedFields = sortedUnique(record.RedactedFields)
	return record
}

// Validate rejects incomplete or ambiguous trace records.
func Validate(record Record) error {
	if record.Version != Version {
		return fmt.Errorf("unsupported trace version %d", record.Version)
	}
	if record.Time.IsZero() {
		return errors.New("time is required")
	}
	if strings.TrimSpace(record.Policy) == "" {
		return errors.New("policy is required")
	}
	if strings.TrimSpace(record.Subject) == "" {
		return errors.New("subject is required")
	}
	if strings.TrimSpace(record.Tool) == "" {
		return errors.New("tool is required")
	}
	if !validEffect(record.Decision.Effect) {
		return fmt.Errorf("invalid decision effect %q", record.Decision.Effect)
	}
	if !record.ArgumentsCaptured && len(record.Args) > 0 {
		return errors.New("args must be empty unless argumentsCaptured is true")
	}
	if record.ArgsHash != "" && !validDigest(record.ArgsHash) {
		return errors.New("argsHash must be sha256:<64 lowercase hex characters>")
	}
	if len(record.RedactedFields) > 0 {
		if !record.ArgumentsCaptured {
			return errors.New("redactedFields require argumentsCaptured")
		}
		if record.ArgsHash == "" {
			return errors.New("redacted arguments require the original argsHash")
		}
		for _, field := range record.RedactedFields {
			if strings.TrimSpace(field) == "" {
				return errors.New("redactedFields values must not be empty")
			}
		}
	}
	return nil
}

func validEffect(effect string) bool {
	switch effect {
	case policy.EffectAllow, policy.EffectDeny, policy.EffectRequireApproval:
		return true
	default:
		return false
	}
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	decoded, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil && len(decoded) == sha256Size && value == strings.ToLower(value)
}

const sha256Size = 32

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	result := append([]string(nil), values...)
	sort.Strings(result)
	write := 1
	for read := 1; read < len(result); read++ {
		if result[read] != result[write-1] {
			result[write] = result[read]
			write++
		}
	}
	return result[:write]
}
