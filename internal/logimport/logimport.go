// Package logimport maps generic historical tool-call logs into Caplock trace
// records using an explicit, reviewable mapping. It never guesses missing
// security facts.
package logimport

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/caplock/caplock/internal/canonical"
	"github.com/caplock/caplock/internal/safefile"
	"github.com/caplock/caplock/internal/trace"
)

const (
	// Version is the mapping format version.
	Version = 1
	// MaxMappingBytes bounds the mapping document.
	MaxMappingBytes = 1 << 20
)

var requiredFields = []string{"time", "policy", "subject", "tool", "capabilities", "decision.effect"}

// Mapping is an explicit source-path mapping to the Caplock trace shape.
type Mapping struct {
	Version     int               `yaml:"version" json:"version"`
	InputFormat string            `yaml:"inputFormat" json:"inputFormat"`
	Fields      map[string]string `yaml:"fields" json:"fields"`
}

// LoadMapping reads a strict YAML or JSON mapping file.
func LoadMapping(path string) (*Mapping, error) {
	data, err := safefile.ReadFile(path, MaxMappingBytes)
	if err != nil {
		return nil, fmt.Errorf("read mapping %s: %w", path, err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var mapping Mapping
	if err := decoder.Decode(&mapping); err != nil {
		return nil, fmt.Errorf("parse mapping %s: %w", path, err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err == nil {
		return nil, errors.New("mapping contains multiple documents")
	} else if !errors.Is(err, io.EOF) {
		return nil, err
	}
	if err := ValidateMapping(&mapping); err != nil {
		return nil, err
	}
	return &mapping, nil
}

// ValidateMapping rejects incomplete mappings and unsupported input formats.
func ValidateMapping(mapping *Mapping) error {
	if mapping == nil {
		return errors.New("mapping is required")
	}
	if mapping.Version != Version {
		return fmt.Errorf("mapping version must be %d", Version)
	}
	switch strings.ToLower(strings.TrimSpace(mapping.InputFormat)) {
	case "jsonl", "csv":
	default:
		return fmt.Errorf("inputFormat must be jsonl or csv")
	}
	for _, field := range requiredFields {
		if strings.TrimSpace(mapping.Fields[field]) == "" {
			return fmt.Errorf("mapping.fields[%q] is required", field)
		}
	}
	return nil
}

// Convert parses a JSONL or CSV log and emits strict trace records in input
// order. Unknown source fields are ignored; missing required facts fail closed.
func Convert(reader io.Reader, mapping *Mapping) ([]trace.Record, error) {
	if err := ValidateMapping(mapping); err != nil {
		return nil, err
	}
	var rows []map[string]any
	var err error
	if strings.EqualFold(mapping.InputFormat, "csv") {
		rows, err = parseCSV(reader)
	} else {
		rows, err = parseJSONL(reader)
	}
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("input log contains no records")
	}
	if len(rows) > trace.MaxRecords {
		return nil, fmt.Errorf("input log exceeds %d records", trace.MaxRecords)
	}
	records := make([]trace.Record, 0, len(rows))
	for index, row := range rows {
		record, err := mapRecord(row, mapping)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", index+1, err)
		}
		records = append(records, record)
	}
	return records, nil
}

func parseJSONL(reader io.Reader) ([]map[string]any, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), trace.MaxBytes)
	rows := make([]map[string]any, 0)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var row map[string]any
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.UseNumber()
		if err := decoder.Decode(&row); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		if row == nil {
			return nil, fmt.Errorf("line %d: expected a JSON object", lineNumber)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

func parseCSV(reader io.Reader) ([]map[string]any, error) {
	csvReader := csv.NewReader(reader)
	csvReader.FieldsPerRecord = -1
	rows, err := csvReader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("CSV contains no header")
	}
	headers := rows[0]
	seen := make(map[string]bool)
	for _, header := range headers {
		if strings.TrimSpace(header) == "" {
			return nil, errors.New("CSV contains an empty header")
		}
		if seen[header] {
			return nil, fmt.Errorf("CSV contains duplicate header %q", header)
		}
		seen[header] = true
	}
	result := make([]map[string]any, 0, len(rows)-1)
	for index, row := range rows[1:] {
		if len(row) != len(headers) {
			return nil, fmt.Errorf("CSV row %d has %d columns, want %d", index+2, len(row), len(headers))
		}
		value := make(map[string]any, len(headers))
		for column, header := range headers {
			value[header] = row[column]
		}
		result = append(result, value)
	}
	return result, nil
}

func mapRecord(row map[string]any, mapping *Mapping) (trace.Record, error) {
	lookupString := func(field string) (string, error) {
		value, ok := lookup(row, mapping.Fields[field])
		if !ok {
			return "", fmt.Errorf("required field %s is missing at %q", field, mapping.Fields[field])
		}
		text := strings.TrimSpace(fmt.Sprint(value))
		if text == "" {
			return "", fmt.Errorf("required field %s is empty", field)
		}
		return text, nil
	}
	atText, err := lookupString("time")
	if err != nil {
		return trace.Record{}, err
	}
	at, err := parseTime(atText)
	if err != nil {
		return trace.Record{}, fmt.Errorf("time: %w", err)
	}
	policy, err := lookupString("policy")
	if err != nil {
		return trace.Record{}, err
	}
	subject, err := lookupString("subject")
	if err != nil {
		return trace.Record{}, err
	}
	tool, err := lookupString("tool")
	if err != nil {
		return trace.Record{}, err
	}
	effect, err := lookupString("decision.effect")
	if err != nil {
		return trace.Record{}, err
	}
	capabilities, err := lookupStringList(row, mapping, "capabilities", true)
	if err != nil {
		return trace.Record{}, err
	}
	record := trace.Record{
		Version:      trace.Version,
		Time:         at.UTC(),
		Policy:       policy,
		Subject:      subject,
		Tool:         tool,
		Capabilities: capabilities,
		Decision: trace.Decision{
			Effect:      effect,
			Obligations: []string{},
		},
	}
	if value, ok := lookupOptionalString(row, mapping, "sink"); ok {
		record.Sink = value
	}
	if value, ok := lookupOptionalString(row, mapping, "environment"); ok {
		record.Environment = value
	}
	if value, ok := lookupOptionalString(row, mapping, "capabilitySource"); ok {
		record.CapabilitySource = value
	}
	if values, err := lookupStringList(row, mapping, "servers", false); err != nil {
		return trace.Record{}, err
	} else {
		record.Servers = values
	}
	if values, err := lookupStringList(row, mapping, "dataClass", false); err != nil {
		return trace.Record{}, err
	} else {
		record.DataClass = values
	}
	if values, err := lookupStringList(row, mapping, "provenance", false); err != nil {
		return trace.Record{}, err
	} else {
		record.Provenance = values
	}
	if values, err := lookupStringList(row, mapping, "decision.obligations", false); err != nil {
		return trace.Record{}, err
	} else {
		record.Decision.Obligations = values
	}
	if value, ok := lookupOptionalString(row, mapping, "decision.ruleId"); ok {
		record.Decision.RuleID = value
	}
	if value, ok := lookupOptionalString(row, mapping, "decision.reason"); ok {
		record.Decision.Reason = value
	}
	if value, ok := lookupOptionalString(row, mapping, "decision.approvalMode"); ok {
		record.Decision.ApprovalMode = value
	}
	if value, ok, err := lookupOptionalBool(row, mapping, "decision.default"); err != nil {
		return trace.Record{}, err
	} else if ok {
		record.Decision.Default = value
	}
	if value, ok, err := lookupOptionalBool(row, mapping, "decision.forwarded"); err != nil {
		return trace.Record{}, err
	} else if ok {
		record.Decision.Forwarded = value
	}
	args, hasArgs, err := lookupArgs(row, mapping)
	if err != nil {
		return trace.Record{}, err
	}
	captured := hasArgs
	if value, ok, err := lookupOptionalBool(row, mapping, "argumentsCaptured"); err != nil {
		return trace.Record{}, err
	} else if ok {
		captured = value
	}
	if !captured && hasArgs {
		return trace.Record{}, errors.New("args are present but argumentsCaptured is false")
	}
	if captured {
		record.ArgumentsCaptured = true
		record.Args = args
	}
	if value, ok := lookupOptionalString(row, mapping, "argsHash"); ok {
		record.ArgsHash = value
	} else if captured {
		record.ArgsHash, err = canonical.HashArguments(args)
		if err != nil {
			return trace.Record{}, err
		}
	}
	if captured && record.ArgsHash != "" {
		if err := canonical.VerifyArguments(record.ArgsHash, args); err != nil {
			return trace.Record{}, err
		}
	}
	record = trace.Normalize(record)
	if err := trace.Validate(record); err != nil {
		return trace.Record{}, err
	}
	return record, nil
}

func lookup(row map[string]any, path string) (any, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false
	}
	if value, ok := row[path]; ok {
		return value, true
	}
	var current any = row
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func lookupOptionalString(row map[string]any, mapping *Mapping, field string) (string, bool) {
	path := strings.TrimSpace(mapping.Fields[field])
	if path == "" {
		return "", false
	}
	value, ok := lookup(row, path)
	if !ok || value == nil {
		return "", false
	}
	return strings.TrimSpace(fmt.Sprint(value)), true
}

func lookupOptionalBool(row map[string]any, mapping *Mapping, field string) (bool, bool, error) {
	path := strings.TrimSpace(mapping.Fields[field])
	if path == "" {
		return false, false, nil
	}
	value, ok := lookup(row, path)
	if !ok || value == nil {
		return false, false, nil
	}
	switch typed := value.(type) {
	case bool:
		return typed, true, nil
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		if err != nil {
			return false, false, fmt.Errorf("%s must be a boolean", field)
		}
		return parsed, true, nil
	default:
		return false, false, fmt.Errorf("%s must be a boolean", field)
	}
}

func lookupStringList(row map[string]any, mapping *Mapping, field string, required bool) ([]string, error) {
	path := strings.TrimSpace(mapping.Fields[field])
	if path == "" {
		if required {
			return nil, fmt.Errorf("mapping.fields[%q] is required", field)
		}
		return []string{}, nil
	}
	value, ok := lookup(row, path)
	if !ok || value == nil {
		if required {
			return nil, fmt.Errorf("required field %s is missing at %q", field, path)
		}
		return []string{}, nil
	}
	values, err := toStringList(value)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	if required && len(values) == 0 {
		return nil, fmt.Errorf("required field %s is empty", field)
	}
	sort.Strings(values)
	return values, nil
}

func toStringList(value any) ([]string, error) {
	switch typed := value.(type) {
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text == "" {
				return nil, errors.New("list contains an empty value")
			}
			result = append(result, text)
		}
		return result, nil
	case []string:
		return append([]string(nil), typed...), nil
	case string:
		text := strings.TrimSpace(typed)
		if text == "" {
			return []string{}, nil
		}
		if strings.HasPrefix(text, "[") {
			var values []string
			if err := json.Unmarshal([]byte(text), &values); err != nil {
				return nil, errors.New("string list is not valid JSON")
			}
			return values, nil
		}
		separator := "|"
		if !strings.Contains(text, "|") {
			separator = ","
		}
		parts := strings.Split(text, separator)
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				result = append(result, part)
			}
		}
		return result, nil
	default:
		return []string{fmt.Sprint(value)}, nil
	}
}

func lookupArgs(row map[string]any, mapping *Mapping) (map[string]any, bool, error) {
	path := strings.TrimSpace(mapping.Fields["args"])
	if path == "" {
		return nil, false, nil
	}
	value, ok := lookup(row, path)
	if !ok || value == nil {
		return nil, false, nil
	}
	switch typed := value.(type) {
	case map[string]any:
		return typed, true, nil
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil, false, nil
		}
		var arguments map[string]any
		decoder := json.NewDecoder(strings.NewReader(typed))
		decoder.UseNumber()
		if err := decoder.Decode(&arguments); err != nil {
			return nil, false, errors.New("args must be a JSON object")
		}
		return arguments, true, nil
	default:
		return nil, false, errors.New("args must be a JSON object")
	}
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err == nil {
		return parsed, nil
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not RFC3339 or Unix seconds", value)
	}
	return time.Unix(seconds, 0).UTC(), nil
}
