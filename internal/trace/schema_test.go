package trace

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func compilePublishedSchema(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join("..", "..", "schemas", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	url := "https://caplock.dev/schemas/" + name
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat = true
	if err := compiler.AddResource(url, bytes.NewReader(data)); err != nil {
		t.Fatalf("add schema %s: %v", name, err)
	}
	schema, err := compiler.Compile(url)
	if err != nil {
		t.Fatalf("compile schema %s: %v", name, err)
	}
	return schema
}

func validateJSON(t *testing.T, schema *jsonschema.Schema, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode value: %v", err)
	}
	if err := schema.Validate(decoded); err != nil {
		t.Fatalf("schema validation failed: %v\n%s", err, data)
	}
}

func TestPublishedTraceSchemaAcceptsWriterOutput(t *testing.T) {
	schema := compilePublishedSchema(t, "trace.schema.json")
	validateJSON(t, schema, Normalize(testRecord()))
	validateJSON(t, schema, Normalize(Record{
		Version:           Version,
		Time:              testTime,
		Policy:            "trace-test",
		Subject:           "agent",
		Tool:              "read_file",
		Capabilities:      []string{"read"},
		ArgumentsCaptured: true,
		Args:              map[string]any{},
		Decision: Decision{
			Effect:      "allow",
			Obligations: []string{},
			Forwarded:   true,
		},
	}))
}

func TestPublishedTraceSchemaRejectsUnknownFields(t *testing.T) {
	schema := compilePublishedSchema(t, "trace.schema.json")
	value := map[string]any{
		"version":           1,
		"time":              testTime.Format(time.RFC3339Nano),
		"policy":            "trace-test",
		"subject":           "agent",
		"tool":              "read_file",
		"capabilities":      []string{"read"},
		"argumentsCaptured": false,
		"unexpected":        true,
		"decision": map[string]any{
			"effect":      "allow",
			"default":     false,
			"obligations": []string{},
			"forwarded":   true,
		},
	}
	if err := schema.Validate(value); err == nil {
		t.Fatal("schema accepted an unknown field")
	}
}

func TestPublishedReplaySchemaAcceptsRenderOutput(t *testing.T) {
	schema := compilePublishedSchema(t, "replay.schema.json")
	result := Result{
		Version:      ReplayVersion,
		Policy:       "after",
		Source:       "calls.jsonl",
		Total:        2,
		Unchanged:    1,
		Changed:      1,
		Weakened:     1,
		Strengthened: 0,
		ArgsMissing:  1,
		Changes: []Change{{
			Time:              testTime.Format(time.RFC3339Nano),
			Subject:           "finance-analyst",
			Tool:              "send_email",
			ArgumentsCaptured: false,
			Direction:         DirectionWeakened,
			Before: DecisionSummary{
				Effect:      "deny",
				Default:     true,
				Obligations: []string{},
			},
			After: DecisionSummary{
				Effect:      "allow",
				RuleID:      "allow-comms",
				Obligations: []string{"audit"},
			},
		}},
	}
	validateJSON(t, schema, result)

	data, err := Render(result, "json")
	if err != nil {
		t.Fatalf("Render(json) error = %v", err)
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode rendered replay: %v", err)
	}
	if err := schema.Validate(decoded); err != nil {
		t.Fatalf("rendered replay violates schema: %v\n%s", err, data)
	}
}
