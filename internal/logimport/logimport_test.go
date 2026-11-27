package logimport

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/caplock/caplock/internal/canonical"
)

func TestConvertJSONLWithExplicitMapping(t *testing.T) {
	mapping := &Mapping{
		Version:     Version,
		InputFormat: "jsonl",
		Fields: map[string]string{
			"time":                 "timestamp",
			"policy":               "metadata.policy",
			"subject":              "actor.id",
			"tool":                 "tool.name",
			"capabilities":         "tool.capabilities",
			"sink":                 "tool.sink",
			"args":                 "request.arguments",
			"decision.effect":      "decision.effect",
			"decision.ruleId":      "decision.rule",
			"decision.obligations": "decision.obligations",
		},
	}
	input := `{"timestamp":"2026-11-26T08:00:00Z","metadata":{"policy":"prod"},"actor":{"id":"agent"},"tool":{"name":"send_email","capabilities":["comms","network"],"sink":"email.send"},"request":{"arguments":{"to":"secret@example.com"}},"decision":{"effect":"require_approval","rule":"approve-email","obligations":["audit"]}}` + "\n"
	records, err := Convert(strings.NewReader(input), mapping)
	if err != nil {
		t.Fatalf("Convert() error = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d", len(records))
	}
	record := records[0]
	if record.Tool != "send_email" || record.Sink != "email.send" || !record.ArgumentsCaptured || record.Args["to"] != "secret@example.com" {
		t.Fatalf("record = %#v", record)
	}
	if record.ArgsHash == "" || len(record.Decision.Obligations) != 1 || record.Decision.Obligations[0] != "audit" {
		t.Fatalf("record = %#v", record)
	}
	if err := canonical.VerifyArguments(record.ArgsHash, record.Args); err != nil {
		t.Fatalf("computed hash does not verify: %v", err)
	}
}

func TestConvertCSVAndRejectBadHash(t *testing.T) {
	mapping := &Mapping{
		Version:     Version,
		InputFormat: "csv",
		Fields: map[string]string{
			"time":            "ts",
			"policy":          "policy",
			"subject":         "subject",
			"tool":            "tool",
			"capabilities":    "capabilities",
			"decision.effect": "effect",
		},
	}
	input := "ts,policy,subject,tool,capabilities,effect\n1764144000,prod,agent,read_file,read|filesystem,allow\n"
	records, err := Convert(strings.NewReader(input), mapping)
	if err != nil {
		t.Fatalf("Convert(csv) error = %v", err)
	}
	if len(records) != 1 || records[0].Capabilities[0] != "filesystem" || records[0].Time.Unix() != 1764144000 {
		t.Fatalf("records = %#v", records)
	}

	mapping.InputFormat = "jsonl"
	mapping.Fields["args"] = "args"
	mapping.Fields["argsHash"] = "hash"
	input = `{"ts":"2026-11-26T08:00:00Z","policy":"prod","subject":"agent","tool":"read_file","capabilities":["read"],"effect":"allow","args":{"path":"/tmp/a"},"hash":"sha256:` + strings.Repeat("0", 64) + `"}` + "\n"
	if _, err := Convert(strings.NewReader(input), mapping); err == nil || !strings.Contains(err.Error(), "argsHash does not match") {
		t.Fatalf("Convert() error = %v", err)
	}
}

func TestConvertRejectsMissingRequiredFact(t *testing.T) {
	mapping := &Mapping{Version: Version, InputFormat: "jsonl", Fields: map[string]string{
		"time": "time", "policy": "policy", "subject": "subject", "tool": "tool", "capabilities": "caps", "decision.effect": "effect",
	}}
	_, err := Convert(strings.NewReader(`{"time":"2026-11-26T08:00:00Z","policy":"p","subject":"s","tool":"t","caps":["read"]}`), mapping)
	if err == nil || !strings.Contains(err.Error(), "decision.effect") {
		t.Fatalf("Convert() error = %v", err)
	}
}

func TestPublishedMappingSchemaAcceptsMapping(t *testing.T) {
	mapping := Mapping{
		Version:     Version,
		InputFormat: "jsonl",
		Fields: map[string]string{
			"time":            "timestamp",
			"policy":          "policy",
			"subject":         "actor",
			"tool":            "tool",
			"capabilities":    "capabilities",
			"decision.effect": "effect",
			"sink":            "sink",
			"args":            "arguments",
		},
	}
	data, err := json.Marshal(mapping)
	if err != nil {
		t.Fatalf("marshal mapping: %v", err)
	}
	path := filepath.Join("..", "..", "schemas", "import-mapping.schema.json")
	schemaData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	url := "https://caplock.dev/schemas/import-mapping.schema.json"
	if err := compiler.AddResource(url, bytes.NewReader(schemaData)); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	schema, err := compiler.Compile(url)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("decode mapping: %v", err)
	}
	if err := schema.Validate(decoded); err != nil {
		t.Fatalf("schema validation failed: %v\n%s", err, data)
	}
}
