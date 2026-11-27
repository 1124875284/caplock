package manifest

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/caplock/caplock/internal/mcp"
)

func TestBuildNormalizesToolsDeterministically(t *testing.T) {
	readOnly := true
	tools := []mcp.Tool{
		{
			Name:        "write_file",
			Description: "Write a file",
			InputSchema: json.RawMessage(`{"required":["path"],"type":"object","properties":{"path":{"type":"string"}}}`),
		},
		{
			Name:        "read_file",
			Description: "Read a file",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"path":{"type":"string"}},"required":[]}`),
			Annotations: mcp.Annotations{ReadOnlyHint: &readOnly},
		},
	}
	first, err := Build(tools)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if got, want := first[0].Name, "read_file"; got != want {
		t.Fatalf("first tool = %q, want %q", got, want)
	}
	if got, want := first[0].Capabilities, []string{"read"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("capabilities = %#v, want %#v", got, want)
	}
	for range 10 {
		next, err := Build(tools)
		if err != nil {
			t.Fatalf("Build() error = %v", err)
		}
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("Build() is not deterministic:\n%#v\n%#v", first, next)
		}
	}

	reordered := append([]mcp.Tool(nil), tools...)
	reordered[0].InputSchema = json.RawMessage(`{"properties":{"path":{"type":"string"}},"required":["path"],"type":"object"}`)
	again, err := Build(reordered)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if first[1].InputSchemaHash != again[1].InputSchemaHash {
		t.Fatal("reordering schema keys changed the schema hash")
	}
}

func TestBuildHashesDescriptionWithoutRetainingIt(t *testing.T) {
	first, err := Build([]mcp.Tool{{Name: "read_file", Description: "Read a file", InputSchema: json.RawMessage(`{"type":"object"}`)}})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	second, err := Build([]mcp.Tool{{Name: "read_file", Description: "Read a file", InputSchema: json.RawMessage(`{"type":"object"}`)}})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	changed, err := Build([]mcp.Tool{{Name: "read_file", Description: "Read any file", InputSchema: json.RawMessage(`{"type":"object"}`)}})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if first[0].DescriptionHash != second[0].DescriptionHash {
		t.Fatal("identical descriptions produced different hashes")
	}
	if first[0].DescriptionHash == changed[0].DescriptionHash {
		t.Fatal("different descriptions produced the same hash")
	}
	data, _ := json.Marshal(first)
	if bytes.Contains(data, []byte("Read a file")) {
		t.Fatalf("manifest retained the raw description: %s", data)
	}
}

func TestBuildRejectsMalformedTools(t *testing.T) {
	tests := []struct {
		name  string
		tools []mcp.Tool
		want  string
	}{
		{name: "duplicate", tools: []mcp.Tool{{Name: "x", InputSchema: json.RawMessage(`{}`)}, {Name: "x", InputSchema: json.RawMessage(`{}`)}}, want: "duplicate"},
		{name: "schema array", tools: []mcp.Tool{{Name: "x", InputSchema: json.RawMessage(`[]`)}}, want: "JSON object"},
		{name: "schema invalid", tools: []mcp.Tool{{Name: "x", InputSchema: json.RawMessage(`{`)}}, want: "not valid JSON"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Build(test.tools)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Build() error = %v, want %q", err, test.want)
			}
		})
	}
}

func FuzzHashSchema(f *testing.F) {
	for _, seed := range []string{`{}`, `{"type":"object"}`, `[]`, `null`, `{`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(_ *testing.T, input []byte) {
		_, _ = hashSchema(input)
	})
}
