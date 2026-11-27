package lockfile

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/1124875284/caplock/internal/config"
)

func TestBuildIsDeterministicAndRedactsSecrets(t *testing.T) {
	project := testProject(t)
	first, err := Marshal(Build(project))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for range 10 {
		next, err := Marshal(Build(project))
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		if !bytes.Equal(first, next) {
			t.Fatalf("lockfile output is not deterministic:\n%s\n%s", first, next)
		}
	}
	if bytes.Contains(first, []byte("example-token")) {
		t.Fatalf("lockfile leaked an env value:\n%s", first)
	}
	if !bytes.Contains(first, []byte("GITHUB_TOKEN")) {
		t.Fatalf("lockfile omitted env key name:\n%s", first)
	}
	if bytes.Contains(first, []byte(`"headerKeys": null`)) {
		t.Fatalf("lockfile used null for a required array:\n%s", first)
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "caplock.lock")
	built := Build(testProject(t))
	if err := Write(path, built); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	loaded, err := Read(path)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if !reflect.DeepEqual(loaded, built) {
		t.Fatalf("round trip mismatch:\nloaded: %#v\nbuilt:  %#v", loaded, built)
	}
}

func TestParseRejectsInvalidLockfiles(t *testing.T) {
	valid := string(mustMarshal(t, Build(testProject(t))))
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "invalid json", content: "{", want: "invalid lockfile"},
		{name: "missing version", content: `{"servers":[]}`, want: "missing 'version'"},
		{name: "wrong version", content: `{"version":2,"servers":[]}`, want: "unsupported lockfile version"},
		{name: "missing servers", content: `{"version":1}`, want: "'servers' must be an array"},
		{name: "unknown top field", content: `{"version":1,"servers":[],"extra":true}`, want: "unknown field"},
		{name: "unknown server field", content: strings.Replace(valid, `"configHash"`, `"unknown":true,"configHash"`, 1), want: "unknown field"},
		{name: "bad hash", content: replaceFirst(valid, "sha256:", "md5:"), want: "configHash"},
		{name: "duplicate env key", content: replaceFirst(valid, `"GITHUB_TOKEN"`, `"GITHUB_TOKEN","GITHUB_TOKEN"`), want: "envKeys"},
		{name: "null args", content: replaceFirstArray(valid, "args", "null"), want: "args"},
		{name: "absolute source", content: replaceFirst(valid, `"source": ".mcp.json"`, `"source": "/tmp/.mcp.json"`), want: "source"},
		{name: "parent source", content: replaceFirst(valid, `"source": ".mcp.json"`, `"source": "../.mcp.json"`), want: "source"},
		{name: "backslash source", content: replaceFirst(valid, `"source": ".mcp.json"`, `"source": ".vscode\\mcp.json"`), want: "source"},
		{name: "drive source", content: replaceFirst(valid, `"source": ".mcp.json"`, `"source": "C:/tmp/.mcp.json"`), want: "source"},
		{name: "empty command", content: replaceFirst(valid, `"command": "npx"`, `"command": ""`), want: "command"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Parse([]byte(test.content))
			if err == nil {
				t.Fatal("Parse() error = nil")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %q, want it to contain %q", err, test.want)
			}
		})
	}
}

func TestParseRejectsNonCanonicalToolFields(t *testing.T) {
	file := Build(testProject(t))
	tools := []Tool{{
		Name:            "read_file",
		DescriptionHash: "sha256:" + strings.Repeat("a", 64),
		InputSchemaHash: "sha256:" + strings.Repeat("b", 64),
		Capabilities:    []string{"filesystem.read"},
	}}
	file.Servers[0].Tools = &tools
	valid := string(mustMarshal(t, file))
	invalid := replaceFirst(valid, `"name": "read_file"`, `"Name": "read_file"`)
	if _, err := Parse([]byte(invalid)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Parse() error = %v, want unknown field", err)
	}
}

func TestToolsRoundTripAndDiff(t *testing.T) {
	first := Build(testProject(t))
	firstTools := []Tool{{
		Name:            "read_file",
		DescriptionHash: "sha256:" + strings.Repeat("a", 64),
		InputSchemaHash: "sha256:" + strings.Repeat("b", 64),
		Annotations:     map[string]bool{"readOnlyHint": true},
		Capabilities:    []string{"filesystem.read"},
	}}
	first.Servers[0].Tools = &firstTools
	data, err := Marshal(first)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	loaded, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !reflect.DeepEqual(loaded, first) {
		t.Fatalf("tools round trip mismatch:\nloaded: %#v\nfirst: %#v", loaded, first)
	}

	second := Build(testProject(t))
	secondTools := []Tool{{
		Name:            "write_file",
		DescriptionHash: "sha256:" + strings.Repeat("c", 64),
		InputSchemaHash: "sha256:" + strings.Repeat("d", 64),
		Capabilities:    []string{"filesystem.write"},
	}}
	second.Servers[0].Tools = &secondTools
	result := CompareLockfiles(loaded, second)
	if got, want := len(result.Changed), 1; got != want {
		t.Fatalf("changed count = %d, want %d", got, want)
	}
	if !reflect.DeepEqual(result.Changed[0].Fields, []string{"tools"}) {
		t.Fatalf("changed fields = %v, want [tools]", result.Changed[0].Fields)
	}
	if got, want := len(result.Changed[0].ToolChanges), 2; got != want {
		t.Fatalf("tool change count = %d, want %d", got, want)
	}
	if got, want := result.Changed[0].ToolChanges[0].Action, "removed"; got != want {
		t.Fatalf("first tool action = %q, want %q", got, want)
	}
	if got, want := result.Changed[0].ToolChanges[1].Action, "added"; got != want {
		t.Fatalf("second tool action = %q, want %q", got, want)
	}
}

func TestToolDiffExplainsChangedFields(t *testing.T) {
	before := Build(testProject(t))
	beforeTools := []Tool{{
		Name:            "read_file",
		DescriptionHash: "sha256:" + strings.Repeat("a", 64),
		InputSchemaHash: "sha256:" + strings.Repeat("b", 64),
		Annotations:     map[string]bool{"readOnlyHint": true},
		Capabilities:    []string{"read"},
	}}
	before.Servers[0].Tools = &beforeTools

	after := Build(testProject(t))
	afterTools := []Tool{{
		Name:            "read_file",
		DescriptionHash: "sha256:" + strings.Repeat("c", 64),
		InputSchemaHash: "sha256:" + strings.Repeat("d", 64),
		Annotations:     map[string]bool{"readOnlyHint": false},
		Capabilities:    []string{"read", "write"},
	}}
	after.Servers[0].Tools = &afterTools

	result := CompareLockfiles(before, after)
	if got, want := len(result.Changed), 1; got != want {
		t.Fatalf("changed count = %d, want %d", got, want)
	}
	changes := result.Changed[0].ToolChanges
	if got, want := len(changes), 1; got != want {
		t.Fatalf("tool change count = %d, want %d", got, want)
	}
	wantFields := []string{"annotations", "capabilities", "description", "inputSchema"}
	if !reflect.DeepEqual(changes[0].Fields, wantFields) {
		t.Fatalf("tool fields = %#v, want %#v", changes[0].Fields, wantFields)
	}
}

func TestEmptyToolListIsPreserved(t *testing.T) {
	file := Build(testProject(t))
	emptyTools := []Tool{}
	file.Servers[0].Tools = &emptyTools
	data := mustMarshal(t, file)
	if !bytes.Contains(data, []byte(`"tools": []`)) {
		t.Fatalf("empty tool list was omitted:\n%s", data)
	}
	loaded, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if loaded.Servers[0].Tools == nil || len(*loaded.Servers[0].Tools) != 0 {
		t.Fatalf("empty tool list was not preserved: %#v", loaded.Servers[0].Tools)
	}

	static := Build(testProject(t))
	staticJSON := mustMarshal(t, static)
	if bytes.Contains(staticJSON, []byte(`"tools"`)) {
		t.Fatalf("static scan unexpectedly emitted tools:\n%s", staticJSON)
	}
}

func TestCompareLockfiles(t *testing.T) {
	base := Build(testProject(t))
	old := cloneFile(base)
	newFile := cloneFile(base)
	old.Servers = append(old.Servers, Server{
		Name: "postgres", Source: ".mcp.json", Transport: "stdio",
		Command: ptr("npx"), Args: []string{}, EnvKeys: []string{}, HeaderKeys: []string{},
		ConfigHash: "sha256:" + strings.Repeat("1", 64),
	})
	newFile.Servers = append(newFile.Servers, Server{
		Name: "filesystem-extra", Source: ".mcp.json", Transport: "stdio",
		Command: ptr("npx"), Args: []string{}, EnvKeys: []string{}, HeaderKeys: []string{},
		ConfigHash: "sha256:" + strings.Repeat("2", 64),
	})
	newFile.Servers[0].ConfigHash = "sha256:" + strings.Repeat("3", 64)
	Normalize(old)
	Normalize(newFile)

	result := CompareLockfiles(old, newFile)
	if got, want := len(result.Added), 1; got != want || result.Added[0].Name != "filesystem-extra" {
		t.Fatalf("added = %#v, want filesystem-extra", result.Added)
	}
	if got, want := len(result.Removed), 1; got != want || result.Removed[0].Name != "postgres" {
		t.Fatalf("removed = %#v, want postgres", result.Removed)
	}
	if got, want := len(result.Changed), 1; got != want {
		t.Fatalf("changed count = %d, want %d", got, want)
	}
	if !result.HasChanges() {
		t.Fatal("HasChanges() = false")
	}
}

func TestCompareNoChanges(t *testing.T) {
	file := Build(testProject(t))
	result := CompareLockfiles(file, cloneFile(file))
	if result.HasChanges() {
		t.Fatalf("unexpected changes: %#v", result)
	}
}

func TestParseEmptyServersProducesArray(t *testing.T) {
	file, err := Parse([]byte(`{"version":1,"servers":[]}`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	data, err := Marshal(file)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !bytes.Contains(data, []byte(`"servers": []`)) {
		t.Fatalf("empty servers did not marshal as an array:\n%s", data)
	}
}

func TestQuickstartLockfileGolden(t *testing.T) {
	project, err := config.LoadProject(filepath.Join("..", "..", "examples", "quickstart"))
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	actual, err := Marshal(Build(project))
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	expected, err := os.ReadFile(filepath.Join("..", "..", "examples", "quickstart", "caplock.lock"))
	if err != nil {
		t.Fatalf("read golden lockfile: %v", err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("quickstart lockfile is stale; run `go run ./cmd/caplock lock examples/quickstart -o examples/quickstart/caplock.lock`\n--- expected\n%s\n--- actual\n%s", expected, actual)
	}
}

func TestPublishedSchemasAreValidJSON(t *testing.T) {
	for _, name := range []string{"caplock.lock.schema.json", "policy.schema.json", "ir.schema.json", "evidence.schema.json", "report.schema.json", "trace.schema.json", "replay.schema.json", "attackgraph.schema.json", "import-mapping.schema.json"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "schemas", name))
			if err != nil {
				t.Fatalf("read schema: %v", err)
			}
			var schema map[string]any
			if err := json.Unmarshal(data, &schema); err != nil {
				t.Fatalf("parse schema: %v", err)
			}
			if _, ok := schema["$schema"]; !ok {
				t.Fatalf("schema %s is missing $schema", name)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"version":1,"servers":[]}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"version":1,"servers":[{}]}`))
	f.Fuzz(func(_ *testing.T, input []byte) {
		_, _ = Parse(input)
	})
}

func testProject(t *testing.T) *config.Project {
	t.Helper()
	root := t.TempDir()
	content := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_TOKEN": "example-token"}
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]
    }
  }
}`
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	project, err := config.LoadProject(root)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	return project
}

func mustMarshal(t *testing.T, file *File) []byte {
	t.Helper()
	data, err := Marshal(file)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return data
}

func replaceFirst(value, old, replacement string) string {
	return strings.Replace(value, old, replacement, 1)
}

func replaceFirstArray(value, key, replacement string) string {
	needle := `"` + key + `": [`
	start := strings.Index(value, needle)
	if start < 0 {
		return value
	}
	end := strings.Index(value[start:], "]")
	if end < 0 {
		return value
	}
	end += start + 1
	return value[:start] + `"` + key + `": ` + replacement + value[end:]
}

func cloneFile(file *File) *File {
	data, _ := json.Marshal(file)
	var cloned File
	_ = json.Unmarshal(data, &cloned)
	return &cloned
}

func ptr(value string) *string { return &value }
