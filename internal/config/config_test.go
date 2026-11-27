package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadProjectNormalizesAndSortsServers(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".mcp.json"), `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_TOKEN": "super-secret-token"}
    },
    "filesystem": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "."],
      "env": {"LOG_LEVEL": "info"}
    }
  }
}`)

	project, err := LoadProject(root)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	if got, want := len(project.Configs), 1; got != want {
		t.Fatalf("config count = %d, want %d", got, want)
	}
	if got, want := project.Configs[0], ".mcp.json"; got != want {
		t.Fatalf("source = %q, want %q", got, want)
	}
	if got, want := len(project.Servers), 2; got != want {
		t.Fatalf("server count = %d, want %d", got, want)
	}
	if got, want := project.Servers[0].Name, "filesystem"; got != want {
		t.Fatalf("first server = %q, want %q", got, want)
	}
	if got, want := project.Servers[1].Name, "github"; got != want {
		t.Fatalf("second server = %q, want %q", got, want)
	}
	for _, server := range project.Servers {
		if !strings.HasPrefix(server.ConfigHash(), "sha256:") {
			t.Fatalf("ConfigHash() = %q", server.ConfigHash())
		}
	}
}

func TestConfigHashIgnoresSecretRotation(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, ".mcp.json")
	writeFile(t, configPath, `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"one"}}}}`)
	first, err := LoadProject(root)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}

	writeFile(t, configPath, `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"two"}}}}`)
	second, err := LoadProject(root)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	if first.Servers[0].ConfigHash() != second.Servers[0].ConfigHash() {
		t.Fatal("rotating a secret changed configHash")
	}
}

func TestConfigHashChangesWithEnvKey(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, ".mcp.json")
	writeFile(t, configPath, `{"mcpServers":{"github":{"command":"npx","env":{"TOKEN_A":"x"}}}}`)
	first, err := LoadProject(root)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	writeFile(t, configPath, `{"mcpServers":{"github":{"command":"npx","env":{"TOKEN_B":"x"}}}}`)
	second, err := LoadProject(root)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	if first.Servers[0].ConfigHash() == second.Servers[0].ConfigHash() {
		t.Fatal("changing an env key did not change configHash")
	}
}

func TestConnectionSecretsStayInMemory(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".mcp.json"), `{
  "mcpServers": {
    "remote": {
      "type": "http",
      "url": "https://example.com/mcp",
      "headers": {"Authorization": "Bearer header-secret"}
    },
    "local": {
      "command": "server",
      "env": {"API_TOKEN": "env-secret"}
    }
  }
}`)
	project, err := LoadProject(root)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	serialized, err := json.Marshal(project)
	if err != nil {
		t.Fatalf("marshal project: %v", err)
	}
	for _, secret := range []string{"header-secret", "env-secret"} {
		if strings.Contains(string(serialized), secret) {
			t.Fatalf("serialized project leaked %q: %s", secret, serialized)
		}
	}
	local := serverByName(t, project, "local")
	remote := serverByName(t, project, "remote")
	if got, want := remote.Headers()["Authorization"], "Bearer header-secret"; got != want {
		t.Fatalf("header = %q, want %q", got, want)
	}
	if got, want := local.Environment()["API_TOKEN"], "env-secret"; got != want {
		t.Fatalf("env = %q, want %q", got, want)
	}
	headers := remote.Headers()
	headers["Authorization"] = "mutated"
	if got, want := remote.Headers()["Authorization"], "Bearer header-secret"; got != want {
		t.Fatalf("Headers() did not return a copy: %q", got)
	}
}

func serverByName(t *testing.T, project *Project, name string) Server {
	t.Helper()
	for _, server := range project.Servers {
		if server.Name == name {
			return server
		}
	}
	t.Fatalf("server %q not found", name)
	return Server{}
}

func TestLoadProjectSupportsJSONCAndServersKey(t *testing.T) {
	root := t.TempDir()
	mkdir(t, filepath.Join(root, ".vscode"))
	writeFile(t, filepath.Join(root, ".vscode", "mcp.json"), `{
  // VS Code often stores MCP servers under "servers".
  "servers": {
    "filesystem": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "server-filesystem",],
    },
  },
}`)

	project, err := LoadProject(root)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	if got, want := len(project.Servers), 1; got != want {
		t.Fatalf("server count = %d, want %d", got, want)
	}
	if got, want := project.Servers[0].Source, ".vscode/mcp.json"; got != want {
		t.Fatalf("source = %q, want %q", got, want)
	}
	if got, want := project.Servers[0].Transport, "stdio"; got != want {
		t.Fatalf("transport = %q, want %q", got, want)
	}
}

func TestLoadProjectSkipsExcludedDirectories(t *testing.T) {
	root := t.TempDir()
	mkdir(t, filepath.Join(root, "node_modules", "package"))
	writeFile(t, filepath.Join(root, "node_modules", "package", ".mcp.json"), `{"mcpServers":{"hidden":{"command":"npx"}}}`)
	mkdir(t, filepath.Join(root, "src"))
	writeFile(t, filepath.Join(root, "src", "mcp.json"), `{"servers":{"visible":{"command":"npx"}}}`)

	project, err := LoadProject(root)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	if got, want := len(project.Servers), 1; got != want {
		t.Fatalf("server count = %d, want %d", got, want)
	}
	if got, want := project.Servers[0].Name, "visible"; got != want {
		t.Fatalf("server = %q, want %q", got, want)
	}
}

func TestDiscoveryFilenamesAreCaseInsensitive(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".MCP.JSON"), `{"mcpServers":{"github":{"command":"npx"}}}`)
	project, err := LoadProject(root)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	if got, want := len(project.Servers), 1; got != want {
		t.Fatalf("server count = %d, want %d", got, want)
	}
}

func TestLoadProjectAcceptsSingleFile(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "custom.json")
	writeFile(t, configPath, `{"mcpServers":{"github":{"command":"npx"}}}`)

	project, err := LoadProject(configPath)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	if got, want := project.Servers[0].Source, "custom.json"; got != want {
		t.Fatalf("source = %q, want %q", got, want)
	}
}

func TestLoadProjectResolvesSymlinkedRoot(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".mcp.json"), `{"mcpServers":{"github":{"command":"npx"}}}`)
	link := filepath.Join(t.TempDir(), "project")
	if err := os.Symlink(root, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	project, err := LoadProject(link)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	if got, want := len(project.Servers), 1; got != want {
		t.Fatalf("server count = %d, want %d", got, want)
	}
}

func TestLoadProjectRejectsInvalidConfigs(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "invalid json", content: `{not-json`, want: "invalid JSONC"},
		{name: "top level array", content: `[]`, want: "expected a JSON object"},
		{name: "servers array", content: `{"mcpServers":[]}`, want: "must be an object"},
		{name: "server scalar", content: `{"mcpServers":{"x":"npx"}}`, want: "must be an object"},
		{name: "args object", content: `{"mcpServers":{"x":{"command":"npx","args":{}}}}`, want: "array of strings"},
		{name: "env array", content: `{"mcpServers":{"x":{"command":"npx","env":[]}}}`, want: "must be an object"},
		{name: "missing target", content: `{"mcpServers":{"x":{"env":{}}}}`, want: "one of 'command' or 'url'"},
		{name: "ambiguous target", content: `{"mcpServers":{"x":{"command":"npx","url":"https://example.com"}}}`, want: "only one of 'command' or 'url'"},
		{name: "non-string env", content: `{"mcpServers":{"x":{"command":"npx","env":{"TOKEN":1}}}}`, want: "values must be strings"},
		{name: "non-string header", content: `{"mcpServers":{"x":{"url":"https://example.com","headers":{"X":true}}}}`, want: "values must be strings"},
		{name: "empty env key", content: `{"mcpServers":{"x":{"command":"npx","env":{"":"value"}}}}`, want: "invalid key"},
		{name: "control header key", content: `{"mcpServers":{"x":{"url":"https://example.com","headers":{"X\nBad":"value"}}}}`, want: "invalid key"},
		{name: "nul env value", content: `{"mcpServers":{"x":{"command":"npx","env":{"TOKEN":"a\u0000b"}}}}`, want: "contains NUL"},
		{name: "unterminated comment", content: `{"mcpServers":{ /* nope`, want: "unterminated block comment"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, filepath.Join(root, ".mcp.json"), test.content)
			_, err := LoadProject(root)
			if err == nil {
				t.Fatal("LoadProject() error = nil")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %q, want it to contain %q", err, test.want)
			}
		})
	}
}

func TestParseJSONCDoesNotStripCommentMarkersInsideStrings(t *testing.T) {
	value, err := parseJSONC([]byte(`{"url":"https://example.com/a/*b*/","x":"//not-a-comment"}`))
	if err != nil {
		t.Fatalf("parseJSONC() error = %v", err)
	}
	document := value.(map[string]any)
	if got, want := document["url"], "https://example.com/a/*b*/"; got != want {
		t.Fatalf("url = %q, want %q", got, want)
	}
	if got, want := document["x"], "//not-a-comment"; got != want {
		t.Fatalf("x = %q, want %q", got, want)
	}
}

func TestProjectInputsRemainStable(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".mcp.json"), `{"mcpServers":{"b":{"command":"npx"},"a":{"command":"uvx"}}}`)
	first, err := LoadProject(root)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	second, err := LoadProject(root)
	if err != nil {
		t.Fatalf("LoadProject() error = %v", err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("project output changed between runs:\n%s\n%s", firstJSON, secondJSON)
	}
}

func FuzzParseJSONC(f *testing.F) {
	for _, seed := range []string{
		`{}`,
		`{"mcpServers":{}}`,
		`{"a":1, // comment\n "b":[1,2,],}`,
		`{"s":"// not a comment"}`,
		`{not-json}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, input string) {
		_, _ = parseJSONC([]byte(input))
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}
