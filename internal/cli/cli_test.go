package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/1124875284/caplock/internal/lockfile"
	"github.com/1124875284/caplock/internal/version"
)

func TestScanJSON(t *testing.T) {
	root := writeConfig(t, `{
  "mcpServers": {
    "github": {"command":"npx","env":{"GITHUB_TOKEN":"example-token"}},
    "filesystem": {"command":"npx","args":["server-filesystem"]}
  }
}`)
	stdout, stderr, code := run(t, "scan", root, "--json")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	var file lockfile.File
	if err := json.Unmarshal([]byte(stdout), &file); err != nil {
		t.Fatalf("decode scan output: %v\n%s", err, stdout)
	}
	if got, want := len(file.Servers), 2; got != want {
		t.Fatalf("server count = %d, want %d", got, want)
	}
	if got, want := file.Servers[0].Name, "filesystem"; got != want {
		t.Fatalf("first server = %q, want %q", got, want)
	}
	if strings.Contains(stdout, "example-token") {
		t.Fatalf("scan output leaked env value:\n%s", stdout)
	}
}

func TestScanText(t *testing.T) {
	root := writeConfig(t, `{"mcpServers":{"github":{"command":"npx","args":["server-github"]}}}`)
	stdout, stderr, code := run(t, "scan", root)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	for _, want := range []string{"SERVER", "github", ".mcp.json", "1 server · 1 config file"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("scan output %q does not contain %q", stdout, want)
		}
	}
}

func TestLockCheckAndSecretRotation(t *testing.T) {
	root := writeConfig(t, `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"one"}}}}`)
	lockPath := filepath.Join(root, "caplock.lock")
	_, stderr, code := run(t, "lock", root, "--output", lockPath)
	if code != 0 {
		t.Fatalf("lock exit code = %d, stderr = %q", code, stderr)
	}
	locked, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("read lockfile: %v", err)
	}
	if bytes.Contains(locked, []byte(`"one"`)) {
		t.Fatalf("lockfile leaked env value:\n%s", locked)
	}

	_, stderr, code = run(t, "lock", root, "--output", lockPath, "--check")
	if code != 0 {
		t.Fatalf("check exit code = %d, stderr = %q", code, stderr)
	}

	writeConfigAt(t, root, `{"mcpServers":{"github":{"command":"npx","env":{"GITHUB_TOKEN":"two"}}}}`)
	_, stderr, code = run(t, "lock", root, "--output", lockPath, "--check")
	if code != 0 {
		t.Fatalf("secret rotation should not drift; exit code = %d, stderr = %q", code, stderr)
	}

	writeConfigAt(t, root, `{"mcpServers":{"github":{"command":"uvx","env":{"GITHUB_TOKEN":"two"}}}}`)
	stdout, stderr, code := run(t, "lock", root, "--output", lockPath, "--check")
	if code != 1 {
		t.Fatalf("changed config exit code = %d, want 1; stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "out of date") {
		t.Fatalf("check output = %q, want out of date", stdout)
	}
}

func TestLockCheckMissingLockfile(t *testing.T) {
	root := writeConfig(t, `{"mcpServers":{"github":{"command":"npx"}}}`)
	stdout, _, code := run(t, "lock", root, "--output", filepath.Join(root, "missing.lock"), "--check")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stdout, "missing") {
		t.Fatalf("output = %q, want missing", stdout)
	}
}

func TestDiffAndExitCode(t *testing.T) {
	root := writeConfig(t, `{"mcpServers":{"github":{"command":"npx"}}}`)
	oldPath := filepath.Join(root, "old.lock")
	newPath := filepath.Join(root, "new.lock")
	if _, stderr, code := run(t, "lock", root, "--output", oldPath); code != 0 {
		t.Fatalf("lock old exit code = %d, stderr = %q", code, stderr)
	}
	writeConfigAt(t, root, `{"mcpServers":{"filesystem":{"command":"npx"}}}`)
	if _, stderr, code := run(t, "lock", root, "--output", newPath); code != 0 {
		t.Fatalf("lock new exit code = %d, stderr = %q", code, stderr)
	}

	stdout, stderr, code := run(t, "diff", oldPath, newPath)
	if code != 0 {
		t.Fatalf("diff without --exit-code returned %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "+ filesystem") || !strings.Contains(stdout, "- github") {
		t.Fatalf("diff output = %q", stdout)
	}

	_, stderr, code = run(t, "diff", oldPath, newPath, "--exit-code")
	if code != 1 {
		t.Fatalf("diff --exit-code returned %d, want 1; stderr = %q", code, stderr)
	}
	if strings.Contains(stderr, "error:") {
		t.Fatalf("drift should be quiet on stderr, got %q", stderr)
	}

	stdout, stderr, code = run(t, "diff", oldPath, newPath, "--json")
	if code != 0 {
		t.Fatalf("diff --json returned %d, stderr = %q", code, stderr)
	}
	var payload struct {
		Version int               `json:"version"`
		Added   []lockfile.Server `json:"added"`
		Removed []lockfile.Server `json:"removed"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("decode diff: %v\n%s", err, stdout)
	}
	if payload.Version != 1 || len(payload.Added) != 1 || len(payload.Removed) != 1 {
		t.Fatalf("diff payload = %#v", payload)
	}
}

func TestDiffJSONUsesEmptyArrays(t *testing.T) {
	root := writeConfig(t, `{"mcpServers":{"github":{"command":"npx"}}}`)
	path := filepath.Join(root, "caplock.lock")
	if _, stderr, code := run(t, "lock", root, "--output", path); code != 0 {
		t.Fatalf("lock exit code = %d, stderr = %q", code, stderr)
	}
	stdout, stderr, code := run(t, "diff", path, path, "--json")
	if code != 0 {
		t.Fatalf("diff exit code = %d, stderr = %q", code, stderr)
	}
	for _, want := range []string{`"added": []`, `"removed": []`, `"changed": []`} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("diff JSON %q does not contain %q", stdout, want)
		}
	}
}

func TestVersion(t *testing.T) {
	stdout, stderr, code := run(t, "version")
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	if got, want := strings.TrimSpace(stdout), "caplock "+version.Version; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

func TestCompileAndLintPolicy(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "caplock.yaml")
	content := `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: demo
spec:
  defaults:
    effect: deny
  rules:
    - id: deny-delete
      effect: deny
      match:
        capability: [destructive]
      obligations: [audit]
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	stdout, stderr, code := run(t, "lint", path)
	if code != 0 {
		t.Fatalf("lint exit code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "No policy lint findings") {
		t.Fatalf("lint output = %q", stdout)
	}

	stdout, stderr, code = run(t, "compile", path)
	if code != 0 {
		t.Fatalf("compile exit code = %d, stderr = %q", code, stderr)
	}
	var ir struct {
		IRVersion int    `json:"irVersion"`
		Policy    string `json:"policy"`
		Rules     []struct {
			ID     string `json:"id"`
			Source struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"source"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(stdout), &ir); err != nil {
		t.Fatalf("decode IR: %v\n%s", err, stdout)
	}
	if ir.IRVersion != 1 || ir.Policy != "demo" || len(ir.Rules) != 1 {
		t.Fatalf("IR = %#v", ir)
	}
	if ir.Rules[0].ID != "deny-delete" || ir.Rules[0].Source.Line == 0 {
		t.Fatalf("rule IR = %#v", ir.Rules[0])
	}

	outputPath := filepath.Join(root, "policy.ir.json")
	stdout, stderr, code = run(t, "compile", path, "--format", "json", "--output", outputPath)
	if code != 0 {
		t.Fatalf("compile --output exit code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("IR output missing: %v", err)
	}
}

func TestLintStrictAndCompileSemanticErrors(t *testing.T) {
	root := t.TempDir()
	warningPath := filepath.Join(root, "warning.yaml")
	warning := `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: warning
spec:
  defaults:
    effect: allow
  rules:
    - id: deny-delete
      effect: deny
      match:
        capability: [destructive]
`
	if err := os.WriteFile(warningPath, []byte(warning), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	stdout, stderr, code := run(t, "lint", warningPath)
	if code != 0 {
		t.Fatalf("lint exit code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "default-allow") {
		t.Fatalf("lint output = %q", stdout)
	}
	stdout, stderr, code = run(t, "lint", warningPath, "--strict")
	if code != 1 {
		t.Fatalf("strict lint exit code = %d, want 1; stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "warning") {
		t.Fatalf("strict lint output = %q", stdout)
	}

	errorPath := filepath.Join(root, "error.yaml")
	invalid := `apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: invalid
spec:
  defaults:
    effect: deny
  rules:
    - id: missing-subject
      effect: deny
      match:
        subject: ghost
        capability: [write]
`
	if err := os.WriteFile(errorPath, []byte(invalid), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	_, stderr, code = run(t, "compile", errorPath)
	if code != 1 {
		t.Fatalf("compile semantic error exit code = %d, want 1; stderr = %q", code, stderr)
	}
	if !strings.Contains(stderr, "lint errors") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestCompileRejectsUnknownPolicyField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "caplock.yaml")
	content := "apiVersion: caplock/v1alpha1\nkind: PolicySet\nmetadata:\n  name: demo\nspec:\n  defaults:\n    effect: deny\n  rules: []\n  unexpected: true\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	_, stderr, code := run(t, "compile", path)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2; stderr = %q", code, stderr)
	}
	if !strings.Contains(stderr, "unexpected") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestInitCreatesLintablePolicy(t *testing.T) {
	root := t.TempDir()
	stdout, stderr, code := run(t, "init", root)
	if code != 0 {
		t.Fatalf("init exit code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "created") {
		t.Fatalf("init output = %q", stdout)
	}
	path := filepath.Join(root, "caplock.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("policy file missing: %v", err)
	}
	stdout, stderr, code = run(t, "lint", path)
	if code != 0 || !strings.Contains(stdout, "No policy lint findings") {
		t.Fatalf("lint exit code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	_, stderr, code = run(t, "init", root)
	if code != 2 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("second init exit code = %d, stderr = %q", code, stderr)
	}
	if _, stderr, code = run(t, "init", root, "--force"); code != 0 {
		t.Fatalf("forced init exit code = %d, stderr = %q", code, stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	_, stderr, code := run(t, "diff", "one")
	if code != 2 {
		t.Fatalf("bad args exit code = %d, want 2; stderr = %q", code, stderr)
	}
}

func TestLockConnectHTTPAndToolDiff(t *testing.T) {
	var descriptionMu sync.RWMutex
	description := "Read one file"
	var requestCount atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer top-secret" {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		var payload struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		requestCount.Add(1)
		switch payload.Method {
		case "initialize":
			writer.Header().Set("Mcp-Session-Id", "session-123")
			writeRPCResult(t, writer, payload.ID, map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{},
				"serverInfo":      map[string]string{"name": "test", "version": "1"},
			})
		case "notifications/initialized":
			if request.Header.Get("Mcp-Session-Id") != "session-123" {
				http.Error(writer, "missing session", http.StatusBadRequest)
				return
			}
			writer.WriteHeader(http.StatusAccepted)
		case "tools/list":
			if request.Header.Get("MCP-Protocol-Version") != "2025-06-18" {
				http.Error(writer, "missing protocol version", http.StatusBadRequest)
				return
			}
			var params struct {
				Cursor string `json:"cursor"`
			}
			_ = json.Unmarshal(payload.Params, &params)
			if params.Cursor == "" {
				writeRPCResult(t, writer, payload.ID, map[string]any{
					"tools": []map[string]any{{
						"name":        "read_file",
						"description": currentDescription(&descriptionMu, &description),
						"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}}},
					}},
					"nextCursor": "second-page",
				})
				return
			}
			writeRPCResult(t, writer, payload.ID, map[string]any{
				"tools": []map[string]any{{
					"name":        "send_email",
					"description": "Send an email",
					"inputSchema": map[string]any{"type": "object"},
				}},
			})
		default:
			http.Error(writer, "unknown method", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	root := t.TempDir()
	writeConfigAt(t, root, fmt.Sprintf(`{"mcpServers":{"remote":{"type":"http","url":%q,"headers":{"Authorization":"Bearer top-secret"}}}}`, server.URL))

	stdout, stderr, code := run(t, "scan", root)
	if code != 0 {
		t.Fatalf("static scan exit code = %d, stderr = %q", code, stderr)
	}
	if requestCount.Load() != 0 {
		t.Fatalf("static scan contacted the MCP server %d times", requestCount.Load())
	}
	if !strings.Contains(stdout, "remote") {
		t.Fatalf("scan output = %q", stdout)
	}

	oldPath := filepath.Join(root, "old.lock")
	stdout, stderr, code = run(t, "lock", root, "--connect", "--output", oldPath)
	if code != 0 {
		t.Fatalf("lock --connect exit code = %d, stdout = %q, stderr = %q", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "2 tools") {
		t.Fatalf("lock output = %q, want tool count", stdout)
	}
	locked, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatalf("read lockfile: %v", err)
	}
	if bytes.Contains(locked, []byte("top-secret")) {
		t.Fatalf("lockfile leaked an HTTP header value:\n%s", locked)
	}
	oldFile, err := lockfile.Read(oldPath)
	if err != nil {
		t.Fatalf("parse lockfile: %v", err)
	}
	remote := findLockedServer(t, oldFile, "remote")
	if remote.Tools == nil || len(*remote.Tools) != 2 {
		t.Fatalf("tools = %#v, want two tools", remote.Tools)
	}

	descriptionMu.Lock()
	description = "Overwrite one file"
	descriptionMu.Unlock()
	newPath := filepath.Join(root, "new.lock")
	if _, stderr, code := run(t, "lock", root, "--connect", "--output", newPath); code != 0 {
		t.Fatalf("second lock exit code = %d, stderr = %q", code, stderr)
	}
	diffOutput, stderr, code := run(t, "diff", oldPath, newPath)
	if code != 0 {
		t.Fatalf("diff exit code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(diffOutput, "~ tool read_file") || !strings.Contains(diffOutput, "description") {
		t.Fatalf("diff output = %q, want a tool description change", diffOutput)
	}

	jsonDiff, stderr, code := run(t, "diff", oldPath, newPath, "--json")
	if code != 0 {
		t.Fatalf("diff --json exit code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(jsonDiff, `"action": "changed"`) || !strings.Contains(jsonDiff, `"name": "read_file"`) {
		t.Fatalf("diff JSON = %q", jsonDiff)
	}
}

func writeRPCResult(t *testing.T, writer http.ResponseWriter, id json.RawMessage, result any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}); err != nil {
		t.Errorf("encode RPC response: %v", err)
	}
}

func currentDescription(mu *sync.RWMutex, value *string) string {
	mu.RLock()
	defer mu.RUnlock()
	return *value
}

func findLockedServer(t *testing.T, file *lockfile.File, name string) lockfile.Server {
	t.Helper()
	for _, server := range file.Servers {
		if server.Name == name {
			return server
		}
	}
	t.Fatalf("server %q not found", name)
	return lockfile.Server{}
}

func TestScanMissingPath(t *testing.T) {
	_, stderr, code := run(t, "scan", filepath.Join(t.TempDir(), "missing"))
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "does not exist") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestNoServers(t *testing.T) {
	root := t.TempDir()
	stdout, stderr, code := run(t, "scan", root)
	if code != 0 {
		t.Fatalf("scan exit code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, "No MCP servers found") {
		t.Fatalf("scan output = %q", stdout)
	}
	_, stderr, code = run(t, "lock", root)
	if code != 2 {
		t.Fatalf("lock exit code = %d, want 2; stderr = %q", code, stderr)
	}
}

func TestConfigErrorDoesNotEchoSecret(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, ".mcp.json")
	if err := os.WriteFile(path, []byte(`{"mcpServers":{"x":{"command":"npx","env":{"TOKEN":"do-not-print-me"}}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, stderr, code := run(t, "scan", root)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if strings.Contains(stderr, "do-not-print-me") {
		t.Fatalf("stderr leaked a secret: %q", stderr)
	}
}

func TestHumanOutputEscapesTerminalControlCharacters(t *testing.T) {
	root := writeConfig(t, "{\"mcpServers\":{\"evil\\u001b[31m\\nname\":{\"command\":\"npx\"}}}")
	stdout, stderr, code := run(t, "scan", root)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr)
	}
	if strings.ContainsRune(stdout, '\x1b') {
		t.Fatalf("scan output contains a raw escape character: %q", stdout)
	}
	if !strings.Contains(stdout, `\x1b`) {
		t.Fatalf("scan output does not show escaped control character: %q", stdout)
	}
}

func TestDisplayText(t *testing.T) {
	if got, want := displayText("a\nb\tc\x1b"), `a\nb\tc\x1b`; got != want {
		t.Fatalf("displayText() = %q, want %q", got, want)
	}
}

func run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Execute(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	root := t.TempDir()
	writeConfigAt(t, root, content)
	return root
}

func writeConfigAt(t *testing.T, root, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}
