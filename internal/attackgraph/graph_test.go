package attackgraph

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/caplock/caplock/internal/lockfile"
	"github.com/caplock/caplock/internal/policy"
	"github.com/caplock/caplock/packs"
)

func TestBuildFindsAndEvaluatesCandidatePaths(t *testing.T) {
	source, err := packs.Read("policies/finance.yaml")
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	ir, err := policy.Compile(source, "caplock.yaml")
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	locked := &lockfile.File{Version: lockfile.Version, Servers: []lockfile.Server{
		{Name: "web", Source: ".mcp.json", Transport: "http", Args: []string{}, EnvKeys: []string{}, HeaderKeys: []string{}, ConfigHash: "sha256:" + strings.Repeat("0", 64), Tools: &[]lockfile.Tool{{Name: "browser_fetch", Capabilities: []string{"external", "external.read", "read"}}}},
		{Name: "secrets", Source: ".mcp.json", Transport: "http", Args: []string{}, EnvKeys: []string{}, HeaderKeys: []string{}, ConfigHash: "sha256:" + strings.Repeat("1", 64), Tools: &[]lockfile.Tool{{Name: "get_token", Capabilities: []string{"identity", "read"}}}},
		{Name: "comms", Source: ".mcp.json", Transport: "http", Args: []string{}, EnvKeys: []string{}, HeaderKeys: []string{}, ConfigHash: "sha256:" + strings.Repeat("2", 64), Tools: &[]lockfile.Tool{{Name: "send_email", Capabilities: []string{"comms", "network"}}}},
		{Name: "shell", Source: ".mcp.json", Transport: "http", Args: []string{}, EnvKeys: []string{}, HeaderKeys: []string{}, ConfigHash: "sha256:" + strings.Repeat("3", 64), Tools: &[]lockfile.Tool{{Name: "run_shell", Capabilities: []string{"execute"}}}},
		{Name: "files", Source: ".mcp.json", Transport: "http", Args: []string{}, EnvKeys: []string{}, HeaderKeys: []string{}, ConfigHash: "sha256:" + strings.Repeat("4", 64), Tools: &[]lockfile.Tool{{Name: "read_report", Capabilities: []string{"read"}}}},
	}}
	result, err := Build(ir, locked, Options{Subject: "finance-analyst", MaxPaths: 50})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if result.Summary.Sources != 2 || result.Summary.Sinks < 2 || len(result.Paths) == 0 {
		t.Fatalf("result = %#v", result)
	}
	var externalMail, secretMail Path
	for _, path := range result.Paths {
		if path.Sink == "email.send" && len(path.Steps) == 2 && path.Steps[0].Tool == "browser_fetch" {
			externalMail = path
		}
		if path.Sink == "email.send" && len(path.Steps) == 2 && path.Steps[0].Tool == "get_token" {
			secretMail = path
		}
	}
	if externalMail.Status != "approval_required" || externalMail.Decision.RuleID != "approve-external-provenance-egress" {
		t.Fatalf("external mail path = %#v\nall=%#v", externalMail, result.Paths)
	}
	if secretMail.Status != "blocked" || secretMail.Decision.RuleID != "deny-secret-exfiltration" {
		t.Fatalf("secret mail path = %#v", secretMail)
	}
	second, err := Build(ir, locked, Options{Subject: "finance-analyst", MaxPaths: 50})
	if err != nil {
		t.Fatalf("second Build() error = %v", err)
	}
	if len(second.Paths) != len(result.Paths) || second.Paths[0].ID != result.Paths[0].ID {
		t.Fatalf("graph is not deterministic")
	}
}

func TestBuildRequiresCapturedTools(t *testing.T) {
	ir, err := policy.Compile([]byte("apiVersion: caplock/v1alpha1\nkind: PolicySet\nmetadata: {name: empty}\nspec: {defaults: {effect: deny}, rules: []}\n"), "caplock.yaml")
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	_, err = Build(ir, &lockfile.File{Version: lockfile.Version, Servers: []lockfile.Server{}}, Options{})
	if err == nil || !strings.Contains(err.Error(), "no captured tools") {
		t.Fatalf("Build() error = %v", err)
	}
}

func TestPublishedGraphSchemaAcceptsRendererOutput(t *testing.T) {
	source, err := packs.Read("policies/finance.yaml")
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	ir, err := policy.Compile(source, "caplock.yaml")
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	locked := &lockfile.File{Version: lockfile.Version, Servers: []lockfile.Server{
		{Name: "web", Source: ".mcp.json", Transport: "http", Args: []string{}, EnvKeys: []string{}, HeaderKeys: []string{}, ConfigHash: "sha256:" + strings.Repeat("0", 64), Tools: &[]lockfile.Tool{{Name: "browser_fetch", Capabilities: []string{"external", "external.read", "read"}}}},
		{Name: "mail", Source: ".mcp.json", Transport: "http", Args: []string{}, EnvKeys: []string{}, HeaderKeys: []string{}, ConfigHash: "sha256:" + strings.Repeat("1", 64), Tools: &[]lockfile.Tool{{Name: "send_email", Capabilities: []string{"comms", "network"}}}},
	}}
	result, err := Build(ir, locked, Options{Subject: "finance-analyst"})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	data, err := Render(result, "json")
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	path := filepath.Join("..", "..", "schemas", "attackgraph.schema.json")
	schemaData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat = true
	url := "https://caplock.dev/schemas/attackgraph.schema.json"
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
		t.Fatalf("decode graph: %v", err)
	}
	if err := schema.Validate(decoded); err != nil {
		t.Fatalf("schema validation failed: %v\n%s", err, data)
	}
}
