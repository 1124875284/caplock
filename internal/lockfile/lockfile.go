// Package lockfile builds, validates, reads, and writes caplock.lock files.
package lockfile

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/caplock/caplock/internal/config"
	"github.com/caplock/caplock/internal/safefile"
)

const (
	// Name is the default lockfile name.
	Name = "caplock.lock"
	// Version is the current lockfile format version.
	Version = 1
	// MaxBytes is the largest lockfile Caplock will read.
	MaxBytes = 16 << 20
)

// File is the top-level caplock.lock document.
type File struct {
	Version int      `json:"version"`
	Servers []Server `json:"servers"`
}

// Server is a locked MCP server definition.
type Server struct {
	Name       string   `json:"name"`
	Source     string   `json:"source"`
	Transport  string   `json:"transport"`
	Command    *string  `json:"command"`
	Args       []string `json:"args"`
	URL        *string  `json:"url"`
	EnvKeys    []string `json:"envKeys"`
	HeaderKeys []string `json:"headerKeys"`
	ConfigHash string   `json:"configHash"`
	Tools      *[]Tool  `json:"tools,omitempty"`
}

// Tool is an optional normalized tool manifest entry. Static scans omit this
// field; a future connected lock will populate it from MCP tools/list.
type Tool struct {
	Name            string          `json:"name"`
	DescriptionHash string          `json:"descriptionHash"`
	InputSchemaHash string          `json:"inputSchemaHash"`
	Annotations     map[string]bool `json:"annotations,omitempty"`
	Capabilities    []string        `json:"capabilities"`
}

// Build creates a deterministic lockfile from discovered servers. Tool manifests
// are not part of a static scan and are therefore omitted.
func Build(project *config.Project) *File {
	servers := make([]Server, 0, len(project.Servers))
	for _, server := range project.Servers {
		servers = append(servers, Server{
			Name:       server.Name,
			Source:     server.Source,
			Transport:  server.Transport,
			Command:    cloneString(server.Command),
			Args:       cloneStrings(server.Args),
			URL:        cloneString(server.URL),
			EnvKeys:    cloneStrings(server.EnvKeys),
			HeaderKeys: cloneStrings(server.HeaderKeys),
			ConfigHash: server.ConfigHash(),
		})
	}
	file := &File{Version: Version, Servers: servers}
	Normalize(file)
	return file
}

// Normalize sorts semantically unordered fields. It does not sort command
// arguments because their order can change behavior.
func Normalize(file *File) {
	if file.Servers == nil {
		file.Servers = []Server{}
	}
	for i := range file.Servers {
		server := &file.Servers[i]
		server.Args = nonNilStrings(server.Args)
		server.EnvKeys = sortedUnique(server.EnvKeys)
		server.HeaderKeys = sortedUnique(server.HeaderKeys)
		if server.Tools != nil {
			tools := make([]Tool, len(*server.Tools))
			copy(tools, *server.Tools)
			for j := range tools {
				tools[j].Capabilities = sortedUnique(tools[j].Capabilities)
			}
			sort.SliceStable(tools, func(a, b int) bool {
				return tools[a].Name < tools[b].Name
			})
			server.Tools = &tools
		}
	}
	sort.SliceStable(file.Servers, func(i, j int) bool {
		if file.Servers[i].Name != file.Servers[j].Name {
			return file.Servers[i].Name < file.Servers[j].Name
		}
		return file.Servers[i].Source < file.Servers[j].Source
	})
}

// Marshal returns the canonical on-disk representation of a lockfile.
func Marshal(file *File) ([]byte, error) {
	if err := Validate(file); err != nil {
		return nil, fmt.Errorf("validate lockfile: %w", err)
	}
	Normalize(file)
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal lockfile: %w", err)
	}
	return append(data, '\n'), nil
}

// Write writes a lockfile atomically with a trailing newline.
func Write(path string, file *File) error {
	data, err := Marshal(file)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	// #nosec G301 -- the output directory is user-selected; lockfiles are meant
	// to be readable and committed to source control.
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create lockfile directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".caplock-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary lockfile: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()

	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary lockfile: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary lockfile: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary lockfile: %w", err)
	}
	// #nosec G302 -- caplock.lock is intentionally a world-readable repository artifact.
	if err := os.Chmod(temporaryPath, 0o644); err != nil {
		return fmt.Errorf("set lockfile permissions: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace lockfile: %w", err)
	}
	return nil
}

// Read parses and validates a lockfile. Semantically unordered fields are
// normalized so diffs focus on permission changes rather than serialization.
func Read(path string) (*File, error) {
	data, err := safefile.ReadFile(path, MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("read lockfile %s: %w", path, err)
	}
	return Parse(data)
}

// Parse parses and validates lockfile bytes.
func Parse(data []byte) (*File, error) {
	root, err := decodeObject(data)
	if err != nil {
		return nil, fmt.Errorf("invalid lockfile: %w", err)
	}
	if err := onlyKeys(root, "version", "servers"); err != nil {
		return nil, fmt.Errorf("invalid lockfile: %w", err)
	}
	versionRaw, ok := root["version"]
	if !ok {
		return nil, errors.New("invalid lockfile: missing 'version'")
	}
	var file File
	if err := strictUnmarshal(versionRaw, &file.Version); err != nil {
		return nil, fmt.Errorf("invalid lockfile 'version': %w", err)
	}
	if file.Version != Version {
		return nil, fmt.Errorf("unsupported lockfile version %d", file.Version)
	}
	serversRaw, ok := root["servers"]
	if !ok || bytes.Equal(bytes.TrimSpace(serversRaw), []byte("null")) {
		return nil, errors.New("invalid lockfile: 'servers' must be an array")
	}
	var rawServers []json.RawMessage
	if err := strictUnmarshal(serversRaw, &rawServers); err != nil {
		return nil, fmt.Errorf("invalid lockfile 'servers': %w", err)
	}
	if rawServers == nil {
		return nil, errors.New("invalid lockfile: 'servers' must be an array")
	}
	file.Servers = make([]Server, 0, len(rawServers))
	for index, rawServer := range rawServers {
		server, err := parseServer(rawServer)
		if err != nil {
			return nil, fmt.Errorf("invalid lockfile server %d: %w", index, err)
		}
		file.Servers = append(file.Servers, *server)
	}
	if err := Validate(&file); err != nil {
		return nil, fmt.Errorf("invalid lockfile: %w", err)
	}
	Normalize(&file)
	return &file, nil
}

func parseServer(data json.RawMessage) (*Server, error) {
	object, err := decodeObject(data)
	if err != nil {
		return nil, err
	}
	if err := onlyKeys(object,
		"name", "source", "transport", "command", "args", "url", "envKeys",
		"headerKeys", "configHash", "tools",
	); err != nil {
		return nil, err
	}
	if err := requireKeys(object,
		"name", "source", "transport", "command", "args", "url", "envKeys",
		"headerKeys", "configHash",
	); err != nil {
		return nil, err
	}
	var server Server
	if err := strictUnmarshal(data, &server); err != nil {
		return nil, err
	}
	if toolsRaw, ok := object["tools"]; ok {
		if bytes.Equal(bytes.TrimSpace(toolsRaw), []byte("null")) {
			return nil, errors.New("'tools' must be an array when present")
		}
		var rawTools []json.RawMessage
		if err := strictUnmarshal(toolsRaw, &rawTools); err != nil {
			return nil, fmt.Errorf("'tools': %w", err)
		}
		tools := make([]Tool, 0, len(rawTools))
		for index, rawTool := range rawTools {
			tool, err := parseTool(rawTool)
			if err != nil {
				return nil, fmt.Errorf("tool %d: %w", index, err)
			}
			tools = append(tools, *tool)
		}
		server.Tools = &tools
	}
	return &server, nil
}

func parseTool(data json.RawMessage) (*Tool, error) {
	object, err := decodeObject(data)
	if err != nil {
		return nil, err
	}
	if err := onlyKeys(object, "name", "descriptionHash", "inputSchemaHash", "annotations", "capabilities"); err != nil {
		return nil, err
	}
	if err := requireKeys(object, "name", "descriptionHash", "inputSchemaHash", "capabilities"); err != nil {
		return nil, err
	}
	var tool Tool
	if err := strictUnmarshal(data, &tool); err != nil {
		return nil, err
	}
	return &tool, nil
}

// Validate checks structural invariants that are not expressible through Go's
// JSON decoder alone.
func Validate(file *File) error {
	if file.Version != Version {
		return fmt.Errorf("unsupported version %d", file.Version)
	}
	if file.Servers == nil {
		return errors.New("'servers' must be an array")
	}
	seen := make(map[string]bool, len(file.Servers))
	for index := range file.Servers {
		server := &file.Servers[index]
		if err := validateServer(server); err != nil {
			return fmt.Errorf("server %d: %w", index, err)
		}
		key := server.Source + "\x00" + server.Name
		if seen[key] {
			return fmt.Errorf("duplicate server %q from %q", server.Name, server.Source)
		}
		seen[key] = true
	}
	return nil
}

func validateServer(server *Server) error {
	if strings.TrimSpace(server.Name) == "" {
		return errors.New("'name' must not be empty")
	}
	if strings.TrimSpace(server.Source) == "" {
		return errors.New("'source' must not be empty")
	}
	if path.IsAbs(server.Source) || filepath.IsAbs(server.Source) || hasDrivePrefix(server.Source) || strings.Contains(server.Source, `\`) || path.Clean(server.Source) != server.Source || server.Source == "." || server.Source == ".." || strings.HasPrefix(server.Source, "../") {
		return errors.New("'source' must be a clean project-relative path using forward slashes")
	}
	if strings.TrimSpace(server.Transport) == "" {
		return errors.New("'transport' must not be empty")
	}
	if server.Command == nil && server.URL == nil {
		return errors.New("one of 'command' or 'url' must be set")
	}
	if server.Command != nil && strings.TrimSpace(*server.Command) == "" {
		return errors.New("'command' must not be empty")
	}
	if server.URL != nil && strings.TrimSpace(*server.URL) == "" {
		return errors.New("'url' must not be empty")
	}
	if server.Args == nil {
		return errors.New("'args' must be an array")
	}
	if server.EnvKeys == nil || hasDuplicates(server.EnvKeys) {
		return errors.New("'envKeys' must be a unique string array")
	}
	if server.HeaderKeys == nil || hasDuplicates(server.HeaderKeys) {
		return errors.New("'headerKeys' must be a unique string array")
	}
	for _, key := range append(append([]string{}, server.EnvKeys...), server.HeaderKeys...) {
		if strings.TrimSpace(key) == "" {
			return errors.New("env/header key names must not be empty")
		}
	}
	if !validSHA256(server.ConfigHash) {
		return fmt.Errorf("'configHash' must match sha256:<64 lowercase hex characters>")
	}
	seenTools := make(map[string]bool)
	if server.Tools == nil {
		return nil
	}
	for _, tool := range *server.Tools {
		if strings.TrimSpace(tool.Name) == "" {
			return errors.New("tool name must not be empty")
		}
		if seenTools[tool.Name] {
			return fmt.Errorf("duplicate tool %q", tool.Name)
		}
		seenTools[tool.Name] = true
		if !validSHA256(tool.DescriptionHash) || !validSHA256(tool.InputSchemaHash) {
			return fmt.Errorf("tool %q hashes must match sha256:<64 lowercase hex characters>", tool.Name)
		}
		if tool.Capabilities == nil || hasDuplicates(tool.Capabilities) {
			return fmt.Errorf("tool %q capabilities must be a unique string array", tool.Name)
		}
		for _, capability := range tool.Capabilities {
			if strings.TrimSpace(capability) == "" {
				return fmt.Errorf("tool %q capability names must not be empty", tool.Name)
			}
		}
		annotations := make([]string, 0, len(tool.Annotations))
		for annotation := range tool.Annotations {
			annotations = append(annotations, annotation)
		}
		sort.Strings(annotations)
		for _, annotation := range annotations {
			switch annotation {
			case "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint":
			default:
				return fmt.Errorf("tool %q has unknown annotation %q", tool.Name, annotation)
			}
		}
	}
	return nil
}

func hasDrivePrefix(value string) bool {
	return len(value) >= 2 && value[1] == ':'
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	if value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil && len(decoded) == 32
}

func decodeObject(data []byte) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := strictUnmarshal(data, &object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, errors.New("expected a JSON object")
	}
	return object, nil
}

func strictUnmarshal(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return errors.New("multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func onlyKeys(object map[string]json.RawMessage, allowed ...string) error {
	set := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		set[key] = true
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !set[key] {
			return fmt.Errorf("unknown field %q", key)
		}
	}
	return nil
}

func requireKeys(object map[string]json.RawMessage, required ...string) error {
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return fmt.Errorf("missing %q", key)
		}
	}
	return nil
}

func hasDuplicates(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if seen[value] {
			return true
		}
		seen[value] = true
	}
	return false
}

func sortedUnique(values []string) []string {
	if values == nil {
		return []string{}
	}
	result := make([]string, len(values))
	copy(result, values)
	sort.Strings(result)
	unique := result[:0]
	for _, value := range result {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	result := make([]string, len(values))
	copy(result, values)
	return result
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	result := make([]string, len(values))
	copy(result, values)
	return result
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
