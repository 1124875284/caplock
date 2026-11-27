// Package config discovers and normalizes MCP client configuration files.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/caplock/caplock/internal/safefile"
)

const maxConfigBytes = 16 << 20

var configFilenames = map[string]bool{
	".mcp.json":                  true,
	"mcp.json":                   true,
	"mcp_config.json":            true,
	"claude_desktop_config.json": true,
}

var excludedDirs = map[string]bool{
	".git":          true,
	".hg":           true,
	".svn":          true,
	"__pycache__":   true,
	".mypy_cache":   true,
	".pytest_cache": true,
	".ruff_cache":   true,
	".venv":         true,
	"venv":          true,
	"node_modules":  true,
	"vendor":        true,
	"dist":          true,
	"build":         true,
}

// Server is one normalized MCP server entry from a client config file.
type Server struct {
	Name       string
	Source     string
	Transport  string
	Command    *string
	Args       []string
	URL        *string
	EnvKeys    []string
	HeaderKeys []string

	raw     map[string]any
	env     map[string]string
	headers map[string]string
}

// Project is the result of discovering and parsing all MCP configs under a path.
type Project struct {
	Root    string
	Configs []string
	Servers []Server
}

// LoadProject discovers known MCP config files and parses their servers. If path
// names a file, only that file is parsed and its parent directory is the project
// root. Static discovery never executes a configured command.
func LoadProject(path string) (*Project, error) {
	root, configs, err := discover(path)
	if err != nil {
		return nil, err
	}
	project := &Project{Root: root, Configs: make([]string, 0, len(configs))}
	seenServers := make(map[string]bool)
	for _, configPath := range configs {
		source, relErr := sourcePath(root, configPath)
		if relErr != nil {
			return nil, relErr
		}
		project.Configs = append(project.Configs, source)
		servers, parseErr := loadServers(configPath, source)
		if parseErr != nil {
			return nil, parseErr
		}
		for _, server := range servers {
			key := server.Source + "\x00" + server.Name
			if seenServers[key] {
				return nil, configError(configPath, "duplicate server %q in the same source", server.Name)
			}
			seenServers[key] = true
			project.Servers = append(project.Servers, server)
		}
	}
	sort.Strings(project.Configs)
	sort.Slice(project.Servers, func(i, j int) bool {
		if project.Servers[i].Name != project.Servers[j].Name {
			return project.Servers[i].Name < project.Servers[j].Name
		}
		return project.Servers[i].Source < project.Servers[j].Source
	})
	return project, nil
}

func discover(path string) (string, []string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", nil, configError(path, "cannot resolve path: %v", err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil, configError(path, "path does not exist")
		}
		return "", nil, configError(path, "cannot inspect path: %v", err)
	}
	if info.Mode().IsRegular() {
		return filepath.Dir(absolute), []string{absolute}, nil
	}
	if !info.IsDir() {
		return "", nil, configError(path, "path must be a directory or regular file")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", nil, configError(path, "cannot resolve directory symlinks: %v", err)
	}
	absolute = resolved

	var configs []string
	walkErr := filepath.WalkDir(absolute, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if current != absolute && excludedDirs[strings.ToLower(entry.Name())] {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() || !configFilenames[strings.ToLower(entry.Name())] {
			return nil
		}
		configs = append(configs, current)
		return nil
	})
	if walkErr != nil {
		return "", nil, configError(path, "cannot discover MCP configs: %v", walkErr)
	}
	sort.Strings(configs)
	return absolute, configs, nil
}

func sourcePath(root, configPath string) (string, error) {
	relative, err := filepath.Rel(root, configPath)
	if err != nil {
		return "", configError(configPath, "cannot make source path relative to project root: %v", err)
	}
	relative = filepath.ToSlash(filepath.Clean(relative))
	if relative == "." || relative == "" || relative == ".." || strings.HasPrefix(relative, "../") {
		return "", configError(configPath, "config is outside the project root")
	}
	return relative, nil
}

func loadServers(configPath, source string) ([]Server, error) {
	data, err := safefile.ReadFile(configPath, maxConfigBytes)
	if err != nil {
		return nil, configError(configPath, "cannot read config: %v", err)
	}
	parsed, err := parseJSONC(data)
	if err != nil {
		return nil, configError(configPath, "%v", err)
	}
	document, ok := parsed.(map[string]any)
	if !ok {
		return nil, configError(configPath, "expected a JSON object")
	}

	rawValue, exists := document["mcpServers"]
	if !exists || rawValue == nil {
		rawValue = document["servers"]
	}
	if rawValue == nil {
		return []Server{}, nil
	}
	rawServers, ok := rawValue.(map[string]any)
	if !ok {
		return nil, configError(configPath, "'mcpServers' or 'servers' must be an object")
	}

	names := make([]string, 0, len(rawServers))
	for name := range rawServers {
		names = append(names, name)
	}
	sort.Strings(names)
	servers := make([]Server, 0, len(names))
	for _, name := range names {
		rawServer, ok := rawServers[name].(map[string]any)
		if !ok {
			return nil, configError(configPath, "server %q must be an object", name)
		}
		server, err := parseServer(name, source, rawServer)
		if err != nil {
			return nil, configError(configPath, "server %q: %v", name, err)
		}
		servers = append(servers, server)
	}
	return servers, nil
}

func parseServer(name, source string, raw map[string]any) (Server, error) {
	if strings.TrimSpace(name) == "" {
		return Server{}, errors.New("name must not be empty")
	}
	transport := firstNonEmptyString(raw["type"], raw["transport"])
	if transport == "" {
		if _, ok := raw["url"].(string); ok {
			transport = "http"
		} else {
			transport = "stdio"
		}
	}
	command, err := optionalString(raw, "command")
	if err != nil {
		return Server{}, err
	}
	url, err := optionalString(raw, "url")
	if err != nil {
		return Server{}, err
	}
	if command == nil && url == nil {
		return Server{}, errors.New("one of 'command' or 'url' is required")
	}
	if command != nil && url != nil {
		return Server{}, errors.New("only one of 'command' or 'url' may be set")
	}

	args, err := parseArgs(raw["args"])
	if err != nil {
		return Server{}, err
	}
	env, envKeys, err := stringMap(raw, "env")
	if err != nil {
		return Server{}, err
	}
	headers, headerKeys, err := stringMap(raw, "headers")
	if err != nil {
		return Server{}, err
	}

	return Server{
		Name:       name,
		Source:     source,
		Transport:  transport,
		Command:    command,
		Args:       args,
		URL:        url,
		EnvKeys:    envKeys,
		HeaderKeys: headerKeys,
		raw:        cloneMap(raw),
		env:        env,
		headers:    headers,
	}, nil
}

func optionalString(raw map[string]any, key string) (*string, error) {
	value, exists := raw[key]
	if !exists || value == nil {
		return nil, nil
	}
	text, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("%q must be a string", key)
	}
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("%q must not be empty", key)
	}
	return &text, nil
}

func firstNonEmptyString(values ...any) string {
	for _, value := range values {
		if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
			return text
		}
	}
	return ""
}

func parseArgs(value any) ([]string, error) {
	args := []string{}
	if value == nil {
		return args, nil
	}
	values, ok := value.([]any)
	if !ok {
		return nil, errors.New("'args' must be an array of strings")
	}
	for _, item := range values {
		text, ok := item.(string)
		if !ok {
			return nil, errors.New("'args' must be an array of strings")
		}
		args = append(args, text)
	}
	return args, nil
}

func stringMap(raw map[string]any, key string) (map[string]string, []string, error) {
	value, exists := raw[key]
	if !exists || value == nil {
		return map[string]string{}, []string{}, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("%q must be an object", key)
	}
	values := make(map[string]string, len(object))
	keys := make([]string, 0, len(object))
	for name, rawValue := range object {
		if name == "" || strings.ContainsRune(name, '=') || containsControl(name) {
			return nil, nil, fmt.Errorf("%q contains an invalid key", key)
		}
		text, ok := rawValue.(string)
		if !ok {
			return nil, nil, fmt.Errorf("%q values must be strings", key)
		}
		if strings.ContainsRune(text, '\x00') {
			return nil, nil, fmt.Errorf("%q value for %q contains NUL", key, name)
		}
		values[name] = text
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return values, keys, nil
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func cloneMap(source map[string]any) map[string]any {
	cloned := make(map[string]any, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

// ConfigHash hashes the redacted server configuration. Secret rotation does not
// change the hash, while keys, commands, arguments, URLs, and other fields do.
func (s Server) ConfigHash() string {
	canonical, err := json.Marshal(redactSecrets(s.raw))
	if err != nil {
		// The input came from JSON and is therefore marshalable. Keep a stable
		// sentinel rather than panicking if a future decoder admits another type.
		canonical = []byte("<unmarshalable>")
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Environment returns a copy of the secret environment values supplied to a
// stdio server. Callers must not serialize or log the result.
func (s Server) Environment() map[string]string {
	return cloneStringMap(s.env)
}

// Headers returns a copy of the secret HTTP header values supplied to a remote
// MCP server. Callers must not serialize or log the result.
func (s Server) Headers() map[string]string {
	return cloneStringMap(s.headers)
}

func cloneStringMap(source map[string]string) map[string]string {
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func redactSecrets(raw map[string]any) map[string]any {
	redacted := cloneMap(raw)
	for _, key := range []string{"env", "headers"} {
		values, ok := redacted[key].(map[string]any)
		if !ok {
			continue
		}
		keys := make([]string, 0, len(values))
		for name := range values {
			keys = append(keys, name)
		}
		sort.Strings(keys)
		placeholder := make(map[string]any, len(keys))
		for _, name := range keys {
			placeholder[name] = "<redacted>"
		}
		redacted[key] = placeholder
	}
	return redacted
}
