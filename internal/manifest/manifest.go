// Package manifest normalizes MCP tools into deterministic lockfile entries.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/1124875284/caplock/internal/inventory"
	"github.com/1124875284/caplock/internal/lockfile"
	"github.com/1124875284/caplock/internal/mcp"
)

// Build hashes and classifies a connected server's MCP tools without retaining
// descriptions or input schemas in the lockfile.
func Build(tools []mcp.Tool) ([]lockfile.Tool, error) {
	result := make([]lockfile.Tool, 0, len(tools))
	seen := make(map[string]bool, len(tools))
	for _, tool := range tools {
		if seen[tool.Name] {
			return nil, fmt.Errorf("MCP server returned duplicate tool %q", tool.Name)
		}
		seen[tool.Name] = true
		schemaHash, err := hashSchema(tool.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("tool %q: %w", tool.Name, err)
		}
		annotations := presentAnnotations(tool.Annotations)
		result = append(result, lockfile.Tool{
			Name:            tool.Name,
			DescriptionHash: hashString(tool.Description),
			InputSchemaHash: schemaHash,
			Annotations:     annotations,
			Capabilities:    inventory.Classify(tool.Name, tool.Description, annotations),
		})
	}
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result, nil
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func hashSchema(raw json.RawMessage) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var schema any
	if err := decoder.Decode(&schema); err != nil {
		return "", errors.New("inputSchema is not valid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return "", errors.New("inputSchema contains multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return "", errors.New("inputSchema contains trailing data")
	}
	if _, ok := schema.(map[string]any); !ok {
		return "", errors.New("inputSchema must be a JSON object")
	}
	canonical, err := json.Marshal(schema)
	if err != nil {
		return "", errors.New("inputSchema cannot be normalized")
	}
	return hashString(string(canonical)), nil
}

func presentAnnotations(annotations mcp.Annotations) map[string]bool {
	result := make(map[string]bool)
	if annotations.ReadOnlyHint != nil {
		result["readOnlyHint"] = *annotations.ReadOnlyHint
	}
	if annotations.DestructiveHint != nil {
		result["destructiveHint"] = *annotations.DestructiveHint
	}
	if annotations.IdempotentHint != nil {
		result["idempotentHint"] = *annotations.IdempotentHint
	}
	if annotations.OpenWorldHint != nil {
		result["openWorldHint"] = *annotations.OpenWorldHint
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
