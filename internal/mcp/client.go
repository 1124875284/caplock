package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/caplock/caplock/internal/version"
)

type rpcTransport interface {
	call(ctx context.Context, id int64, method string, params any) (json.RawMessage, error)
	notify(ctx context.Context, method string, params any) error
	setProtocolVersion(version string)
	close() error
}

type rpcClient struct {
	transport rpcTransport
	nextID    int64
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int64  `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

type rpcError struct {
	Code int `json:"code"`
}

type initializeResult struct {
	ProtocolVersion string `json:"protocolVersion"`
}

type listToolsResult struct {
	Tools      []wireTool `json:"tools"`
	NextCursor string     `json:"nextCursor"`
}

type wireTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations struct {
		ReadOnlyHint    *bool `json:"readOnlyHint"`
		DestructiveHint *bool `json:"destructiveHint"`
		IdempotentHint  *bool `json:"idempotentHint"`
		OpenWorldHint   *bool `json:"openWorldHint"`
	} `json:"annotations"`
}

func (c *rpcClient) fetchTools(ctx context.Context) ([]Tool, error) {
	result, err := c.call(ctx, "initialize", map[string]any{
		"protocolVersion": SupportedProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]string{
			"name":    "caplock",
			"version": version.Version,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize MCP session: %w", err)
	}
	var initialized initializeResult
	if err := json.Unmarshal(result, &initialized); err != nil {
		return nil, errors.New("server returned an invalid initialize result")
	}
	if strings.TrimSpace(initialized.ProtocolVersion) == "" || len(initialized.ProtocolVersion) > 64 || !validHeaderValue(initialized.ProtocolVersion) {
		return nil, errors.New("server did not select a valid MCP protocol version")
	}
	c.transport.setProtocolVersion(initialized.ProtocolVersion)
	if err := c.transport.notify(ctx, "notifications/initialized", map[string]any{}); err != nil {
		return nil, fmt.Errorf("send initialized notification: %w", err)
	}

	allTools := make([]Tool, 0)
	manifestBytes := 0
	seenCursors := make(map[string]bool)
	cursor := ""
	for page := 1; ; page++ {
		if page > maxPages {
			return nil, fmt.Errorf("server exceeded the %d-page tools/list limit", maxPages)
		}
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		rawResult, err := c.call(ctx, "tools/list", params)
		if err != nil {
			return nil, fmt.Errorf("list MCP tools: %w", err)
		}
		var listed listToolsResult
		if err := json.Unmarshal(rawResult, &listed); err != nil {
			return nil, errors.New("server returned an invalid tools/list result")
		}
		for _, item := range listed.Tools {
			if err := validateTool(item); err != nil {
				return nil, err
			}
			manifestBytes += len(item.Name) + len(item.Description) + len(item.InputSchema)
			if manifestBytes > maxManifestBytes {
				return nil, fmt.Errorf("server tool manifest exceeds %d bytes", maxManifestBytes)
			}
			if len(allTools) >= maxTools {
				return nil, fmt.Errorf("server exceeded the %d-tool limit", maxTools)
			}
			allTools = append(allTools, Tool{
				Name:        item.Name,
				Description: item.Description,
				InputSchema: item.InputSchema,
				Annotations: Annotations{
					ReadOnlyHint:    item.Annotations.ReadOnlyHint,
					DestructiveHint: item.Annotations.DestructiveHint,
					IdempotentHint:  item.Annotations.IdempotentHint,
					OpenWorldHint:   item.Annotations.OpenWorldHint,
				},
			})
		}
		if listed.NextCursor == "" {
			return allTools, nil
		}
		if seenCursors[listed.NextCursor] {
			return nil, errors.New("server repeated a tools/list cursor")
		}
		seenCursors[listed.NextCursor] = true
		cursor = listed.NextCursor
	}
}

func validateTool(tool wireTool) error {
	if strings.TrimSpace(tool.Name) == "" {
		return errors.New("server returned a tool with an empty name")
	}
	if len(tool.Name) > maxToolNameSize {
		return fmt.Errorf("server returned a tool name longer than %d bytes", maxToolNameSize)
	}
	if strings.ContainsRune(tool.Name, '\x00') {
		return errors.New("server returned a tool name containing NUL")
	}
	if len(tool.InputSchema) == 0 || string(tool.InputSchema) == "null" {
		return fmt.Errorf("tool %q has no input schema", tool.Name)
	}
	return nil
}

func (c *rpcClient) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.nextID++
	return c.transport.call(ctx, c.nextID, method, params)
}
