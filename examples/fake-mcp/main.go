// Command fake-mcp is a dependency-free MCP stdio server used by Caplock's
// connected-mode example. It is intentionally small and deterministic.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

const protocolVersion = "2025-06-18"

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  struct {
		Cursor    string          `json:"cursor"`
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var message request
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			fmt.Fprintln(os.Stderr, "fake-mcp: invalid JSON-RPC message")
			os.Exit(1)
		}
		switch message.Method {
		case "initialize":
			writeResult(encoder, message.ID, map[string]any{
				"protocolVersion": protocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]string{"name": "caplock-fake-mcp", "version": "1"},
			})
		case "notifications/initialized":
		case "tools/list":
			if message.Params.Cursor == "" {
				writeResult(encoder, message.ID, map[string]any{
					"tools": []map[string]any{
						{
							"name":        "read_file",
							"description": "Read a file from the workspace",
							"inputSchema": map[string]any{
								"type":       "object",
								"properties": map[string]any{"path": map[string]any{"type": "string"}},
								"required":   []string{"path"},
							},
							"annotations": map[string]bool{"readOnlyHint": true},
						},
					},
					"nextCursor": "page-2",
				})
				continue
			}
			writeResult(encoder, message.ID, map[string]any{
				"tools": []map[string]any{
					{
						"name":        "send_email",
						"description": "Send an email to an external recipient",
						"inputSchema": map[string]any{
							"type":       "object",
							"properties": map[string]any{"to": map[string]any{"type": "string"}, "body": map[string]any{"type": "string"}},
							"required":   []string{"to", "body"},
						},
					},
					{
						"name":        "delete_repository",
						"description": "Permanently delete a repository",
						"inputSchema": map[string]any{
							"type":       "object",
							"properties": map[string]any{"repository": map[string]any{"type": "string"}},
							"required":   []string{"repository"},
						},
						"annotations": map[string]bool{"destructiveHint": true},
					},
				},
			})
		case "tools/call":
			if message.Params.Name == "" {
				writeError(encoder, message.ID, -32602, "tool name is required")
				continue
			}
			text := callText(message.Params.Name, message.Params.Arguments)
			writeResult(encoder, message.ID, map[string]any{
				"content": []map[string]string{{"type": "text", "text": text}},
				"isError": false,
			})
		default:
			writeError(encoder, message.ID, -32601, "method not found")
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "fake-mcp: cannot read stdin")
		os.Exit(1)
	}
}

func writeResult(encoder *json.Encoder, id json.RawMessage, result any) {
	if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result}); err != nil {
		os.Exit(1)
	}
}

func writeError(encoder *json.Encoder, id json.RawMessage, code int, message string) {
	if err := encoder.Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": message},
	}); err != nil {
		os.Exit(1)
	}
}

func callText(name string, raw json.RawMessage) string {
	arguments := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &arguments)
	}
	switch name {
	case "read_file":
		return fmt.Sprintf("read %v", arguments["path"])
	case "send_email":
		return fmt.Sprintf("send_email demo accepted for %v", arguments["to"])
	case "delete_repository":
		return fmt.Sprintf("delete_repository demo accepted for %v", arguments["repository"])
	default:
		return fmt.Sprintf("called %s", name)
	}
}
