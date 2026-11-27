package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFetchToolsStdio(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tools, err := FetchTools(ctx, Spec{
		Name:      "helper",
		Transport: "stdio",
		Command:   executable,
		Args:      []string{"-test.run=^TestStdioHelperProcess$"},
		Env: map[string]string{
			"CAPLOCK_MCP_HELPER":         "1",
			"CAPLOCK_HELPER_DESCRIPTION": "Read a file",
		},
	})
	if err != nil {
		t.Fatalf("FetchTools() error = %v", err)
	}
	if got, want := len(tools), 2; got != want {
		t.Fatalf("tool count = %d, want %d", got, want)
	}
	if got, want := tools[0].Name, "read_file"; got != want {
		t.Fatalf("first tool = %q, want %q", got, want)
	}
	if got, want := tools[0].Description, "Read a file"; got != want {
		t.Fatalf("description = %q, want %q", got, want)
	}
	if got, want := tools[1].Name, "send_email"; got != want {
		t.Fatalf("second tool = %q, want %q", got, want)
	}
	if tools[0].Annotations.ReadOnlyHint == nil || !*tools[0].Annotations.ReadOnlyHint {
		t.Fatalf("readOnlyHint was not captured: %#v", tools[0].Annotations)
	}
}

func TestDecodeSSEResponse(t *testing.T) {
	stream := strings.NewReader(": keepalive\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"tools\":[]}}\n\n")
	result, err := decodeSSEResponse(stream, 7)
	if err != nil {
		t.Fatalf("decodeSSEResponse() error = %v", err)
	}
	if got, want := string(result), `{"tools":[]}`; got != want {
		t.Fatalf("result = %q, want %q", got, want)
	}
}

func TestFetchToolsHTTPEventStream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var payload struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		switch payload.Method {
		case "initialize":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(writer, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":%q}}`, payload.ID, SupportedProtocolVersion)
		case "notifications/initialized":
			writer.WriteHeader(http.StatusAccepted)
		case "tools/list":
			writer.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(writer, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"tools\":[{\"name\":\"read_file\",\"inputSchema\":{\"type\":\"object\"}}]}}\n\n", payload.ID)
		default:
			http.Error(writer, "unknown method", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	tools, err := FetchTools(context.Background(), Spec{Transport: "http", URL: server.URL})
	if err != nil {
		t.Fatalf("FetchTools() error = %v", err)
	}
	if got, want := len(tools), 1; got != want {
		t.Fatalf("tool count = %d, want %d", got, want)
	}
	if got, want := tools[0].Name, "read_file"; got != want {
		t.Fatalf("tool name = %q, want %q", got, want)
	}
}

func TestFetchToolsRejectsUnsupportedTransport(t *testing.T) {
	_, err := FetchTools(context.Background(), Spec{Transport: "sse", URL: "http://example.com"})
	if err == nil || !strings.Contains(err.Error(), "unsupported MCP transport") {
		t.Fatalf("FetchTools() error = %v", err)
	}
}

func TestStdioHelperProcess(_ *testing.T) {
	if os.Getenv("CAPLOCK_MCP_HELPER") != "1" {
		return
	}
	serveStdioHelper()
	os.Exit(0)
}

func serveStdioHelper() {
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var request struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			os.Exit(2)
		}
		switch request.Method {
		case "initialize":
			_ = encoder.Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      request.ID,
				"result": map[string]any{
					"protocolVersion": SupportedProtocolVersion,
					"capabilities":    map[string]any{},
					"serverInfo":      map[string]string{"name": "helper", "version": "1"},
				},
			})
		case "notifications/initialized":
		case "tools/list":
			if request.Params.Cursor == "" {
				_ = encoder.Encode(map[string]any{
					"jsonrpc": "2.0",
					"id":      request.ID,
					"result": map[string]any{
						"tools": []map[string]any{{
							"name":        "read_file",
							"description": os.Getenv("CAPLOCK_HELPER_DESCRIPTION"),
							"inputSchema": map[string]any{"type": "object"},
							"annotations": map[string]bool{"readOnlyHint": true},
						}},
						"nextCursor": "next",
					},
				})
				continue
			}
			_ = encoder.Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      request.ID,
				"result": map[string]any{
					"tools": []map[string]any{{
						"name":        "send_email",
						"description": "Send mail",
						"inputSchema": map[string]any{"type": "object"},
					}},
				},
			})
		default:
			_ = encoder.Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      request.ID,
				"error":   map[string]any{"code": -32601, "message": "method not found"},
			})
		}
	}
}

func FuzzDecodeResponse(f *testing.F) {
	for _, seed := range []string{
		`{"jsonrpc":"2.0","id":1,"result":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/progress"}`,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}`,
		`null`,
		`{`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, input string) {
		_, _ = decodeResponse([]byte(input), 1)
	})
}
