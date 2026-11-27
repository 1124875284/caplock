// Package mcp implements the small JSON-RPC subset Caplock needs to capture an
// MCP server's tool manifest. It supports stdio and Streamable HTTP transports.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	// SupportedProtocolVersion is sent during initialization and negotiated down
	// to the version selected by the server.
	SupportedProtocolVersion = "2025-06-18"

	maxMessageBytes  = 16 << 20
	maxManifestBytes = 32 << 20
	maxTools         = 10_000
	maxPages         = 100
	maxToolNameSize  = 1_024
)

// Spec describes one MCP server connection. Secret values in Env and Headers
// must never be serialized or logged.
type Spec struct {
	Name      string
	Transport string
	Command   string
	Args      []string
	Dir       string
	Env       map[string]string
	URL       string
	Headers   map[string]string
}

// Tool is the MCP wire representation of a tool that Caplock normalizes before
// writing it to a lockfile.
type Tool struct {
	Name        string
	Description string
	InputSchema json.RawMessage
	Annotations Annotations
}

// Annotations are the optional MCP tool behavior hints. Pointers distinguish
// an absent hint from an explicit false value.
type Annotations struct {
	ReadOnlyHint    *bool
	DestructiveHint *bool
	IdempotentHint  *bool
	OpenWorldHint   *bool
}

// FetchTools connects to one server, initializes the session, and returns all
// tools across paginated tools/list responses.
func FetchTools(ctx context.Context, spec Spec) (tools []Tool, err error) {
	transport, err := newTransport(ctx, spec)
	if err != nil {
		return nil, err
	}
	client := rpcClient{transport: transport}
	defer func() {
		if closeErr := transport.close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	return client.fetchTools(ctx)
}

func newTransport(ctx context.Context, spec Spec) (rpcTransport, error) {
	switch strings.ToLower(strings.TrimSpace(spec.Transport)) {
	case "stdio":
		if strings.TrimSpace(spec.Command) == "" {
			return nil, errors.New("stdio transport requires a command")
		}
		if strings.TrimSpace(spec.URL) != "" {
			return nil, errors.New("stdio transport cannot use a URL")
		}
		return newStdioTransport(ctx, spec)
	case "http", "streamable-http", "streamable_http":
		if strings.TrimSpace(spec.URL) == "" {
			return nil, errors.New("HTTP transport requires a URL")
		}
		if strings.TrimSpace(spec.Command) != "" {
			return nil, errors.New("HTTP transport cannot use a command")
		}
		return newHTTPTransport(spec)
	default:
		return nil, fmt.Errorf("unsupported MCP transport %q", spec.Transport)
	}
}
