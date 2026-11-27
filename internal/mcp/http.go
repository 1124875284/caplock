package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/1124875284/caplock/internal/version"
)

type httpTransport struct {
	client          *http.Client
	endpoint        *url.URL
	headers         http.Header
	protocolVersion string

	mu        sync.RWMutex
	sessionID string
}

func newHTTPTransport(spec Spec) (*httpTransport, error) {
	endpoint, err := url.Parse(strings.TrimSpace(spec.URL))
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return nil, errors.New("HTTP transport requires an absolute http or https URL")
	}
	if endpoint.User != nil {
		return nil, errors.New("HTTP transport URL must not contain user credentials")
	}
	if endpoint.Fragment != "" {
		return nil, errors.New("HTTP transport URL must not contain a fragment")
	}
	headers, err := validateHeaders(spec.Headers)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          4,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &httpTransport{client: client, endpoint: endpoint, headers: headers}, nil
}

func (t *httpTransport) call(ctx context.Context, id int64, method string, params any) (json.RawMessage, error) {
	request := rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params}
	response, err := t.post(ctx, request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return nil, fmt.Errorf("MCP HTTP server returned status %d", response.StatusCode)
	}
	if err := t.captureSession(response); err != nil {
		return nil, err
	}

	mediaType, _, parseErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if parseErr != nil && response.Header.Get("Content-Type") != "" {
		return nil, errors.New("MCP HTTP server returned an invalid content type")
	}
	switch mediaType {
	case "", "application/json":
		return decodeJSONResponse(response.Body, id)
	case "text/event-stream":
		return decodeSSEResponse(response.Body, id)
	default:
		return nil, errors.New("MCP HTTP server returned an unsupported content type")
	}
}

func (t *httpTransport) notify(ctx context.Context, method string, params any) error {
	request := rpcRequest{JSONRPC: "2.0", Method: method, Params: params}
	response, err := t.post(ctx, request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if err := t.captureSession(response); err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("MCP HTTP server returned status %d", response.StatusCode)
	}
	return nil
}

func (t *httpTransport) post(ctx context.Context, request rpcRequest) (*http.Response, error) {
	data, err := json.Marshal(request)
	if err != nil {
		return nil, errors.New("encode MCP HTTP request")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("create MCP HTTP request")
	}
	for name, values := range t.headers {
		for _, value := range values {
			httpRequest.Header.Add(name, value)
		}
	}
	httpRequest.Header.Set("Accept", "application/json, text/event-stream")
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("User-Agent", "caplock/"+version.Version)
	t.mu.RLock()
	sessionID := t.sessionID
	protocolVersion := t.protocolVersion
	t.mu.RUnlock()
	if sessionID != "" {
		httpRequest.Header.Set("Mcp-Session-Id", sessionID)
	}
	if protocolVersion != "" {
		httpRequest.Header.Set("MCP-Protocol-Version", protocolVersion)
	}
	response, err := t.client.Do(httpRequest)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("MCP HTTP request to %s was canceled", t.endpoint.Host)
		}
		return nil, fmt.Errorf("MCP HTTP request to %s failed", t.endpoint.Host)
	}
	return response, nil
}

func (t *httpTransport) setProtocolVersion(protocolVersion string) {
	t.mu.Lock()
	t.protocolVersion = protocolVersion
	t.mu.Unlock()
}

func (t *httpTransport) captureSession(response *http.Response) error {
	sessionID := response.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		return nil
	}
	if len(sessionID) > 1_024 || !validHeaderValue(sessionID) {
		return errors.New("MCP HTTP server returned an invalid session ID")
	}
	t.mu.Lock()
	t.sessionID = sessionID
	t.mu.Unlock()
	return nil
}

func (t *httpTransport) close() error {
	t.client.CloseIdleConnections()
	return nil
}

func decodeJSONResponse(body io.Reader, id int64) (json.RawMessage, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxMessageBytes+1))
	if err != nil {
		return nil, errors.New("read MCP HTTP response")
	}
	if len(data) > maxMessageBytes {
		return nil, fmt.Errorf("MCP HTTP response exceeds %d bytes", maxMessageBytes)
	}
	result, err := decodeResponse(data, id)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("MCP HTTP response did not contain the requested result")
	}
	return result, nil
}

func decodeSSEResponse(body io.Reader, id int64) (json.RawMessage, error) {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 64*1024), maxMessageBytes)
	var dataLines []string
	total := 0
	dispatch := func() (json.RawMessage, bool, error) {
		if len(dataLines) == 0 {
			return nil, false, nil
		}
		data := strings.Join(dataLines, "\n")
		dataLines = dataLines[:0]
		result, err := decodeResponse([]byte(data), id)
		if err != nil {
			return nil, false, err
		}
		if result == nil {
			return nil, false, nil
		}
		return result, true, nil
	}

	for scanner.Scan() {
		line := scanner.Text()
		total += len(line) + 1
		if total > maxMessageBytes {
			return nil, fmt.Errorf("MCP SSE response exceeds %d bytes", maxMessageBytes)
		}
		if line == "" {
			result, found, err := dispatch()
			if err != nil {
				return nil, err
			}
			if found {
				return result, nil
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			field = line
			value = ""
		}
		value = strings.TrimPrefix(value, " ")
		if field == "data" {
			dataLines = append(dataLines, value)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("read MCP SSE response")
	}
	result, found, err := dispatch()
	if err != nil {
		return nil, err
	}
	if found {
		return result, nil
	}
	return nil, errors.New("MCP SSE stream ended before the requested result")
}

func validateHeaders(values map[string]string) (http.Header, error) {
	headers := make(http.Header, len(values))
	for name, value := range values {
		if !validHeaderName(name) {
			return nil, errors.New("MCP HTTP config contains an invalid header name")
		}
		if !validHeaderValue(value) {
			return nil, fmt.Errorf("MCP HTTP header %q contains an invalid value", name)
		}
		switch http.CanonicalHeaderKey(name) {
		case "Accept", "Content-Type", "User-Agent", "Mcp-Session-Id", "Mcp-Protocol-Version":
			continue
		default:
			headers.Set(name, value)
		}
	}
	return headers, nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
			continue
		}
		switch character {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func validHeaderValue(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == '\t' {
			continue
		}
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
