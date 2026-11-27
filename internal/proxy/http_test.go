package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/1124875284/caplock/internal/trace"
)

type capturedRequest struct {
	method string
	body   string
	header http.Header
}

func newTestTarget(t *testing.T) (*httptest.Server, *[]capturedRequest, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var requests []capturedRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		mu.Lock()
		requests = append(requests, capturedRequest{method: request.Method, body: string(body), header: request.Header.Clone()})
		mu.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet {
			writer.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(writer, "data: ok\n\n")
			return
		}
		var message struct {
			ID json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(body, &message)
		if len(message.ID) == 0 || bytes.Equal(message.ID, []byte("null")) {
			writer.WriteHeader(http.StatusAccepted)
			return
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      message.ID,
			"result":  map[string]any{"forwarded": true},
		})
	}))
	return server, &requests, &mu
}

func newTestProxy(t *testing.T, target *httptest.Server, audit io.Writer, traceWriters ...io.Writer) *httptest.Server {
	t.Helper()
	parsed, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	options := HTTPOptions{Engine: testEngine(t, ApprovalBlock, nil), Target: parsed}
	if audit != nil {
		options.Audit = NewJSONLAudit(audit).Write
	}
	if len(traceWriters) > 0 && traceWriters[0] != nil {
		options.Trace = trace.NewJSONLWriter(traceWriters[0]).Write
		options.TraceArguments = true
	}
	handler, err := NewHTTPHandler(options)
	if err != nil {
		t.Fatalf("NewHTTPHandler() error = %v", err)
	}
	return httptest.NewServer(handler)
}

func postJSON(t *testing.T, endpoint, body string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return response, data
}

func TestHTTPProxyForwardsAllowedCallAndHeaders(t *testing.T) {
	target, requests, mu := newTestTarget(t)
	defer target.Close()
	var audit bytes.Buffer
	front := newTestProxy(t, target, &audit)
	defer front.Close()

	response, body := postJSON(t, front.URL, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/a"}}}`, map[string]string{
		"Mcp-Session-Id":       "session-123",
		"MCP-Protocol-Version": "2025-06-18",
	})
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"forwarded":true`) {
		t.Fatalf("status = %d, body = %s", response.StatusCode, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*requests) != 1 {
		t.Fatalf("target requests = %d", len(*requests))
	}
	request := (*requests)[0]
	if request.header.Get("Mcp-Session-Id") != "session-123" || request.header.Get("MCP-Protocol-Version") != "2025-06-18" {
		t.Fatalf("headers = %#v", request.header)
	}
	if !strings.Contains(audit.String(), `"tool":"read_file"`) || !strings.Contains(audit.String(), `"forwarded":true`) {
		t.Fatalf("audit = %s", audit.String())
	}
	if strings.Contains(audit.String(), "/workspace/a") {
		t.Fatalf("audit leaked arguments: %s", audit.String())
	}
}

func TestHTTPProxyBlocksApprovalCallWithoutForwarding(t *testing.T) {
	target, requests, mu := newTestTarget(t)
	defer target.Close()
	var audit bytes.Buffer
	front := newTestProxy(t, target, &audit)
	defer front.Close()

	response, body := postJSON(t, front.URL, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"outside@example.com"}}}`, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.StatusCode, body)
	}
	if response.Header.Get("X-Caplock-Decision") != "require_approval" {
		t.Fatalf("decision header = %q", response.Header.Get("X-Caplock-Decision"))
	}
	if !strings.Contains(string(body), `"code":-32001`) {
		t.Fatalf("body = %s", body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*requests) != 0 {
		t.Fatalf("blocked request reached target: %#v", *requests)
	}
	if strings.Contains(audit.String(), "outside@example.com") {
		t.Fatalf("audit leaked arguments: %s", audit.String())
	}
}

func TestHTTPProxyPassesThroughNonToolsCallsAndGET(t *testing.T) {
	target, requests, mu := newTestTarget(t)
	defer target.Close()
	front := newTestProxy(t, target, nil)
	defer front.Close()

	if response, body := postJSON(t, front.URL, `{"jsonrpc":"2.0","id":3,"method":"initialize","params":{}}`, nil); response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"forwarded":true`) {
		t.Fatalf("initialize status = %d, body = %s", response.StatusCode, body)
	}
	response, err := http.Get(front.URL + "/sse")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	data, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(data), "data: ok") {
		t.Fatalf("GET status = %d, body = %s", response.StatusCode, data)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*requests) != 2 || (*requests)[0].method != http.MethodPost || (*requests)[1].method != http.MethodGet {
		t.Fatalf("requests = %#v", *requests)
	}
}

func TestHTTPProxyRejectsInvalidInputWithoutForwarding(t *testing.T) {
	target, requests, mu := newTestTarget(t)
	defer target.Close()
	front := newTestProxy(t, target, nil)
	defer front.Close()

	cases := []struct {
		name string
		body string
		code int
		text string
	}{
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}]`, http.StatusBadRequest, "batch"},
		{"parse", `{`, http.StatusBadRequest, "parse error"},
		{"params", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":[]}}`, http.StatusBadRequest, "invalid tools/call params"},
		{"envelope", `{"jsonrpc":"1.0","id":5,"method":"tools/call","params":{"name":"read_file"}}`, http.StatusBadRequest, "invalid JSON-RPC request"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			response, body := postJSON(t, front.URL, testCase.body, nil)
			if response.StatusCode != testCase.code || !strings.Contains(string(body), testCase.text) {
				t.Fatalf("status = %d, body = %s", response.StatusCode, body)
			}
		})
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*requests) != 0 {
		t.Fatalf("invalid requests reached target: %#v", *requests)
	}
}

func TestHTTPProxyRejectsOversizedBody(t *testing.T) {
	target, requests, mu := newTestTarget(t)
	defer target.Close()
	parsed, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	handler, err := NewHTTPHandler(HTTPOptions{Engine: testEngine(t, ApprovalBlock, nil), Target: parsed, MaxBodyBytes: 16})
	if err != nil {
		t.Fatalf("NewHTTPHandler() error = %v", err)
	}
	front := httptest.NewServer(handler)
	defer front.Close()
	response, body := postJSON(t, front.URL, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, nil)
	if response.StatusCode != http.StatusRequestEntityTooLarge || !strings.Contains(string(body), "message size limit") {
		t.Fatalf("status = %d, body = %s", response.StatusCode, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*requests) != 0 {
		t.Fatalf("oversized request reached target: %#v", *requests)
	}
}

func TestHTTPProxyAuditFailureFailsClosed(t *testing.T) {
	target, requests, mu := newTestTarget(t)
	defer target.Close()
	parsed, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	handler, err := NewHTTPHandler(HTTPOptions{
		Engine: testEngine(t, ApprovalBlock, nil),
		Target: parsed,
		Audit: func(AuditRecord) error {
			return io.ErrClosedPipe
		},
	})
	if err != nil {
		t.Fatalf("NewHTTPHandler() error = %v", err)
	}
	front := httptest.NewServer(handler)
	defer front.Close()
	response, body := postJSON(t, front.URL, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"read_file"}}`, nil)
	if response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "audit unavailable") {
		t.Fatalf("status = %d, body = %s", response.StatusCode, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*requests) != 0 {
		t.Fatalf("request with failed audit reached target: %#v", *requests)
	}
}

func TestHTTPProxyUpstreamFailureIsSanitized(t *testing.T) {
	target, _, _ := newTestTarget(t)
	parsed, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	target.Close()
	handler, err := NewHTTPHandler(HTTPOptions{Engine: testEngine(t, ApprovalBlock, nil), Target: parsed})
	if err != nil {
		t.Fatalf("NewHTTPHandler() error = %v", err)
	}
	front := httptest.NewServer(handler)
	defer front.Close()
	response, body := postJSON(t, front.URL, `{"jsonrpc":"2.0","id":7,"method":"initialize"}`, nil)
	if response.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "upstream MCP server unavailable") {
		t.Fatalf("status = %d, body = %s", response.StatusCode, body)
	}
}

func TestHTTPProxyDoesNotForwardBatch(t *testing.T) {
	var counter atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		counter.Add(1)
		writer.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	front := newTestProxy(t, target, nil)
	defer front.Close()
	_, _ = postJSON(t, front.URL, `[{"jsonrpc":"2.0","id":1,"method":"initialize"}]`, nil)
	if counter.Load() != 0 {
		t.Fatalf("batch request reached target %d times", counter.Load())
	}
}
