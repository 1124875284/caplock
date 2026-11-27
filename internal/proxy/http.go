package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultMaxBodyBytes bounds one HTTP JSON-RPC request body.
	DefaultMaxBodyBytes int64 = 8 << 20
	// DefaultListen is the loopback-only default HTTP proxy address.
	DefaultListen = "127.0.0.1:8787"
)

// HTTPOptions configures the Streamable HTTP proxy handler.
type HTTPOptions struct {
	Engine         *Engine
	Audit          AuditFunc
	Trace          TraceFunc
	Alert          AlertFunc
	TraceArguments bool
	Target         *url.URL
	Diagnostics    io.Writer
	MaxBodyBytes   int64
}

// NewHTTPHandler builds a reverse proxy that intercepts JSON-RPC tools/call
// requests. Non-POST methods and non-tools/call POSTs pass through unchanged.
func NewHTTPHandler(options HTTPOptions) (http.Handler, error) {
	if options.Engine == nil {
		return nil, errors.New("engine is required")
	}
	if options.Target == nil {
		return nil, errors.New("target URL is required")
	}
	if options.Target.Scheme != "http" && options.Target.Scheme != "https" {
		return nil, fmt.Errorf("target URL must use http or https, got %q", options.Target.Scheme)
	}
	if options.Target.Host == "" {
		return nil, errors.New("target URL must include a host")
	}
	if options.MaxBodyBytes <= 0 {
		options.MaxBodyBytes = DefaultMaxBodyBytes
	}
	reverse := httputil.NewSingleHostReverseProxy(options.Target)
	reverse.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, _ error) {
		writeHTTPRPCError(writer, http.StatusBadGateway, nil, -32603, "upstream MCP server unavailable", nil)
	}
	return &httpHandler{
		engine:         options.Engine,
		audit:          options.Audit,
		trace:          options.Trace,
		alert:          options.Alert,
		traceArguments: options.TraceArguments,
		reverse:        reverse,
		diagnostics:    options.Diagnostics,
		maxBodyBytes:   options.MaxBodyBytes,
	}, nil
}

type httpHandler struct {
	engine         *Engine
	audit          AuditFunc
	trace          TraceFunc
	alert          AlertFunc
	traceArguments bool
	reverse        *httputil.ReverseProxy
	diagnostics    io.Writer
	maxBodyBytes   int64
}

func (h *httpHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		h.reverse.ServeHTTP(writer, request)
		return
	}
	body, tooLarge, err := readHTTPBody(request.Body, h.maxBodyBytes)
	if tooLarge {
		writeHTTPRPCError(writer, http.StatusRequestEntityTooLarge, nil, -32600, "request body exceeds the message size limit", nil)
		return
	}
	if err != nil {
		writeHTTPRPCError(writer, http.StatusBadRequest, nil, -32700, "cannot read request body", nil)
		return
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		h.forward(writer, request, body)
		return
	}
	if trimmed[0] == '[' {
		writeHTTPRPCError(writer, http.StatusBadRequest, nil, -32600, "batch JSON-RPC requests are not supported", nil)
		return
	}
	var message rpcMessage
	if err := json.Unmarshal(trimmed, &message); err != nil {
		writeHTTPRPCError(writer, http.StatusBadRequest, nil, -32700, "parse error", nil)
		return
	}
	if message.Method != "tools/call" {
		h.forward(writer, request, body)
		return
	}

	id, valid := normalizeID(message.ID)
	if message.JSONRPC != "2.0" || !valid {
		decision := InvalidDecision("", "invalid tools/call envelope")
		if auditErr := h.writeAudit(decision); auditErr != nil {
			h.auditFailure(writer, http.StatusServiceUnavailable, id)
			return
		}
		writeHTTPRPCError(writer, http.StatusBadRequest, id, -32600, "invalid JSON-RPC request", nil)
		return
	}
	params, err := parseCallParams(message.Params)
	if err != nil {
		decision := InvalidDecision(params.Name, "invalid tools/call params")
		if auditErr := h.writeAudit(decision); auditErr != nil {
			h.auditFailure(writer, http.StatusServiceUnavailable, id)
			return
		}
		writeHTTPRPCError(writer, http.StatusBadRequest, id, -32602, "invalid tools/call params", nil)
		return
	}
	decision, err := h.engine.Decide(params.Name, params.Arguments)
	if err != nil {
		logDiagnostic(h.diagnostics, "policy evaluation failed")
		invalid := InvalidDecision(params.Name, "policy evaluation failed")
		if auditErr := h.writeAudit(invalid); auditErr != nil {
			h.auditFailure(writer, http.StatusServiceUnavailable, id)
			return
		}
		writeHTTPRPCError(writer, http.StatusInternalServerError, id, -32603, "policy evaluation failed", nil)
		return
	}
	if err := h.writeTrace(decision, params.Arguments); err != nil {
		h.traceFailure(writer, http.StatusServiceUnavailable, id)
		return
	}
	if err := h.writeAudit(decision); err != nil {
		h.auditFailure(writer, http.StatusServiceUnavailable, id)
		return
	}
	if err := h.writeAlert(decision); err != nil {
		h.alertFailure(writer, http.StatusServiceUnavailable, id)
		return
	}
	if !decision.Forward {
		writer.Header().Set("X-Caplock-Decision", decision.Policy.Effect)
		writeHTTPRPCError(writer, http.StatusOK, id, -32001, "caplock: "+decision.Reason, policyErrorData(decision))
		return
	}
	if decision.ForwardArguments != nil {
		rewritten, err := rewriteHTTPCallArguments(body, decision.ForwardArguments)
		if err != nil {
			logDiagnostic(h.diagnostics, "redacted argument rewrite failed; blocking request")
			writeHTTPRPCError(writer, http.StatusInternalServerError, id, -32603, "argument redaction failed; request blocked", nil)
			return
		}
		body = rewritten
	}
	h.forward(writer, request, body)
}

func rewriteHTTPCallArguments(body []byte, arguments map[string]any) ([]byte, error) {
	var message map[string]any
	if err := json.Unmarshal(body, &message); err != nil {
		return nil, err
	}
	params, ok := message["params"].(map[string]any)
	if !ok {
		return nil, errors.New("tools/call params is not an object")
	}
	params["arguments"] = arguments
	message["params"] = params
	return json.Marshal(message)
}

func (h *httpHandler) forward(writer http.ResponseWriter, request *http.Request, body []byte) {
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	h.reverse.ServeHTTP(writer, request)
}

func (h *httpHandler) writeTrace(decision Decision, arguments map[string]any) error {
	if h.trace == nil {
		return nil
	}
	return h.trace(h.engine.TraceRecord(decision, arguments, h.traceArguments))
}

func (h *httpHandler) writeAudit(decision Decision) error {
	if h.audit == nil {
		return nil
	}
	return h.audit(h.engine.Record(decision))
}

func (h *httpHandler) writeAlert(decision Decision) error {
	if h.alert == nil || !contains(decision.Policy.Obligations, "alert") {
		return nil
	}
	return h.alert(h.engine.Alert(decision))
}

func (h *httpHandler) traceFailure(writer http.ResponseWriter, status int, id json.RawMessage) {
	logDiagnostic(h.diagnostics, "trace write failed; blocking request")
	writeHTTPRPCError(writer, status, id, -32603, "trace unavailable; request blocked", nil)
}

func (h *httpHandler) auditFailure(writer http.ResponseWriter, status int, id json.RawMessage) {
	logDiagnostic(h.diagnostics, "audit write failed; blocking request")
	writeHTTPRPCError(writer, status, id, -32603, "audit unavailable; request blocked", nil)
}

func (h *httpHandler) alertFailure(writer http.ResponseWriter, status int, id json.RawMessage) {
	logDiagnostic(h.diagnostics, "alert write failed; blocking request")
	writeHTTPRPCError(writer, status, id, -32603, "alert unavailable; request blocked", nil)
}

func readHTTPBody(body io.ReadCloser, maxBytes int64) ([]byte, bool, error) {
	defer func() { _ = body.Close() }()
	data, err := io.ReadAll(io.LimitReader(body, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > maxBytes {
		return nil, true, nil
	}
	return data, false, nil
}

func writeHTTPRPCError(writer http.ResponseWriter, status int, id json.RawMessage, code int, message string, data any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	if data == nil {
		_ = writeRPCError(writer, id, code, message)
		return
	}
	_ = writeRPCError(writer, id, code, message, data)
}

// HTTPServeOptions configures the blocking HTTP server loop.
type HTTPServeOptions struct {
	Listen      string
	Handler     http.Handler
	Diagnostics io.Writer
}

// RunHTTP serves the proxy until the context is cancelled.
func RunHTTP(ctx context.Context, options HTTPServeOptions) error {
	if options.Handler == nil {
		return errors.New("HTTP handler is required")
	}
	listen := strings.TrimSpace(options.Listen)
	if listen == "" {
		listen = DefaultListen
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listen, err)
	}
	server := &http.Server{
		Handler:           options.Handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	if options.Diagnostics != nil {
		_, _ = fmt.Fprintf(options.Diagnostics, "caplock proxy: listening on http://%s\n", listener.Addr().String())
	}
	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			_ = server.Close()
			return err
		}
		if err := <-serveDone; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case err := <-serveDone:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
