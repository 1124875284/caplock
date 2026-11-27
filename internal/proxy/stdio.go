package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
)

const (
	// DefaultMaxRequestBytes bounds a single inbound JSON-RPC message.
	DefaultMaxRequestBytes int64 = 8 << 20
	// DefaultMaxResponseBytes bounds a single child JSON-RPC message.
	DefaultMaxResponseBytes int64 = 64 << 20
)

// ErrFrameTooLarge is returned for a newline-delimited message above the limit.
var ErrFrameTooLarge = errors.New("JSON-RPC message exceeds the configured size limit")

// ChildExitError preserves a wrapped MCP server's process exit code.
type ChildExitError struct {
	Code int
}

func (e *ChildExitError) Error() string {
	return fmt.Sprintf("MCP server exited with status %d", e.Code)
}

// StdioOptions configures a newline-delimited JSON-RPC proxy around a child MCP
// server. The child is only started when RunStdio is called explicitly.
type StdioOptions struct {
	Engine         *Engine
	Audit          AuditFunc
	Trace          TraceFunc
	Alert          AlertFunc
	TraceArguments bool
	Command        []string
	Dir            string
	Env            []string
	Stdin          io.Reader
	Stdout         io.Writer
	Stderr         io.Writer
	ChildStderr    io.Writer

	MaxRequestBytes  int64
	MaxResponseBytes int64
}

type inboundFrame struct {
	data []byte
	err  error
}

type childResult struct {
	wait   error
	output error
}

// RunStdio proxies MCP JSON-RPC over the parent's stdio to a child process.
// Non-tools/call messages are forwarded unchanged. tools/call messages are
// evaluated before forwarding and are blocked with a JSON-RPC error when denied.
func RunStdio(ctx context.Context, options StdioOptions) error {
	if options.Engine == nil {
		return errors.New("engine is required")
	}
	if len(options.Command) == 0 || strings.TrimSpace(options.Command[0]) == "" {
		return errors.New("a child command is required after --")
	}
	if options.Stdin == nil || options.Stdout == nil || options.Stderr == nil {
		return errors.New("stdin, stdout, and stderr are required")
	}
	if options.MaxRequestBytes <= 0 {
		options.MaxRequestBytes = DefaultMaxRequestBytes
	}
	if options.MaxResponseBytes <= 0 {
		options.MaxResponseBytes = DefaultMaxResponseBytes
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// #nosec G204 -- the user explicitly supplies the child MCP command after --.
	command := exec.CommandContext(ctx, options.Command[0], options.Command[1:]...)
	command.Dir = options.Dir
	command.Env = options.Env

	childStdin, err := command.StdinPipe()
	if err != nil {
		return fmt.Errorf("open child stdin: %w", err)
	}
	childStdout, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open child stdout: %w", err)
	}
	childStderr := options.ChildStderr
	if childStderr == nil {
		childStderr = io.Discard
	}
	command.Stderr = childStderr

	if err := command.Start(); err != nil {
		return fmt.Errorf("start MCP server: %w", err)
	}

	out := &lockedWriter{writer: options.Stdout}
	diagnostics := &lockedWriter{writer: options.Stderr}

	stdoutDone := make(chan error, 1)
	go func() {
		stdoutDone <- pumpFrames(childStdout, out, options.MaxResponseBytes)
	}()

	childDone := make(chan childResult, 1)
	go func() {
		outputErr := <-stdoutDone
		if outputErr != nil {
			_ = command.Process.Kill()
		}
		childDone <- childResult{wait: command.Wait(), output: outputErr}
	}()

	inbound := make(chan inboundFrame, 8)
	go readInbound(ctx, options.Stdin, options.MaxRequestBytes, inbound)

	forward := make(chan []byte, 8)
	writerDone := make(chan error, 1)
	go writeChild(childStdin, forward, writerDone)

	var returnErr error
	for {
		select {
		case frame, ok := <-inbound:
			if !ok {
				close(forward)
				_ = <-writerDone
				result := <-childDone
				return combineExit(result, nil)
			}
			if frame.err != nil {
				if errors.Is(frame.err, ErrFrameTooLarge) {
					if err := writeRPCError(out, nil, -32600, "request exceeds the message size limit", nil); err != nil {
						returnErr = err
						break
					}
					continue
				}
				returnErr = fmt.Errorf("read parent stdin: %w", frame.err)
				break
			}
			if err := handleFrame(ctx, options, out, diagnostics, forward, frame.data); err != nil {
				returnErr = err
				break
			}
		case result := <-childDone:
			close(forward)
			_ = <-writerDone
			return combineExit(result, nil)
		case <-ctx.Done():
			_ = command.Process.Kill()
			close(forward)
			_ = <-writerDone
			<-childDone
			return ctx.Err()
		}
		if returnErr != nil {
			break
		}
	}

	_ = command.Process.Kill()
	close(forward)
	_ = <-writerDone
	<-childDone
	return returnErr
}

func combineExit(result childResult, override error) error {
	if override != nil {
		return override
	}
	if result.output != nil {
		return fmt.Errorf("read MCP server stdout: %w", result.output)
	}
	if result.wait == nil {
		return nil
	}
	var exitError *exec.ExitError
	if errors.As(result.wait, &exitError) {
		code := exitError.ExitCode()
		if code < 1 {
			code = 1
		}
		return &ChildExitError{Code: code}
	}
	return result.wait
}

func handleFrame(ctx context.Context, options StdioOptions, output, diagnostics io.Writer, forward chan<- []byte, frame []byte) error {
	trimmed := bytes.TrimSpace(frame)
	if len(trimmed) == 0 {
		return nil
	}
	if trimmed[0] == '[' {
		return writeRPCError(output, nil, -32600, "batch JSON-RPC requests are not supported", nil)
	}
	var message rpcMessage
	if err := json.Unmarshal(trimmed, &message); err != nil {
		return writeRPCError(output, nil, -32700, "parse error", nil)
	}
	if message.Method != "tools/call" {
		return enqueue(ctx, forward, frame)
	}

	id, valid := normalizeID(message.ID)
	if message.JSONRPC != "2.0" || !valid {
		decision := InvalidDecision("", "invalid tools/call envelope")
		if err := writeAudit(options, decision); err != nil {
			return auditFailure(output, diagnostics, id, err)
		}
		return writeRPCError(output, id, -32600, "invalid JSON-RPC request", nil)
	}

	params, err := parseCallParams(message.Params)
	if err != nil {
		decision := InvalidDecision(params.Name, "invalid tools/call params")
		if auditErr := writeAudit(options, decision); auditErr != nil {
			return auditFailure(output, diagnostics, id, auditErr)
		}
		return writeRPCError(output, id, -32602, "invalid tools/call params", nil)
	}

	decision, err := options.Engine.Decide(params.Name, params.Arguments)
	if err != nil {
		logDiagnostic(diagnostics, "policy evaluation failed")
		invalid := InvalidDecision(params.Name, "policy evaluation failed")
		if auditErr := writeAudit(options, invalid); auditErr != nil {
			return auditFailure(output, diagnostics, id, auditErr)
		}
		return writeRPCError(output, id, -32603, "policy evaluation failed", nil)
	}
	if err := writeTrace(options.Trace, options.Engine, decision, params.Arguments, options.TraceArguments); err != nil {
		return traceFailure(output, diagnostics, id, err)
	}
	if err := writeAudit(options, decision); err != nil {
		return auditFailure(output, diagnostics, id, err)
	}
	if err := writeAlert(options, decision); err != nil {
		return alertFailure(output, diagnostics, id, err)
	}
	if !decision.Forward {
		return writePolicyError(output, id, decision)
	}
	if decision.ForwardArguments != nil {
		rewritten, err := rewriteCallArguments(frame, decision.ForwardArguments)
		if err != nil {
			return traceFailure(output, diagnostics, id, fmt.Errorf("rewrite redacted arguments: %w", err))
		}
		frame = rewritten
	}
	return enqueue(ctx, forward, frame)
}

func rewriteCallArguments(frame []byte, arguments map[string]any) ([]byte, error) {
	var message map[string]any
	if err := json.Unmarshal(frame, &message); err != nil {
		return nil, err
	}
	params, ok := message["params"].(map[string]any)
	if !ok {
		return nil, errors.New("tools/call params is not an object")
	}
	params["arguments"] = arguments
	message["params"] = params
	encoded, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func traceFailure(output, diagnostics io.Writer, id json.RawMessage, err error) error {
	logDiagnostic(diagnostics, "trace write failed; blocking request")
	_ = writeRPCError(output, id, -32603, "trace unavailable; request blocked", nil)
	return fmt.Errorf("write trace record: %w", err)
}

func auditFailure(output, diagnostics io.Writer, id json.RawMessage, err error) error {
	logDiagnostic(diagnostics, "audit write failed; blocking request")
	_ = writeRPCError(output, id, -32603, "audit unavailable; request blocked", nil)
	return fmt.Errorf("write audit record: %w", err)
}

func alertFailure(output, diagnostics io.Writer, id json.RawMessage, err error) error {
	logDiagnostic(diagnostics, "alert write failed; blocking request")
	return writeRPCError(output, id, -32603, "alert unavailable; request blocked", nil)
}

func logDiagnostic(writer io.Writer, message string) {
	if writer == nil {
		return
	}
	_, _ = fmt.Fprintf(writer, "caplock proxy: %s\n", message)
}

func enqueue(ctx context.Context, forward chan<- []byte, frame []byte) error {
	select {
	case forward <- frame:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func readInbound(ctx context.Context, reader io.Reader, maxBytes int64, out chan<- inboundFrame) {
	defer close(out)
	buffered := bufio.NewReaderSize(reader, 64<<10)
	for {
		frame, err := readFrame(buffered, maxBytes)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			select {
			case out <- inboundFrame{err: err}:
			case <-ctx.Done():
				return
			}
			if errors.Is(err, ErrFrameTooLarge) {
				continue
			}
			return
		}
		select {
		case out <- inboundFrame{data: frame}:
		case <-ctx.Done():
			return
		}
	}
}

func writeChild(stdin io.WriteCloser, forward <-chan []byte, done chan<- error) {
	for frame := range forward {
		if err := writeAll(stdin, frame); err != nil {
			done <- err
			return
		}
	}
	done <- stdin.Close()
}

func pumpFrames(reader io.Reader, writer io.Writer, maxBytes int64) error {
	buffered := bufio.NewReaderSize(reader, 64<<10)
	for {
		frame, err := readFrame(buffered, maxBytes)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := writeAll(writer, frame); err != nil {
			return err
		}
	}
}

func readFrame(reader *bufio.Reader, maxBytes int64) ([]byte, error) {
	var result []byte
	oversized := false
	for {
		chunk, err := reader.ReadSlice('\n')
		if !oversized {
			if int64(len(result))+int64(len(chunk)) > maxBytes {
				oversized = true
				result = nil
			} else {
				result = append(result, chunk...)
			}
		}
		switch {
		case err == nil:
			if oversized {
				return nil, ErrFrameTooLarge
			}
			return result, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if oversized {
				return nil, ErrFrameTooLarge
			}
			if len(result) > 0 || len(chunk) > 0 {
				if !oversized {
					result = append(result, chunk...)
				}
				return result, nil
			}
			return nil, io.EOF
		default:
			return nil, err
		}
	}
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type callParams struct {
	Name      string
	Arguments map[string]any
}

func parseCallParams(raw json.RawMessage) (callParams, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return callParams{Arguments: map[string]any{}}, errors.New("params are required")
	}
	var payload struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(trimmed, &payload); err != nil {
		return callParams{Arguments: map[string]any{}}, err
	}
	name := strings.TrimSpace(payload.Name)
	if name == "" {
		return callParams{Arguments: map[string]any{}}, errors.New("params.name is required")
	}
	arguments := map[string]any{}
	argumentBytes := bytes.TrimSpace(payload.Arguments)
	if len(argumentBytes) > 0 && !bytes.Equal(argumentBytes, []byte("null")) {
		if err := json.Unmarshal(argumentBytes, &arguments); err != nil {
			return callParams{Name: name, Arguments: map[string]any{}}, errors.New("params.arguments must be an object")
		}
	}
	return callParams{Name: name, Arguments: arguments}, nil
}

func normalizeID(raw json.RawMessage) (json.RawMessage, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return json.RawMessage("null"), false
	}
	switch trimmed[0] {
	case '"':
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil {
			return json.RawMessage("null"), false
		}
		return trimmed, true
	default:
		decoder := json.NewDecoder(bytes.NewReader(trimmed))
		decoder.UseNumber()
		var number json.Number
		if err := decoder.Decode(&number); err != nil {
			return json.RawMessage("null"), false
		}
		return trimmed, true
	}
}

type rpcErrorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   rpcErrorBody    `json:"error"`
}

type rpcErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func writeRPCError(writer io.Writer, id json.RawMessage, code int, message string, data ...any) error {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	response := rpcErrorResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   rpcErrorBody{Code: code, Message: message},
	}
	if len(data) > 0 {
		response.Error.Data = data[0]
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return writeAll(writer, encoded)
}

func writePolicyError(writer io.Writer, id json.RawMessage, decision Decision) error {
	return writeRPCError(writer, id, -32001, "caplock: "+decision.Reason, policyErrorData(decision))
}

func policyErrorData(decision Decision) map[string]any {
	return map[string]any{"caplock": map[string]any{
		"effect":                decision.Policy.Effect,
		"ruleId":                decision.Policy.RuleID,
		"default":               decision.Policy.Default,
		"reason":                decision.Reason,
		"unenforcedObligations": nonNil(decision.UnenforcedObligations),
		"runtimeBlocked":        decision.RuntimeBlocked,
	}}
}

func writeAudit(options StdioOptions, decision Decision) error {
	if options.Audit == nil {
		return nil
	}
	return options.Audit(options.Engine.Record(decision))
}

func writeAlert(options StdioOptions, decision Decision) error {
	if options.Alert == nil || !contains(decision.Policy.Obligations, "alert") {
		return nil
	}
	return options.Alert(options.Engine.Alert(decision))
}

type lockedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *lockedWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(data)
}
