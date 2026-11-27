package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

type stdioTransport struct {
	command *exec.Cmd
	stdin   *os.File
	stdout  *os.File
	stderr  *os.File

	messages chan []byte
	readDone chan error
	waitDone chan struct{}
	done     chan struct{}

	writeMu   sync.Mutex
	closeOnce sync.Once
}

func newStdioTransport(ctx context.Context, spec Spec) (*stdioTransport, error) {
	childStdin, stdin, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create stdio pipe: %w", err)
	}
	stdout, childStdout, err := os.Pipe()
	if err != nil {
		closeFiles(stdin, childStdin)
		return nil, fmt.Errorf("create stdout pipe: %w", err)
	}
	stderr, childStderr, err := os.Pipe()
	if err != nil {
		closeFiles(stdin, childStdin, childStdout, stdout)
		return nil, fmt.Errorf("create stderr pipe: %w", err)
	}

	command := exec.CommandContext(ctx, spec.Command, spec.Args...) // #nosec G204 -- --connect explicitly executes the user-selected server command.
	command.Dir = spec.Dir
	command.Env = mergedEnvironment(spec.Env)
	command.Stdin = childStdin
	command.Stdout = childStdout
	command.Stderr = childStderr
	if err := command.Start(); err != nil {
		closeFiles(stdin, childStdin, childStdout, stdout, childStderr, stderr)
		return nil, fmt.Errorf("start MCP server: %w", err)
	}
	closeFiles(childStdin, childStdout, childStderr)

	transport := &stdioTransport{
		command:  command,
		stdin:    stdin,
		stdout:   stdout,
		stderr:   stderr,
		messages: make(chan []byte, 16),
		readDone: make(chan error, 1),
		waitDone: make(chan struct{}),
		done:     make(chan struct{}),
	}
	go transport.readMessages()
	go func() {
		_, _ = io.Copy(io.Discard, stderr)
	}()
	go func() {
		_ = command.Wait()
		close(transport.waitDone)
	}()
	return transport, nil
}

func (t *stdioTransport) call(ctx context.Context, id int64, method string, params any) (json.RawMessage, error) {
	if err := t.write(rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params}); err != nil {
		return nil, err
	}
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for MCP response: %w", ctx.Err())
		case message, ok := <-t.messages:
			if !ok {
				if err := <-t.readDone; err != nil {
					return nil, fmt.Errorf("read MCP response: %w", err)
				}
				return nil, errors.New("MCP server closed its stdout before responding")
			}
			result, err := decodeResponse(message, id)
			if err != nil {
				return nil, err
			}
			if result != nil {
				return result, nil
			}
		}
	}
}

func (t *stdioTransport) notify(ctx context.Context, method string, params any) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return t.write(rpcRequest{JSONRPC: "2.0", Method: method, Params: params})
}

func (*stdioTransport) setProtocolVersion(string) {}

func (t *stdioTransport) write(request rpcRequest) error {
	data, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode MCP request: %w", err)
	}
	data = append(data, '\n')
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if _, err := t.stdin.Write(data); err != nil {
		if errors.Is(err, os.ErrClosed) {
			return errors.New("MCP server closed stdin")
		}
		return fmt.Errorf("write MCP request: %w", err)
	}
	return nil
}

func (t *stdioTransport) readMessages() {
	scanner := bufio.NewScanner(t.stdout)
	scanner.Buffer(make([]byte, 64*1024), maxMessageBytes)
	defer close(t.messages)
	for scanner.Scan() {
		line := bytesTrimSpaceCopy(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		select {
		case t.messages <- line:
		case <-t.done:
			t.readDone <- nil
			return
		}
	}
	if err := scanner.Err(); err != nil {
		t.readDone <- fmt.Errorf("invalid or oversized MCP message: %w", err)
		return
	}
	t.readDone <- nil
}

func (t *stdioTransport) close() error {
	t.closeOnce.Do(func() {
		close(t.done)
		_ = t.stdin.Close()
		if t.command.Process != nil {
			_ = t.command.Process.Kill()
		}
		closeFiles(t.stdout, t.stderr)
		select {
		case <-t.waitDone:
		case <-time.After(5 * time.Second):
		}
	})
	return nil
}

func mergedEnvironment(overrides map[string]string) []string {
	values := make(map[string]string)
	for _, entry := range os.Environ() {
		name, value, found := strings.Cut(entry, "=")
		if found {
			values[name] = value
		}
	}
	for name, value := range overrides {
		values[name] = value
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	environment := make([]string, 0, len(names))
	for _, name := range names {
		environment = append(environment, name+"="+values[name])
	}
	return environment
}

func bytesTrimSpaceCopy(value []byte) []byte {
	start := 0
	for start < len(value) && isSpaceByte(value[start]) {
		start++
	}
	end := len(value)
	for end > start && isSpaceByte(value[end-1]) {
		end--
	}
	copied := make([]byte, end-start)
	copy(copied, value[start:end])
	return copied
}

func isSpaceByte(value byte) bool {
	switch value {
	case ' ', '\t', '\r', '\n':
		return true
	default:
		return false
	}
}

func closeFiles(files ...*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}
