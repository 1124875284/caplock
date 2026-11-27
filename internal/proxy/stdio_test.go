package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/caplock/caplock/internal/trace"
)

func TestProxyHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_PROXY_HELPER") != "1" {
		return
	}
	if os.Getenv("GO_PROXY_HELPER_MODE") == "exit7" {
		os.Exit(7)
	}
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var message struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			continue
		}
		if len(message.ID) == 0 || bytes.Equal(message.ID, []byte("null")) {
			continue
		}
		if message.Method == "tools/call" {
			var params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			_ = json.Unmarshal(message.Params, &params)
			_ = encoder.Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      message.ID,
				"result":  map[string]any{"forwarded": true, "tool": params.Name, "arguments": params.Arguments},
			})
			continue
		}
		_ = encoder.Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      message.ID,
			"result":  map[string]any{"method": message.Method},
		})
	}
	os.Exit(0)
}

func helperCommand(mode string) ([]string, []string) {
	environment := append(os.Environ(), "GO_WANT_PROXY_HELPER=1")
	if mode != "" {
		environment = append(environment, "GO_PROXY_HELPER_MODE="+mode)
	}
	return []string{os.Args[0], "-test.run=TestProxyHelperProcess"}, environment
}

func TestRunStdioForwardsAllowedCallAndAuditsWithoutArguments(t *testing.T) {
	command, environment := helperCommand("")
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/secret/report.txt"}}}`,
		"",
	}, "\n")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var audit bytes.Buffer
	engine := testEngine(t, ApprovalBlock, nil)
	err := RunStdio(context.Background(), StdioOptions{
		Engine:  engine,
		Audit:   NewJSONLAudit(&audit).Write,
		Command: command,
		Env:     environment,
		Stdin:   strings.NewReader(input),
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("RunStdio() error = %v, stderr = %s", err, stderr.String())
	}
	output := stdout.String()
	if !strings.Contains(output, `"method":"initialize"`) || !strings.Contains(output, `"forwarded":true`) {
		t.Fatalf("stdout = %s", output)
	}
	auditOutput := audit.String()
	if strings.Contains(auditOutput, "/secret/report.txt") {
		t.Fatalf("audit leaked arguments: %s", auditOutput)
	}
	var record AuditRecord
	if err := json.Unmarshal(bytes.TrimSpace(audit.Bytes()), &record); err != nil {
		t.Fatalf("decode audit: %v\n%s", err, auditOutput)
	}
	if record.Tool != "read_file" || !record.Forwarded || record.ArgsHash == "" {
		t.Fatalf("audit = %#v", record)
	}
}

func TestRunStdioCapturesReplayableTrace(t *testing.T) {
	command, environment := helperCommand("")
	input := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/readme.md"}}}` + "\n"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var captured []trace.Record
	err := RunStdio(context.Background(), StdioOptions{
		Engine:         testEngine(t, ApprovalBlock, nil),
		TraceArguments: true,
		Trace: func(record trace.Record) error {
			captured = append(captured, record)
			return nil
		},
		Command: command,
		Env:     environment,
		Stdin:   strings.NewReader(input),
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("RunStdio() error = %v, stderr = %s", err, stderr.String())
	}
	if len(captured) != 1 {
		t.Fatalf("captured records = %d, want 1", len(captured))
	}
	record := captured[0]
	if record.Tool != "read_file" || !record.ArgumentsCaptured || record.Args["path"] != "/workspace/readme.md" {
		t.Fatalf("trace record = %#v", record)
	}
	if record.Decision.Effect != "allow" || !record.Decision.Forwarded || record.ArgsHash == "" {
		t.Fatalf("trace decision = %#v", record.Decision)
	}
}

func TestRunStdioBlocksApprovalRequiredCall(t *testing.T) {
	command, environment := helperCommand("")
	input := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"outside@example.com"}}}` + "\n"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var audit bytes.Buffer
	err := RunStdio(context.Background(), StdioOptions{
		Engine:  testEngine(t, ApprovalBlock, nil),
		Audit:   NewJSONLAudit(&audit).Write,
		Command: command,
		Env:     environment,
		Stdin:   strings.NewReader(input),
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("RunStdio() error = %v, stderr = %s", err, stderr.String())
	}
	if strings.Contains(stdout.String(), `"forwarded":true`) {
		t.Fatalf("blocked call reached the child: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"code":-32001`) || !strings.Contains(stdout.String(), "approval required") {
		t.Fatalf("stdout = %s", stdout.String())
	}
	if !strings.Contains(audit.String(), `"forwarded":false`) || !strings.Contains(audit.String(), `"tool":"send_email"`) {
		t.Fatalf("audit = %s", audit.String())
	}
}

func TestRunStdioRejectsInvalidParamsAndBatches(t *testing.T) {
	command, environment := helperCommand("")
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":[]}}`,
		`[{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file"}}]`,
		"",
	}, "\n")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := RunStdio(context.Background(), StdioOptions{
		Engine:  testEngine(t, ApprovalBlock, nil),
		Command: command,
		Env:     environment,
		Stdin:   strings.NewReader(input),
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("RunStdio() error = %v, stderr = %s", err, stderr.String())
	}
	output := stdout.String()
	if !strings.Contains(output, `"code":-32602`) || !strings.Contains(output, `"code":-32600`) {
		t.Fatalf("stdout = %s", output)
	}
	if strings.Contains(output, `"forwarded":true`) {
		t.Fatalf("invalid requests reached the child: %s", output)
	}
}

func TestRunStdioRejectsOversizedRequestAndContinues(t *testing.T) {
	command, environment := helperCommand("")
	input := strings.Repeat("x", 100) + "\n" + `{"jsonrpc":"2.0","id":2,"method":"initialize"}` + "\n"
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := RunStdio(context.Background(), StdioOptions{
		Engine:          testEngine(t, ApprovalBlock, nil),
		Command:         command,
		Env:             environment,
		Stdin:           strings.NewReader(input),
		Stdout:          &stdout,
		Stderr:          &stderr,
		MaxRequestBytes: 60,
	})
	if err != nil {
		t.Fatalf("RunStdio() error = %v, stderr = %s", err, stderr.String())
	}
	output := stdout.String()
	if !strings.Contains(output, "message size limit") || !strings.Contains(output, `"method":"initialize"`) {
		t.Fatalf("stdout = %s", output)
	}
}

func TestRunStdioPropagatesChildExitCode(t *testing.T) {
	command, environment := helperCommand("exit7")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := RunStdio(context.Background(), StdioOptions{
		Engine:  testEngine(t, ApprovalBlock, nil),
		Command: command,
		Env:     environment,
		Stdin:   strings.NewReader(""),
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	var exitError *ChildExitError
	if !errors.As(err, &exitError) || exitError.Code != 7 {
		t.Fatalf("RunStdio() error = %v, want exit code 7", err)
	}
}
