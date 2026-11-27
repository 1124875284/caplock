package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/1124875284/caplock/internal/canonical"
	"github.com/1124875284/caplock/internal/lockfile"
	"github.com/1124875284/caplock/internal/policy"
	"github.com/1124875284/caplock/internal/proxy"
	"github.com/1124875284/caplock/internal/trace"
)

type proxySettings struct {
	policyPath     string
	subject        string
	lockfilePath   string
	auditPath      string
	alertPath      string
	tracePath      string
	traceArguments string
	traceRedact    string
	redactFields   string
	rateLimit      string
	approvalMode   string
	environment    string
	childStderr    string
}

func (s *proxySettings) addFlags(command *cobra.Command) {
	command.Flags().StringVar(&s.policyPath, "policy", policy.Name, "Compiled policy source")
	command.Flags().StringVar(&s.subject, "subject", "", "Agent subject used for policy evaluation")
	command.Flags().StringVar(&s.lockfilePath, "lockfile", "", "Optional lockfile used for tool capabilities and manifest drift checks")
	command.Flags().StringVar(&s.auditPath, "audit", "", "Optional JSONL audit path (arguments are hashed, never logged)")
	command.Flags().StringVar(&s.alertPath, "alert", "", "Optional JSONL alert path for rules carrying the alert obligation")
	command.Flags().StringVar(&s.tracePath, "trace", "", "Optional replayable JSONL trace path")
	command.Flags().StringVar(&s.traceArguments, "trace-arguments", "hash", "Trace argument capture: hash or full (full records raw arguments)")
	command.Flags().StringVar(&s.traceRedact, "trace-redact", "", "Comma-separated trace-only field names to redact in full capture")
	command.Flags().StringVar(&s.redactFields, "redact-fields", "password,secret,token,authorization,api_key,access_token,client_secret", "Comma-separated argument fields redacted before forwarding when a rule requires redact")
	command.Flags().StringVar(&s.rateLimit, "rate-limit", "", "Rate-limit obligation budget as <count>/<duration>, for example 60/1m")
	command.Flags().StringVar(&s.approvalMode, "approval-mode", string(proxy.ApprovalBlock), "require_approval behavior: block or forward")
	command.Flags().StringVar(&s.environment, "environment", "", "Request context.environment value")
	command.Flags().StringVar(&s.childStderr, "child-stderr", "discard", "Child MCP stderr handling: discard or inherit")
	_ = command.MarkFlagRequired("subject")
}

type proxyRuntime struct {
	engine         *proxy.Engine
	audit          proxy.AuditFunc
	trace          proxy.TraceFunc
	alert          proxy.AlertFunc
	traceArguments bool
	close          func() error
}

func (s proxySettings) build() (*proxyRuntime, error) {
	ir, err := policy.LoadFile(s.policyPath)
	if err != nil {
		return nil, fail(2, "%v", err)
	}
	issues := policy.Lint(ir, s.policyPath)
	if policy.HasErrors(issues) {
		return nil, fail(1, "policy has lint errors; run `caplock lint %s`", displayText(s.policyPath))
	}
	if strings.TrimSpace(s.auditPath) == "" && proxy.RequiresAudit(ir) {
		return nil, fail(2, "policy requires audit obligations; pass --audit <path>")
	}
	if strings.TrimSpace(s.alertPath) == "" && proxy.RequiresObligation(ir, "alert") {
		return nil, fail(2, "policy requires alert obligations; pass --alert <path>")
	}
	mode, err := proxy.ParseApprovalMode(s.approvalMode)
	if err != nil {
		return nil, fail(2, "%v", err)
	}
	captureArguments := false
	switch strings.ToLower(strings.TrimSpace(s.traceArguments)) {
	case "", "hash":
	case "full":
		captureArguments = true
	default:
		return nil, fail(2, "unsupported --trace-arguments %q; use hash or full", s.traceArguments)
	}
	if captureArguments && strings.TrimSpace(s.tracePath) == "" {
		return nil, fail(2, "--trace-arguments full requires --trace <path>")
	}
	traceRedaction, err := canonical.ParseRedactionKeys(s.traceRedact)
	if err != nil {
		return nil, fail(2, "invalid --trace-redact: %v", err)
	}
	if len(traceRedaction) > 0 && (!captureArguments || strings.TrimSpace(s.tracePath) == "") {
		return nil, fail(2, "--trace-redact requires --trace and --trace-arguments full")
	}
	redaction, err := canonical.ParseRedactionKeys(s.redactFields)
	if err != nil {
		return nil, fail(2, "invalid --redact-fields: %v", err)
	}
	var limiter *proxy.RateLimiter
	if strings.TrimSpace(s.rateLimit) != "" {
		limiter, err = proxy.ParseRateLimit(s.rateLimit)
		if err != nil {
			return nil, fail(2, "%v", err)
		}
	}
	if strings.TrimSpace(s.rateLimit) == "" && proxy.RequiresObligation(ir, "rate_limit") {
		return nil, fail(2, "policy requires rate_limit obligations; pass --rate-limit <count>/<duration>")
	}
	sinks := []string{s.auditPath, s.alertPath, s.tracePath}
	for index := range sinks {
		if strings.TrimSpace(sinks[index]) == "" {
			continue
		}
		for other := index + 1; other < len(sinks); other++ {
			if strings.TrimSpace(sinks[other]) != "" && sinks[index] == sinks[other] {
				return nil, fail(2, "--audit, --alert, and --trace must use different files")
			}
		}
	}
	var locked *lockfile.File
	if strings.TrimSpace(s.lockfilePath) != "" {
		locked, err = lockfile.Read(s.lockfilePath)
		if err != nil {
			return nil, fail(2, "%v", err)
		}
	}
	engine, err := proxy.NewEngine(proxy.Options{
		Policy:             ir,
		Lockfile:           locked,
		Subject:            s.subject,
		Environment:        s.environment,
		ApprovalMode:       mode,
		AuditEnabled:       strings.TrimSpace(s.auditPath) != "",
		RedactionKeys:      redaction,
		TraceRedactionKeys: traceRedaction,
		RateLimiter:        limiter,
		AlertEnabled:       strings.TrimSpace(s.alertPath) != "",
	})
	if err != nil {
		return nil, fail(2, "%v", err)
	}
	closers := make([]func() error, 0, 3)
	closeAll := func() error {
		errs := make([]error, 0, len(closers))
		for _, closer := range closers {
			errs = append(errs, closer())
		}
		return errors.Join(errs...)
	}
	runtime := &proxyRuntime{
		engine:         engine,
		traceArguments: captureArguments,
		close:          closeAll,
	}
	if strings.TrimSpace(s.auditPath) != "" {
		file, err := openProxySink(s.auditPath, "audit log")
		if err != nil {
			return nil, err
		}
		closers = append(closers, file.Close)
		runtime.audit = proxy.NewJSONLAudit(file).Write
	}
	if strings.TrimSpace(s.tracePath) != "" {
		file, err := openProxySink(s.tracePath, "trace file")
		if err != nil {
			_ = closeAll()
			return nil, err
		}
		closers = append(closers, file.Close)
		runtime.trace = trace.NewJSONLWriter(file).Write
	}
	if strings.TrimSpace(s.alertPath) != "" {
		file, err := openProxySink(s.alertPath, "alert log")
		if err != nil {
			_ = closeAll()
			return nil, err
		}
		closers = append(closers, file.Close)
		runtime.alert = proxy.NewJSONLAlerts(file).Write
	}
	return runtime, nil
}

func openProxySink(path, label string) (*os.File, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fail(3, "%s %s must not be a symlink", label, displayText(path))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fail(3, "inspect %s %s: %v", label, displayText(path), err)
	}
	// #nosec G304,G302 -- the operator explicitly selects this path; the file
	// is created append-only with owner-only permissions.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fail(3, "open %s %s: %v", label, displayText(path), err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fail(3, "%s %s must be a regular file", label, displayText(path))
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fail(3, "restrict %s %s: %v", label, displayText(path), err)
	}
	return file, nil
}

func (s proxySettings) childStderrWriter(stderr io.Writer) (io.Writer, error) {
	switch strings.ToLower(strings.TrimSpace(s.childStderr)) {
	case "discard", "":
		return io.Discard, nil
	case "inherit":
		return stderr, nil
	default:
		return nil, fail(2, "unsupported --child-stderr %q; use discard or inherit", s.childStderr)
	}
}

func newProxyCommand() *cobra.Command {
	var settings proxySettings
	command := &cobra.Command{
		Use:   "proxy [flags] -- COMMAND [ARGS...]",
		Short: "Enforce policy on MCP tools/call over stdio",
		Long:  "Run an MCP server as a child process and block tools/call requests that the compiled policy denies. The child is started only by this explicit command.",
		Args:  cobra.ArbitraryArgs,
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fail(2, "a child MCP command is required after --")
			}
			runtime, err := settings.build()
			if err != nil {
				return err
			}
			defer func() { _ = runtime.close() }()
			if runtime.traceArguments {
				_, _ = fmt.Fprintln(command.ErrOrStderr(), "caplock proxy: warning: --trace-arguments full captures raw tool arguments; protect the trace file")
			}
			childStderr, err := settings.childStderrWriter(command.ErrOrStderr())
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(command.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			err = proxy.RunStdio(ctx, proxy.StdioOptions{
				Engine:         runtime.engine,
				Audit:          runtime.audit,
				Alert:          runtime.alert,
				Trace:          runtime.trace,
				TraceArguments: runtime.traceArguments,
				Command:        args,
				Stdin:          command.InOrStdin(),
				Stdout:         command.OutOrStdout(),
				Stderr:         command.ErrOrStderr(),
				ChildStderr:    childStderr,
			})
			return mapProxyError(err)
		},
	}
	settings.addFlags(command)
	command.AddCommand(newHTTPProxyCommand())
	return command
}

func newHTTPProxyCommand() *cobra.Command {
	var settings proxySettings
	var listen string
	var target string
	command := &cobra.Command{
		Use:   "http",
		Short: "Enforce policy on MCP Streamable HTTP tools/call",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			parsed, err := url.Parse(target)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				return fail(2, "invalid --target URL %q", target)
			}
			runtime, err := settings.build()
			if err != nil {
				return err
			}
			defer func() { _ = runtime.close() }()
			if runtime.traceArguments {
				_, _ = fmt.Fprintln(command.ErrOrStderr(), "caplock proxy: warning: --trace-arguments full captures raw tool arguments; protect the trace file")
			}
			handler, err := proxy.NewHTTPHandler(proxy.HTTPOptions{
				Engine:         runtime.engine,
				Audit:          runtime.audit,
				Alert:          runtime.alert,
				Trace:          runtime.trace,
				TraceArguments: runtime.traceArguments,
				Target:         parsed,
				Diagnostics:    command.ErrOrStderr(),
			})
			if err != nil {
				return fail(2, "%v", err)
			}
			ctx, stop := signal.NotifyContext(command.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			err = proxy.RunHTTP(ctx, proxy.HTTPServeOptions{
				Listen:      listen,
				Handler:     handler,
				Diagnostics: command.ErrOrStderr(),
			})
			return mapProxyError(err)
		},
	}
	settings.addFlags(command)
	command.Flags().StringVar(&listen, "listen", proxy.DefaultListen, "Listen address (loopback by default)")
	command.Flags().StringVar(&target, "target", "", "Upstream Streamable HTTP MCP endpoint")
	_ = command.MarkFlagRequired("target")
	return command
}

func mapProxyError(err error) error {
	if err == nil {
		return nil
	}
	var childExit *proxy.ChildExitError
	if errors.As(err, &childExit) {
		return fail(childExit.Code, "%v", childExit)
	}
	if errors.Is(err, context.Canceled) {
		return failQuiet(130, "interrupted")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fail(2, "%v", err)
	}
	return fail(2, "%v", err)
}
