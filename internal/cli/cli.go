// Package cli implements the caplock command-line interface.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/caplock/caplock/internal/config"
	"github.com/caplock/caplock/internal/lockfile"
	"github.com/caplock/caplock/internal/manifest"
	"github.com/caplock/caplock/internal/mcp"
	"github.com/caplock/caplock/internal/policy"
	"github.com/caplock/caplock/internal/safefile"
	"github.com/caplock/caplock/internal/version"
)

type exitError struct {
	code  int
	err   error
	quiet bool
}

func (e *exitError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

func fail(code int, format string, args ...any) error {
	return &exitError{code: code, err: fmt.Errorf(format, args...)}
}

func failQuiet(code int, format string, args ...any) error {
	return &exitError{code: code, err: fmt.Errorf(format, args...), quiet: true}
}

// Execute runs the CLI and maps errors to the documented process exit codes.
func Execute(args []string, stdout, stderr io.Writer) int {
	command := NewRootCommand(stdout, stderr)
	command.SetArgs(args)
	if err := command.Execute(); err != nil {
		var typed *exitError
		if errors.As(err, &typed) {
			if !typed.quiet && typed.err != nil {
				_, _ = fmt.Fprintf(stderr, "error: %s\n", displayText(typed.err.Error()))
			}
			return typed.code
		}
		_, _ = fmt.Fprintf(stderr, "error: %s\n", displayText(err.Error()))
		return 2
	}
	return 0
}

// NewRootCommand builds the root command. It is exported for CLI tests and for
// embedding Caplock in other Go programs without spawning a subprocess.
func NewRootCommand(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "caplock",
		Short:         "The capability lockfile and policy compiler for MCP agents",
		Long:          "Caplock discovers MCP servers, writes a deterministic capability lockfile, compiles policy source into Policy IR, and reviews permission drift.",
		Version:       version.Version,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			return command.Help()
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate("caplock {{.Version}}\n")
	root.CompletionOptions.DisableDefaultCmd = true
	root.AddCommand(
		newVersionCommand(),
		newScanCommand(),
		newLockCommand(),
		newDiffCommand(),
		newInitCommand(),
		newDraftCommand(),
		newCompileCommand(),
		newLintCommand(),
		newTestCommand(),
		newReportCommand(),
		newCorpusCommand(),
		newImportCommand(),
		newExportCommand(),
		newMatrixCommand(),
		newGraphCommand(),
		newReplayCommand(),
		newProxyCommand(),
	)
	return root
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the Caplock version",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			_, err := fmt.Fprintf(command.OutOrStdout(), "caplock %s\n", version.Version)
			return err
		},
	}
}

func newScanCommand() *cobra.Command {
	var jsonOutput bool
	var connect bool
	var timeout time.Duration
	command := &cobra.Command{
		Use:   "scan [PATH]",
		Short: "Discover MCP servers and optionally capture their tool manifests",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			project, err := config.LoadProject(path)
			if err != nil {
				return fail(2, "%v", err)
			}
			file, err := buildInventory(command.Context(), project, connect, timeout)
			if err != nil {
				return err
			}
			if jsonOutput {
				return writeScanJSON(command.OutOrStdout(), file)
			}
			return writeScanText(command.OutOrStdout(), project, file, connect)
		},
	}
	command.Flags().BoolVar(&jsonOutput, "json", false, "Print a machine-readable inventory")
	command.Flags().BoolVar(&connect, "connect", false, "Execute or contact each MCP server to fetch tools/list")
	command.Flags().DurationVar(&timeout, "timeout", 20*time.Second, "Per-server connection timeout")
	return command
}

func writeScanJSON(out io.Writer, file *lockfile.File) error {
	data, err := lockfile.Marshal(file)
	if err != nil {
		return fail(3, "serialize inventory: %v", err)
	}
	if _, err := out.Write(data); err != nil {
		return fail(3, "write inventory: %v", err)
	}
	return nil
}

func writeScanText(out io.Writer, project *config.Project, file *lockfile.File, connected bool) error {
	if len(project.Servers) == 0 {
		_, err := fmt.Fprintf(out, "No MCP servers found (%s scanned).\n", plural(len(project.Configs), "config file"))
		return err
	}
	writer := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	header := "SERVER\tSOURCE\tTRANSPORT\tCOMMAND / URL"
	if connected {
		header = "SERVER\tSOURCE\tTRANSPORT\tTOOLS\tCAPABILITIES\tCOMMAND / URL"
	}
	if _, err := fmt.Fprintln(writer, header); err != nil {
		return err
	}
	lockedServers := indexLockedServers(file)
	for _, server := range project.Servers {
		if connected {
			locked := lockedServers[server.Source+"\x00"+server.Name]
			toolCount := "0"
			capabilities := "-"
			if locked.Tools != nil {
				toolCount = fmt.Sprintf("%d", len(*locked.Tools))
				capabilities = strings.Join(serverCapabilities(locked), ", ")
				if capabilities == "" {
					capabilities = "-"
				}
			}
			if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\t%s\n", displayText(server.Name), displayText(server.Source), displayText(server.Transport), toolCount, displayText(capabilities), displayText(serverTarget(server))); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", displayText(server.Name), displayText(server.Source), displayText(server.Transport), displayText(serverTarget(server))); err != nil {
				return err
			}
		}
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	summary := fmt.Sprintf("%s · %s", plural(len(project.Servers), "server"), plural(len(project.Configs), "config file"))
	if connected {
		summary += " · " + plural(countTools(file), "tool")
	}
	_, err := fmt.Fprintf(out, "\n%s\n", summary)
	return err
}

func indexLockedServers(file *lockfile.File) map[string]lockfile.Server {
	result := make(map[string]lockfile.Server, len(file.Servers))
	for _, server := range file.Servers {
		result[server.Source+"\x00"+server.Name] = server
	}
	return result
}

func serverCapabilities(server lockfile.Server) []string {
	if server.Tools == nil {
		return nil
	}
	seen := make(map[string]bool)
	for _, tool := range *server.Tools {
		for _, capability := range tool.Capabilities {
			seen[capability] = true
		}
	}
	result := make([]string, 0, len(seen))
	for capability := range seen {
		result = append(result, capability)
	}
	sort.Strings(result)
	return result
}

func serverTarget(server config.Server) string {
	if server.Command != nil {
		parts := append([]string{*server.Command}, server.Args...)
		return strings.Join(parts, " ")
	}
	if server.URL != nil {
		return *server.URL
	}
	return ""
}

func newLockCommand() *cobra.Command {
	var output string
	var check bool
	var connect bool
	var timeout time.Duration
	command := &cobra.Command{
		Use:   "lock [PATH]",
		Short: "Write a deterministic caplock.lock",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			path := "."
			if len(args) == 1 {
				path = args[0]
			}
			project, err := config.LoadProject(path)
			if err != nil {
				return fail(2, "%v", err)
			}
			if len(project.Servers) == 0 {
				return fail(2, "no MCP servers found; nothing to lock")
			}
			file, err := buildInventory(command.Context(), project, connect, timeout)
			if err != nil {
				return err
			}
			if check {
				return checkLockfile(command.OutOrStdout(), output, file)
			}
			if err := lockfile.Write(output, file); err != nil {
				return fail(3, "%v", err)
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "wrote %s (%s)\n", displayText(output), describeInventory(file))
			return err
		},
	}
	command.Flags().StringVarP(&output, "output", "o", lockfile.Name, "Lockfile path")
	command.Flags().BoolVar(&check, "check", false, "Fail with exit code 1 when the lockfile is missing or out of date")
	command.Flags().BoolVar(&connect, "connect", false, "Execute or contact each MCP server to fetch tools/list")
	command.Flags().DurationVar(&timeout, "timeout", 20*time.Second, "Per-server connection timeout")
	return command
}

func buildInventory(ctx context.Context, project *config.Project, connect bool, timeout time.Duration) (*lockfile.File, error) {
	file := lockfile.Build(project)
	if !connect {
		return file, nil
	}
	if timeout <= 0 {
		return nil, fail(2, "--timeout must be greater than zero")
	}
	servers := indexLockedServers(file)
	for _, configured := range project.Servers {
		spec, err := connectionSpec(configured, project.Root)
		if err != nil {
			return nil, fail(2, "connect to server %q: %v", configured.Name, err)
		}
		serverContext, cancel := context.WithTimeout(ctx, timeout)
		tools, err := mcp.FetchTools(serverContext, spec)
		cancel()
		if err != nil {
			return nil, fail(2, "connect to server %q: %v", configured.Name, err)
		}
		normalized, err := manifest.Build(tools)
		if err != nil {
			return nil, fail(2, "normalize tools for server %q: %v", configured.Name, err)
		}
		key := configured.Source + "\x00" + configured.Name
		locked := servers[key]
		locked.Tools = &normalized
		servers[key] = locked
	}
	file.Servers = file.Servers[:0]
	for _, server := range servers {
		file.Servers = append(file.Servers, server)
	}
	lockfile.Normalize(file)
	return file, nil
}

func connectionSpec(server config.Server, root string) (mcp.Spec, error) {
	spec := mcp.Spec{
		Name:      server.Name,
		Transport: server.Transport,
		Env:       server.Environment(),
		Headers:   server.Headers(),
	}
	switch strings.ToLower(server.Transport) {
	case "stdio":
		if server.Command == nil {
			return mcp.Spec{}, errors.New("stdio transport requires a command")
		}
		spec.Command = *server.Command
		spec.Args = append([]string(nil), server.Args...)
		spec.Dir = root
	case "http", "streamable-http", "streamable_http", "streamablehttp":
		if server.URL == nil {
			return mcp.Spec{}, errors.New("HTTP transport requires a URL")
		}
		spec.URL = *server.URL
	default:
		return mcp.Spec{}, fmt.Errorf("unsupported MCP transport %q", server.Transport)
	}
	return spec, nil
}

func checkLockfile(out io.Writer, path string, expected *lockfile.File) error {
	actual, err := safefile.ReadFile(path, lockfile.MaxBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, writeErr := fmt.Fprintf(out, "lockfile is out of date: %s is missing\n", displayText(path)); writeErr != nil {
				return fail(3, "write check output: %v", writeErr)
			}
			return failQuiet(1, "lockfile missing")
		}
		return fail(3, "read lockfile %s: %v", path, err)
	}
	expectedBytes, err := lockfile.Marshal(expected)
	if err != nil {
		return fail(3, "%v", err)
	}
	if !bytes.Equal(actual, expectedBytes) {
		if _, writeErr := fmt.Fprintf(out, "lockfile is out of date: %s\nrun `caplock lock` and review the diff\n", displayText(path)); writeErr != nil {
			return fail(3, "write check output: %v", writeErr)
		}
		return failQuiet(1, "lockfile out of date")
	}
	_, err = fmt.Fprintf(out, "lockfile is up to date (%s)\n", describeInventory(expected))
	return err
}

func describeInventory(file *lockfile.File) string {
	description := plural(len(file.Servers), "server")
	if countTools(file) > 0 || hasCollectedTools(file) {
		description += ", " + plural(countTools(file), "tool")
	}
	return description
}

func countTools(file *lockfile.File) int {
	count := 0
	for _, server := range file.Servers {
		if server.Tools != nil {
			count += len(*server.Tools)
		}
	}
	return count
}

func hasCollectedTools(file *lockfile.File) bool {
	for _, server := range file.Servers {
		if server.Tools != nil {
			return true
		}
	}
	return false
}

func newDiffCommand() *cobra.Command {
	var exitCode bool
	var jsonOutput bool
	command := &cobra.Command{
		Use:   "diff OLD NEW",
		Short: "Compare two lockfiles",
		Args:  cobra.ExactArgs(2),
		RunE: func(command *cobra.Command, args []string) error {
			oldFile, err := lockfile.Read(args[0])
			if err != nil {
				return fail(2, "%v", err)
			}
			newFile, err := lockfile.Read(args[1])
			if err != nil {
				return fail(2, "%v", err)
			}
			result := lockfile.CompareLockfiles(oldFile, newFile)
			if jsonOutput {
				if err := writeDiffJSON(command.OutOrStdout(), result); err != nil {
					return err
				}
			} else if err := writeDiffText(command.OutOrStdout(), result); err != nil {
				return err
			}
			if exitCode && result.HasChanges() {
				return failQuiet(1, "permission changes detected")
			}
			return nil
		},
	}
	command.Flags().BoolVar(&exitCode, "exit-code", false, "Exit with code 1 when permissions changed")
	command.Flags().BoolVar(&jsonOutput, "json", false, "Print machine-readable changes")
	return command
}

func newCompileCommand() *cobra.Command {
	var output string
	var format string
	command := &cobra.Command{
		Use:   "compile [POLICY]",
		Short: "Compile caplock.yaml into deterministic Policy IR",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			path := policy.Name
			if len(args) == 1 {
				path = args[0]
			}
			ir, err := policy.LoadFile(path)
			if err != nil {
				return fail(2, "%v", err)
			}
			issues := policy.Lint(ir, filepath.Base(path))
			if policy.HasErrors(issues) {
				return fail(1, "policy has lint errors; run `caplock lint %s`", displayText(path))
			}
			var data []byte
			switch strings.ToLower(format) {
			case "ir":
				data, err = json.MarshalIndent(ir, "", "  ")
				if err == nil {
					data = append(data, '\n')
				}
			case "json":
				data, err = json.Marshal(ir)
				if err == nil {
					data = append(data, '\n')
				}
			default:
				return fail(2, "unsupported format %q; use ir or json", format)
			}
			if err != nil {
				return fail(3, "serialize Policy IR: %v", err)
			}
			if output == "" {
				if _, err := command.OutOrStdout().Write(data); err != nil {
					return fail(3, "write Policy IR: %v", err)
				}
				return nil
			}
			// #nosec G306 -- Policy IR is a repository artifact intended to be readable.
			if err := os.WriteFile(output, data, 0o644); err != nil {
				return fail(3, "write Policy IR %s: %v", displayText(output), err)
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "wrote %s (%s)\n", displayText(output), plural(len(ir.Rules), "rule"))
			return err
		},
	}
	command.Flags().StringVarP(&output, "output", "o", "", "Write IR to a file instead of stdout")
	command.Flags().StringVar(&format, "format", "ir", "Output format: ir or json")
	return command
}

func newInitCommand() *cobra.Command {
	var force bool
	command := &cobra.Command{
		Use:   "init [DIR]",
		Short: "Create a starter caplock.yaml policy set",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			directory := "."
			if len(args) == 1 {
				directory = args[0]
			}
			path := filepath.Join(directory, policy.Name)
			flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
			if force {
				flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
			}
			// #nosec G302,G304 -- the user chooses the policy directory and this
			// artifact is intended to be committed and readable.
			file, err := os.OpenFile(path, flags, 0o644)
			if err != nil {
				if errors.Is(err, os.ErrExist) {
					return fail(2, "%s already exists; use --force to replace it", displayText(path))
				}
				return fail(3, "create %s: %v", displayText(path), err)
			}
			if _, err := io.WriteString(file, policyTemplate); err != nil {
				_ = file.Close()
				return fail(3, "write %s: %v", displayText(path), err)
			}
			if err := file.Close(); err != nil {
				return fail(3, "close %s: %v", displayText(path), err)
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "created %s\n", displayText(path))
			return err
		},
	}
	command.Flags().BoolVar(&force, "force", false, "Replace an existing caplock.yaml")
	return command
}

const policyTemplate = `# Caplock policy set. Compile with: caplock compile caplock.yaml
apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: agent-policy
  owner: security
spec:
  defaults:
    effect: deny
  subjects: []
  rules: []
  # Example rule:
  # - id: deny-destructive-tools
  #   effect: deny
  #   match:
  #     capability: [destructive]
  #   obligations: [audit, alert]
`

func newLintCommand() *cobra.Command {
	var strict bool
	var jsonOutput bool
	command := &cobra.Command{
		Use:   "lint [POLICY]",
		Short: "Lint a caplock.yaml policy set",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			path := policy.Name
			if len(args) == 1 {
				path = args[0]
			}
			ir, err := policy.LoadFile(path)
			if err != nil {
				return fail(2, "%v", err)
			}
			issues := policy.Lint(ir, filepath.Base(path))
			if jsonOutput {
				payload := struct {
					Version int            `json:"version"`
					Policy  string         `json:"policy"`
					Issues  []policy.Issue `json:"issues"`
				}{Version: 1, Policy: ir.Policy, Issues: issues}
				encoder := json.NewEncoder(command.OutOrStdout())
				encoder.SetIndent("", "  ")
				encoder.SetEscapeHTML(false)
				if err := encoder.Encode(payload); err != nil {
					return fail(3, "write lint output: %v", err)
				}
			} else if err := writeLintText(command.OutOrStdout(), issues); err != nil {
				return err
			}
			if policy.HasErrors(issues) || strict && len(issues) > 0 {
				return failQuiet(1, "policy lint findings")
			}
			return nil
		},
	}
	command.Flags().BoolVar(&strict, "strict", false, "Fail when warnings are present")
	command.Flags().BoolVar(&jsonOutput, "json", false, "Print machine-readable findings")
	return command
}

func writeLintText(out io.Writer, issues []policy.Issue) error {
	if len(issues) == 0 {
		_, err := fmt.Fprintln(out, "No policy lint findings.")
		return err
	}
	for _, issue := range issues {
		location := "policy"
		if issue.Source != nil {
			location = displayText(issue.Source.File)
			if issue.Source.Line > 0 {
				location += fmt.Sprintf(":%d", issue.Source.Line)
				if issue.Source.Column > 0 {
					location += fmt.Sprintf(":%d", issue.Source.Column)
				}
			}
		}
		if _, err := fmt.Fprintf(out, "%s: %s [%s] %s\n", location, issue.Severity, displayText(issue.Code), displayText(issue.Message)); err != nil {
			return err
		}
	}
	return nil
}

func writeDiffJSON(out io.Writer, result lockfile.Diff) error {
	payload := struct {
		Version int `json:"version"`
		lockfile.Diff
	}{Version: lockfile.Version, Diff: result}
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return fail(3, "write diff: %v", err)
	}
	return nil
}

func writeDiffText(out io.Writer, result lockfile.Diff) error {
	if !result.HasChanges() {
		_, err := fmt.Fprintln(out, "No permission changes.")
		return err
	}
	for _, server := range result.Added {
		if _, err := fmt.Fprintf(out, "+ %s (%s) added server\n", displayText(server.Name), displayText(server.Source)); err != nil {
			return err
		}
	}
	for _, server := range result.Removed {
		if _, err := fmt.Fprintf(out, "- %s (%s) removed server\n", displayText(server.Name), displayText(server.Source)); err != nil {
			return err
		}
	}
	for _, change := range result.Changed {
		if _, err := fmt.Fprintf(out, "~ %s (%s) %s\n", displayText(change.After.Name), displayText(change.After.Source), describeFields(change.Fields)); err != nil {
			return err
		}
		for _, tool := range change.ToolChanges {
			switch tool.Action {
			case "added":
				if _, err := fmt.Fprintf(out, "  + tool %s\n", displayText(tool.Name)); err != nil {
					return err
				}
			case "removed":
				if _, err := fmt.Fprintf(out, "  - tool %s\n", displayText(tool.Name)); err != nil {
					return err
				}
			case "changed":
				if _, err := fmt.Fprintf(out, "  ~ tool %s (%s)\n", displayText(tool.Name), displayText(strings.Join(tool.Fields, ", "))); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func describeFields(fields []string) string {
	hasConfig := contains(fields, "config")
	hasTools := contains(fields, "tools")
	switch {
	case hasConfig && hasTools:
		return "config and tool manifest changed"
	case hasConfig:
		return "config changed"
	case hasTools:
		return "tool manifest changed"
	case len(fields) == 0:
		return "changed"
	default:
		return strings.Join(fields, ", ") + " changed"
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func plural(count int, singular string) string {
	if count == 1 {
		return fmt.Sprintf("%d %s", count, singular)
	}
	return fmt.Sprintf("%d %ss", count, singular)
}

func displayText(value string) string {
	var builder strings.Builder
	for _, character := range value {
		switch character {
		case '\n':
			builder.WriteString(`\n`)
		case '\r':
			builder.WriteString(`\r`)
		case '\t':
			builder.WriteString(`\t`)
		default:
			if unicode.IsControl(character) || unicode.In(character, unicode.Cf, unicode.Zl, unicode.Zp) {
				if character <= 0xFF {
					_, _ = fmt.Fprintf(&builder, `\x%02x`, character)
				} else {
					_, _ = fmt.Fprintf(&builder, `\u%04x`, character)
				}
				continue
			}
			builder.WriteRune(character)
		}
	}
	return builder.String()
}
