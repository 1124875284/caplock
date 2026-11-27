package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/1124875284/caplock/internal/attackgraph"
	"github.com/1124875284/caplock/internal/lockfile"
	"github.com/1124875284/caplock/internal/policy"
)

func newGraphCommand() *cobra.Command {
	var lockfilePath string
	var subject string
	var format string
	var evaluationTime string
	var output string
	var maxPaths int
	var failOnExposed bool
	command := &cobra.Command{
		Use:   "graph [POLICY]",
		Short: "Search conservative source-to-sink MCP attack paths",
		Long: "Infer source, transform, and sink roles from captured tool capabilities, then evaluate bounded candidate paths against policy. " +
			"This is a heuristic attack-path review aid, not content-level dataflow proof.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			path := policy.Name
			if len(args) == 1 {
				path = args[0]
			}
			ir, issues, err := loadPolicyWithLint(path)
			if err != nil {
				return err
			}
			if policy.HasErrors(issues) {
				return fail(1, "policy has lint errors; run `caplock lint %s`", displayText(path))
			}
			file, err := lockfile.Read(lockfilePath)
			if err != nil {
				return fail(2, "%v", err)
			}
			options := attackgraph.Options{Subject: subject, MaxPaths: maxPaths}
			if strings.TrimSpace(evaluationTime) != "" {
				at, err := time.Parse(time.RFC3339, evaluationTime)
				if err != nil {
					return fail(2, "invalid --time %q; use RFC3339, for example 2026-01-01T12:00:00Z", evaluationTime)
				}
				options.At = at
			}
			result, err := attackgraph.Build(ir, file, options)
			if err != nil {
				return fail(2, "%v", err)
			}
			data, err := attackgraph.Render(result, format)
			if err != nil {
				return fail(2, "%v", err)
			}
			if strings.TrimSpace(output) == "" {
				if _, err := command.OutOrStdout().Write(data); err != nil {
					return fail(3, "write graph: %v", err)
				}
			} else {
				// #nosec G306 -- graph reports are reviewable repository/CI artifacts.
				if err := os.WriteFile(output, data, 0o644); err != nil {
					return fail(3, "write graph %s: %v", displayText(output), err)
				}
				if _, err := fmt.Fprintf(command.ErrOrStderr(), "wrote %s (%d candidate paths)\n", displayText(output), len(result.Paths)); err != nil {
					return fail(3, "write graph status: %v", err)
				}
			}
			if failOnExposed && exposedCount(result) > 0 {
				return failQuiet(1, "attack graph contains %d exposed high/critical path(s)", exposedCount(result))
			}
			return nil
		},
	}
	command.Flags().StringVar(&lockfilePath, "lockfile", lockfile.Name, "Lockfile with captured tools")
	command.Flags().StringVar(&subject, "subject", "agent", "Subject used for sink evaluation")
	command.Flags().StringVar(&format, "format", "text", "Output format: text, json, or yaml")
	command.Flags().StringVar(&evaluationTime, "time", "", "Evaluation instant in RFC3339 (default: 2026-01-01T12:00:00Z)")
	command.Flags().StringVarP(&output, "output", "o", "", "Write the graph to a file instead of stdout")
	command.Flags().IntVar(&maxPaths, "max-paths", attackgraph.DefaultMaxPaths, "Maximum candidate paths to emit")
	command.Flags().BoolVar(&failOnExposed, "fail-on-exposed", false, "Exit 1 when a high/critical path is allowed")
	return command
}

func exposedCount(result attackgraph.Result) int {
	count := 0
	for _, path := range result.Paths {
		if path.Status == "allowed" && (path.Severity == "high" || path.Severity == "critical") {
			count++
		}
	}
	return count
}
