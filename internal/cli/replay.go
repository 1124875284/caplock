package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/caplock/caplock/internal/policy"
	"github.com/caplock/caplock/internal/trace"
)

func newReplayCommand() *cobra.Command {
	var policyPath string
	var format string
	var output string
	var failOnChange bool
	var failOnWeakened bool
	var strictArgs bool
	var allowArgsHashMismatch bool
	command := &cobra.Command{
		Use:   "replay TRACE",
		Short: "Replay a captured tool-call trace against a policy revision",
		Long: "Evaluate every recorded tool call against the current policy and report decision changes. " +
			"Records captured with arguments report precise diffs; hash-only records still replay non-argument facts and are marked args_missing.",
		Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			ir, issues, err := loadPolicyWithLint(policyPath)
			if err != nil {
				return err
			}
			if policy.HasErrors(issues) {
				return fail(1, "policy has lint errors; run `caplock lint %s`", displayText(policyPath))
			}
			records, err := trace.ReadFile(args[0])
			if err != nil {
				return fail(2, "%v", err)
			}
			result, err := trace.Replay(ir, records, trace.ReplayOptions{
				Source:                   args[0],
				SkipArgsHashVerification: allowArgsHashMismatch,
			})
			if err != nil {
				return fail(2, "%v", err)
			}
			data, err := trace.Render(result, format)
			if err != nil {
				return fail(2, "%v", err)
			}
			if strings.TrimSpace(output) == "" {
				if _, err := command.OutOrStdout().Write(data); err != nil {
					return fail(3, "write replay output: %v", err)
				}
			} else {
				// #nosec G306 -- replay reports are reviewable repository/CI artifacts.
				if err := os.WriteFile(output, data, 0o644); err != nil {
					return fail(3, "write replay output %s: %v", displayText(output), err)
				}
				if _, err := fmt.Fprintf(command.ErrOrStderr(), "wrote %s (%d changes)\n", displayText(output), result.Changed); err != nil {
					return fail(3, "write replay status: %v", err)
				}
			}
			if strictArgs && result.ArgsMissing > 0 {
				return fail(1, "trace replay is partial: %d record(s) have no captured arguments", result.ArgsMissing)
			}
			if failOnWeakened && result.Weakened > 0 {
				return fail(1, "trace replay found %d weakened decision(s)", result.Weakened)
			}
			if failOnChange && result.Changed > 0 {
				return fail(1, "trace replay found %d changed decision(s)", result.Changed)
			}
			return nil
		},
	}
	command.Flags().StringVar(&policyPath, "policy", policy.Name, "Policy to replay against")
	command.Flags().StringVar(&format, "format", "text", "Output format: text or json")
	command.Flags().StringVarP(&output, "output", "o", "", "Write the replay report to a file instead of stdout")
	command.Flags().BoolVar(&failOnChange, "fail-on-change", false, "Exit 1 when any decision changes")
	command.Flags().BoolVar(&failOnWeakened, "fail-on-weakened", false, "Exit 1 when a decision becomes weaker")
	command.Flags().BoolVar(&strictArgs, "strict-args", false, "Exit 1 when any record lacks captured arguments")
	command.Flags().BoolVar(&allowArgsHashMismatch, "allow-args-hash-mismatch", false, "Do not reject captured arguments whose argsHash does not match (reviewed imports only)")
	return command
}
