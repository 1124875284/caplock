package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/caplock/caplock/internal/lockfile"
	"github.com/caplock/caplock/internal/matrix"
	"github.com/caplock/caplock/internal/policy"
)

func newMatrixCommand() *cobra.Command {
	var lockfilePath string
	var subject string
	var format string
	var evaluationTime string
	var output string
	command := &cobra.Command{
		Use:   "matrix [POLICY]",
		Short: "Render a subject-by-tool least-privilege matrix",
		Args:  cobra.MaximumNArgs(1),
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
			options := matrix.Options{Subject: subject}
			if strings.TrimSpace(evaluationTime) != "" {
				at, err := time.Parse(time.RFC3339, evaluationTime)
				if err != nil {
					return fail(2, "invalid --time %q; use RFC3339, for example 2026-01-01T12:00:00Z", evaluationTime)
				}
				options.At = at
			}
			result, err := matrix.Build(ir, file, options)
			if err != nil {
				return fail(2, "%v", err)
			}
			data, err := matrix.Render(result, format)
			if err != nil {
				return fail(2, "%v", err)
			}
			if strings.TrimSpace(output) == "" {
				_, err := command.OutOrStdout().Write(data)
				return err
			}
			// #nosec G306 -- matrices are repository/CI artifacts intended to be readable.
			if err := os.WriteFile(output, data, 0o644); err != nil {
				return fail(3, "write matrix %s: %v", displayText(output), err)
			}
			_, err = fmt.Fprintf(command.ErrOrStderr(), "wrote %s (%d tools)\n", displayText(output), result.Summary.Tools)
			return err
		},
	}
	command.Flags().StringVar(&lockfilePath, "lockfile", lockfile.Name, "Lockfile with captured tools")
	command.Flags().StringVar(&subject, "subject", "agent", "Subject used for the matrix")
	command.Flags().StringVar(&format, "format", "text", "Output format: text, json, yaml, or csv")
	command.Flags().StringVar(&evaluationTime, "time", "", "Evaluation instant in RFC3339 (default: 2026-01-01T12:00:00Z)")
	command.Flags().StringVarP(&output, "output", "o", "", "Write the matrix to a file instead of stdout")
	return command
}
