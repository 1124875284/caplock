package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/1124875284/caplock/internal/evidence"
	"github.com/1124875284/caplock/internal/policy"
	"github.com/1124875284/caplock/internal/trace"
)

func newCorpusCommand() *cobra.Command {
	var policyPath string
	var output string
	command := &cobra.Command{
		Use:   "corpus TRACE",
		Short: "Generate reviewable regression candidates from a captured trace",
		Long: "Evaluate each observed tool call against the current policy and emit a caplock evidence corpus. " +
			"Expectations record current behavior, are tagged review-required, and are not a proof of least privilege.",
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
			corpus, err := evidence.FromTrace(ir, records, args[0])
			if err != nil {
				return fail(2, "%v", err)
			}
			data, err := evidence.Marshal(corpus)
			if err != nil {
				return fail(2, "serialize candidate corpus: %v", err)
			}
			if strings.TrimSpace(output) == "" {
				_, err = command.OutOrStdout().Write(data)
				return err
			}
			// #nosec G306 -- candidate corpora are reviewable repository artifacts.
			if err := os.WriteFile(output, data, 0o644); err != nil {
				return fail(3, "write corpus %s: %v", displayText(output), err)
			}
			_, err = fmt.Fprintf(command.ErrOrStderr(), "wrote %s (%d review candidates; expected decisions reflect current behavior)\n", displayText(output), len(corpus.Cases))
			return err
		},
	}
	command.Flags().StringVar(&policyPath, "policy", policy.Name, "Policy used to capture current decisions")
	command.Flags().StringVarP(&output, "output", "o", "", "Write the candidate corpus to a file instead of stdout")
	return command
}
