package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/1124875284/caplock/internal/intent"
	"github.com/1124875284/caplock/internal/safefile"
)

func newDraftCommand() *cobra.Command {
	var output string
	var name string
	var subject string
	var parent string
	var defaultWindow string
	var force bool
	var listTemplates bool
	command := &cobra.Command{
		Use:   "draft [BRIEF]",
		Short: "Draft caplock.yaml from constrained natural-language statements",
		Long: "Compile a deterministic subset of natural-language security statements into caplock/v1alpha1 YAML. " +
			"This command uses explicit templates, not an LLM; use @template <id> to disambiguate a statement.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			if listTemplates {
				return writeTemplateList(command)
			}
			if len(args) != 1 {
				return fail(2, "draft requires a natural-language brief file")
			}
			briefPath := args[0]
			data, err := safefile.ReadFile(briefPath, intent.MaxBytes)
			if err != nil {
				return fail(2, "read policy brief: %v", err)
			}
			if strings.TrimSpace(name) == "" {
				name = draftPolicyName(briefPath)
			}
			result, err := intent.Compile(data, intent.Options{
				Name:          name,
				Subject:       subject,
				Parent:        parent,
				DefaultWindow: defaultWindow,
			})
			if err != nil {
				return fail(2, "%v", err)
			}
			rendered, err := intent.Render(result)
			if err != nil {
				return fail(3, "render drafted policy: %v", err)
			}
			if strings.TrimSpace(output) == "" {
				_, err := command.OutOrStdout().Write(rendered)
				return err
			}
			flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
			if force {
				flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
			}
			// #nosec G302,G304 -- the user chooses the output path and policies are readable artifacts.
			file, err := os.OpenFile(output, flags, 0o644)
			if err != nil {
				if errors.Is(err, os.ErrExist) {
					return fail(2, "%s already exists; use --force to replace it", displayText(output))
				}
				return fail(3, "create %s: %v", displayText(output), err)
			}
			if _, err := file.Write(rendered); err != nil {
				_ = file.Close()
				return fail(3, "write %s: %v", displayText(output), err)
			}
			if err := file.Close(); err != nil {
				return fail(3, "close %s: %v", displayText(output), err)
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "wrote %s (%d rules, %d statements mapped)\n", displayText(output), countDraftRules(result), len(result.Matches))
			return err
		},
	}
	command.Flags().StringVarP(&output, "output", "o", "", "Write policy YAML to a file instead of stdout")
	command.Flags().StringVar(&name, "name", "", "Policy metadata name (default: derived from the brief filename)")
	command.Flags().StringVar(&subject, "subject", intent.DefaultSubject, "Subject id used by generated rules")
	command.Flags().StringVar(&parent, "parent", intent.DefaultParent, "Parent subject for a generated delegation statement")
	command.Flags().StringVar(&defaultWindow, "default-window", intent.DefaultWindow, "Fallback time window when a finance statement omits one")
	command.Flags().BoolVar(&force, "force", false, "Replace an existing output file")
	command.Flags().BoolVar(&listTemplates, "list-templates", false, "List supported statement templates")
	return command
}

func writeTemplateList(command *cobra.Command) error {
	writer := tabwriter.NewWriter(command.OutOrStdout(), 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(writer, "TEMPLATE\tMEANING\tEXAMPLE"); err != nil {
		return fail(3, "write template list: %v", err)
	}
	for _, item := range intent.Templates() {
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\n", item.ID, item.Summary, item.Example); err != nil {
			return fail(3, "write template list: %v", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fail(3, "write template list: %v", err)
	}
	return nil
}

func draftPolicyName(path string) string {
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if strings.TrimSpace(base) == "" || base == "." || base == string(filepath.Separator) {
		return intent.DefaultName
	}
	return base
}

func countDraftRules(result intent.Result) int {
	if result.Document.Spec == nil || result.Document.Spec.Rules == nil {
		return 0
	}
	return len(*result.Document.Spec.Rules)
}
