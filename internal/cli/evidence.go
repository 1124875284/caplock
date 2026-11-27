package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/caplock/caplock/internal/evidence"
	"github.com/caplock/caplock/internal/exporter"
	"github.com/caplock/caplock/internal/lockfile"
	"github.com/caplock/caplock/internal/policy"
	"github.com/caplock/caplock/internal/report"
)

type evidenceOptions struct {
	corpusPath   string
	baselinePath string
	lockfilePath string
	subject      string
}

func (o *evidenceOptions) addFlags(command *cobra.Command) {
	command.Flags().StringVar(&o.corpusPath, "corpus", "", "Attack corpus file (default: embedded 50-case baseline)")
	command.Flags().StringVar(&o.baselinePath, "baseline", "", "Previous policy to compare decisions against")
	command.Flags().StringVar(&o.lockfilePath, "lockfile", "", "Lockfile used for tool-coverage checks")
	command.Flags().StringVar(&o.subject, "subject", "agent", "Subject used for tool-coverage checks")
}

func (o *evidenceOptions) run(policyPath string) (evidence.Result, error) {
	ir, issues, err := loadPolicyWithLint(policyPath)
	if err != nil {
		return evidence.Result{}, err
	}
	if policy.HasErrors(issues) {
		return evidence.Result{}, fail(1, "policy has lint errors; run `caplock lint %s`", displayText(policyPath))
	}
	corpus, err := evidence.DefaultCorpus()
	if err != nil {
		return evidence.Result{}, fail(2, "load embedded evidence corpus: %v", err)
	}
	if strings.TrimSpace(o.corpusPath) != "" {
		corpus, err = evidence.Load(o.corpusPath)
		if err != nil {
			return evidence.Result{}, fail(2, "%v", err)
		}
	}
	options := evidence.Options{Subject: o.subject}
	if strings.TrimSpace(o.baselinePath) != "" {
		baseline, err := policy.LoadFile(o.baselinePath)
		if err != nil {
			return evidence.Result{}, fail(2, "load baseline policy: %v", err)
		}
		options.Baseline = baseline
	}
	if strings.TrimSpace(o.lockfilePath) != "" {
		file, err := lockfile.Read(o.lockfilePath)
		if err != nil {
			return evidence.Result{}, fail(2, "%v", err)
		}
		options.Lockfile = file
	}
	result, err := evidence.Run(ir, corpus, options)
	if err != nil {
		return evidence.Result{}, fail(2, "%v", err)
	}
	return result, nil
}

func loadPolicyWithLint(path string) (*policy.IR, []policy.Issue, error) {
	ir, err := policy.LoadFile(path)
	if err != nil {
		return nil, nil, fail(2, "%v", err)
	}
	return ir, policy.Lint(ir, filepath.Base(path)), nil
}

func newTestCommand() *cobra.Command {
	var options evidenceOptions
	var jsonOutput bool
	var allowFailures bool
	var failOnBaselineChange bool
	command := &cobra.Command{
		Use:   "test [POLICY]",
		Short: "Run the attack-path regression corpus against a policy",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			path := policy.Name
			if len(args) == 1 {
				path = args[0]
			}
			result, err := options.run(path)
			if err != nil {
				return err
			}
			if jsonOutput {
				encoder := json.NewEncoder(command.OutOrStdout())
				encoder.SetIndent("", "  ")
				encoder.SetEscapeHTML(false)
				if err := encoder.Encode(result); err != nil {
					return fail(3, "write test results: %v", err)
				}
			} else if _, err := command.OutOrStdout().Write(report.Text(report.Build(result))); err != nil {
				return fail(3, "write test results: %v", err)
			}
			if !result.Passed && !allowFailures {
				return failQuiet(1, "policy regression failed")
			}
			if failOnBaselineChange && len(result.BaselineChanges) > 0 {
				return failQuiet(1, "baseline decisions changed")
			}
			return nil
		},
	}
	options.addFlags(command)
	command.Flags().BoolVar(&jsonOutput, "json", false, "Print the full machine-readable evidence result")
	command.Flags().BoolVar(&allowFailures, "allow-failures", false, "Report failures without exiting 1")
	command.Flags().BoolVar(&failOnBaselineChange, "fail-on-baseline-change", false, "Exit 1 when any baseline decision changes")
	return command
}

func newReportCommand() *cobra.Command {
	var options evidenceOptions
	var format string
	var output string
	var failOnGaps bool
	command := &cobra.Command{
		Use:   "report [POLICY]",
		Short: "Render an attack-path, policy-gap, and coverage report",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			path := policy.Name
			if len(args) == 1 {
				path = args[0]
			}
			result, err := options.run(path)
			if err != nil {
				return err
			}
			document := report.Build(result)
			data, err := renderReport(document, format)
			if err != nil {
				return fail(2, "%v", err)
			}
			if strings.TrimSpace(output) == "" {
				if _, err := command.OutOrStdout().Write(data); err != nil {
					return fail(3, "write report: %v", err)
				}
			} else {
				// #nosec G306 -- reports are repository/CI artifacts intended to be readable.
				if err := os.WriteFile(output, data, 0o644); err != nil {
					return fail(3, "write report %s: %v", displayText(output), err)
				}
				if _, err := fmt.Fprintf(command.ErrOrStderr(), "wrote %s\n", displayText(output)); err != nil {
					return fail(3, "write report status: %v", err)
				}
			}
			if failOnGaps && len(document.Gaps) > 0 {
				return failQuiet(1, "policy gaps detected")
			}
			return nil
		},
	}
	options.addFlags(command)
	command.Flags().StringVar(&format, "format", "text", "Output format: text, json, html, or sarif")
	command.Flags().StringVarP(&output, "output", "o", "", "Write the report to a file instead of stdout")
	command.Flags().BoolVar(&failOnGaps, "fail-on-gaps", false, "Exit 1 when the report contains gaps")
	return command
}

func renderReport(document report.Report, format string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "text", "txt":
		return report.Text(document), nil
	case "json":
		return report.JSON(document)
	case "html":
		return report.HTML(document)
	case "sarif":
		return report.SARIF(document)
	default:
		return nil, fmt.Errorf("unsupported report format %q; use text, json, html, or sarif", format)
	}
}

func newExportCommand() *cobra.Command {
	var format string
	var output string
	command := &cobra.Command{
		Use:   "export [POLICY]",
		Short: "Export compiled policy as Rego, Cedar, YAML, JSON, or SDK config",
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
			data, err := exporter.Render(ir, format)
			if err != nil {
				return fail(2, "%v", err)
			}
			if strings.TrimSpace(output) == "" {
				if _, err := command.OutOrStdout().Write(data); err != nil {
					return fail(3, "write export: %v", err)
				}
				return nil
			}
			// #nosec G306 -- exports are repository/runtime artifacts intended to be readable.
			if err := os.WriteFile(output, data, 0o644); err != nil {
				return fail(3, "write export %s: %v", displayText(output), err)
			}
			_, err = fmt.Fprintf(command.OutOrStdout(), "wrote %s (%s)\n", displayText(output), strings.ToLower(format))
			return err
		},
	}
	command.Flags().StringVar(&format, "format", "rego", "Output format: rego, cedar, yaml, json, or sdk")
	command.Flags().StringVarP(&output, "output", "o", "", "Write the export to a file instead of stdout")
	return command
}
