package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/1124875284/caplock/internal/logimport"
	"github.com/1124875284/caplock/internal/safefile"
	"github.com/1124875284/caplock/internal/trace"
)

func newImportCommand() *cobra.Command {
	var mappingPath string
	var output string
	command := &cobra.Command{
		Use:   "import LOG",
		Short: "Map generic JSONL or CSV tool-call logs into Caplock trace JSONL",
		Long: "Use an explicit mapping file to import historical tool-call logs. Missing required fields, unknown formats, bad timestamps, and argument-hash mismatches fail closed. " +
			"Caplock never guesses vendor-specific fields.",
		Args: cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			mapping, err := logimport.LoadMapping(mappingPath)
			if err != nil {
				return fail(2, "%v", err)
			}
			data, err := safefile.ReadFile(args[0], trace.MaxBytes)
			if err != nil {
				return fail(2, "read input log %s: %v", displayText(args[0]), err)
			}
			records, err := logimport.Convert(bytes.NewReader(data), mapping)
			if err != nil {
				return fail(2, "%v", err)
			}
			if strings.TrimSpace(mapping.Fields["args"]) != "" {
				if _, err := fmt.Fprintln(command.ErrOrStderr(), "caplock import: warning: the mapping captures raw tool arguments; protect the output trace"); err != nil {
					return fail(3, "write import warning: %v", err)
				}
			}
			if strings.TrimSpace(output) == "" {
				writer := trace.NewJSONLWriter(command.OutOrStdout())
				for _, record := range records {
					if err := writer.Write(record); err != nil {
						return fail(3, "write imported trace: %v", err)
					}
				}
				return nil
			}
			if info, err := os.Lstat(output); err == nil && info.Mode()&os.ModeSymlink != 0 {
				return fail(3, "trace output %s must not be a symlink", displayText(output))
			} else if err != nil && !errors.Is(err, os.ErrNotExist) {
				return fail(3, "inspect trace output %s: %v", displayText(output), err)
			}
			// #nosec G304 -- the operator explicitly selects the trace output path.
			file, err := os.OpenFile(output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return fail(3, "open trace output %s: %v", displayText(output), err)
			}
			writer := trace.NewJSONLWriter(file)
			for _, record := range records {
				if err := writer.Write(record); err != nil {
					_ = file.Close()
					return fail(3, "write imported trace: %v", err)
				}
			}
			if err := file.Close(); err != nil {
				return fail(3, "close trace output %s: %v", displayText(output), err)
			}
			_, err = fmt.Fprintf(command.ErrOrStderr(), "wrote %s (%d trace records)\n", displayText(output), len(records))
			return err
		},
	}
	command.Flags().StringVar(&mappingPath, "mapping", "", "Explicit YAML/JSON field mapping file")
	command.Flags().StringVarP(&output, "output", "o", "", "Write trace JSONL to a file instead of stdout")
	_ = command.MarkFlagRequired("mapping")
	return command
}
