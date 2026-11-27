// Command gen writes a deterministic 20-server lockfile used by the local
// benchmark. The server names are synthetic; this harness does not contact
// external MCP servers.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/1124875284/caplock/internal/lockfile"
)

type fixture struct {
	server       string
	tool         string
	capabilities []string
}

func main() {
	output := flag.String("output", "bench/generated/caplock.lock", "lockfile output path")
	flag.Parse()
	fixtures := []fixture{
		{"browser", "browser_fetch", []string{"external", "external.read", "read"}},
		{"files", "read_file", []string{"read"}},
		{"database", "query_db", []string{"read"}},
		{"reports", "read_report", []string{"read"}},
		{"crm", "read_customer", []string{"read"}},
		{"secrets", "get_secret", []string{"identity", "read"}},
		{"identity", "get_token", []string{"identity", "read"}},
		{"mail", "send_email", []string{"comms", "network"}},
		{"slack", "slack_post", []string{"comms", "network"}},
		{"hook", "webhook_send", []string{"network"}},
		{"sms", "sms_send", []string{"comms", "network"}},
		{"upload", "upload_file", []string{"external", "network"}},
		{"http", "http_post", []string{"network"}},
		{"shell", "run_shell", []string{"execute"}},
		{"storage", "delete_bucket", []string{"destructive", "network"}},
		{"files-write", "write_file", []string{"write"}},
		{"rbac", "assign_role", []string{"identity"}},
		{"finance", "transfer_funds", []string{"finance.write"}},
		{"approvals", "approve_invoice", []string{"finance.approve"}},
		{"warehouse", "truncate_table", []string{"destructive", "write"}},
	}
	file := &lockfile.File{Version: lockfile.Version, Servers: make([]lockfile.Server, 0, len(fixtures))}
	for index, item := range fixtures {
		command := "bench-null"
		tool := lockfile.Tool{
			Name:            item.tool,
			DescriptionHash: fmt.Sprintf("sha256:%064x", index+1),
			InputSchemaHash: fmt.Sprintf("sha256:%064x", index+101),
			Capabilities:    item.capabilities,
		}
		tools := []lockfile.Tool{tool}
		file.Servers = append(file.Servers, lockfile.Server{
			Name:       item.server,
			Source:     "bench/servers.yaml",
			Transport:  "stdio",
			Command:    &command,
			Args:       []string{},
			EnvKeys:    []string{},
			HeaderKeys: []string{},
			ConfigHash: fmt.Sprintf("sha256:%064x", index+201),
			Tools:      &tools,
		})
	}
	if err := lockfile.Write(*output, file); err != nil {
		fmt.Fprintln(os.Stderr, "bench gen:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d servers, %d tools)\n", *output, len(file.Servers), len(file.Servers))
}
