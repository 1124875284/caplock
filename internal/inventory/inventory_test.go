package inventory

import (
	"reflect"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name        string
		tool        string
		description string
		annotations map[string]bool
		want        []string
	}{
		{name: "read", tool: "read_file", description: "Read a file", want: []string{"read"}},
		{name: "camel case write", tool: "createIssue", description: "Create an issue", want: []string{"write"}},
		{name: "destructive", tool: "delete_repository", description: "Delete a repo", want: []string{"destructive", "write"}},
		{name: "execute", tool: "run_shell", description: "Run a shell command", want: []string{"execute"}},
		{name: "comms", tool: "send_email", description: "Send a message", want: []string{"comms"}},
		{name: "finance", tool: "create_invoice", description: "Create a payment request", want: []string{"finance", "write"}},
		{name: "annotations", tool: "mystery", description: "Does a thing", annotations: map[string]bool{"readOnlyHint": true, "openWorldHint": true}, want: []string{"external", "network", "read"}},
		{name: "unknown", tool: "mystery", description: "Does a thing", want: []string{"unknown"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Classify(test.tool, test.description, test.annotations); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("Classify() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestClassifyDetailed(t *testing.T) {
	tests := []struct {
		name        string
		tool        string
		description string
		want        []string
	}{
		{name: "finance write", tool: "transfer_funds", description: "Transfer money to a vendor", want: []string{"finance", "finance.write"}},
		{name: "finance approve", tool: "approve_invoice", description: "Approve an invoice", want: []string{"finance", "finance.approve"}},
		{name: "identity write", tool: "update_user_role", description: "Assign a role to a user", want: []string{"identity", "identity.write", "write"}},
		{name: "external read", tool: "fetch_web_page", description: "Download a public page", want: []string{"external", "external.read", "network", "read"}},
		{name: "base only", tool: "read_file", description: "Read a file", want: []string{"read"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ClassifyDetailed(test.tool, test.description, nil); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ClassifyDetailed() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestSink(t *testing.T) {
	tests := []struct {
		name         string
		tool         string
		capabilities []string
		want         string
	}{
		{name: "email", tool: "send_email", capabilities: []string{"comms"}, want: "email.send"},
		{name: "slack", tool: "post_to_slack", capabilities: []string{"comms"}, want: "slack.send"},
		{name: "sms", tool: "send_sms", capabilities: []string{"comms"}, want: "sms.send"},
		{name: "webhook", tool: "post_webhook", capabilities: []string{"comms", "network"}, want: "webhook.send"},
		{name: "upload", tool: "upload_file", capabilities: []string{"write"}, want: "file.upload"},
		{name: "web fetch", tool: "fetch_web_page", capabilities: []string{"read", "external"}, want: "web.fetch"},
		{name: "http post", tool: "http_post", capabilities: []string{"network", "write"}, want: "http.post"},
		{name: "shell", tool: "run_shell", capabilities: []string{"execute"}, want: "shell.exec"},
		{name: "database", tool: "sql_query", capabilities: []string{"read"}, want: "database.query"},
		{name: "delete", tool: "delete_file", capabilities: []string{"destructive", "write"}, want: "storage.delete"},
		{name: "write", tool: "write_file", capabilities: []string{"write"}, want: "file.write"},
		{name: "read", tool: "read_file", capabilities: []string{"read"}, want: "file.read"},
		{name: "unknown", tool: "mystery_tool", capabilities: []string{"unknown"}, want: "mystery_tool"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Sink(test.tool, test.capabilities); got != test.want {
				t.Fatalf("Sink() = %q, want %q", got, test.want)
			}
		})
	}
}
