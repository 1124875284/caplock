// Package inventory classifies tool behavior into a small, deterministic
// capability vocabulary. Classification is a review aid, not an authorization
// decision.
package inventory

import (
	"sort"
	"strings"
	"unicode"
)

// Capability names used in lockfiles. The vocabulary is intentionally small
// and stable so policy rules can target it across MCP servers.
const (
	CapabilityRead        = "read"
	CapabilityWrite       = "write"
	CapabilityExecute     = "execute"
	CapabilityNetwork     = "network"
	CapabilityIdentity    = "identity"
	CapabilityFinance     = "finance"
	CapabilityComms       = "comms"
	CapabilityDestructive = "destructive"
	CapabilityExternal    = "external"
	CapabilityUnknown     = "unknown"
)

var keywords = map[string][]string{
	"read":        {"read", "get", "list", "search", "find", "query", "inspect", "view", "fetch", "download", "open", "stat", "describe"},
	"write":       {"write", "create", "update", "patch", "set", "put", "upload", "append", "insert", "modify", "move", "copy", "save"},
	"execute":     {"execute", "exec", "run", "shell", "command", "spawn", "script", "invoke", "launch"},
	"network":     {"http", "https", "url", "uri", "web", "network", "api", "curl", "browse", "remote"},
	"identity":    {"identity", "auth", "oauth", "token", "credential", "credentials", "secret", "password", "user", "role", "permission", "login", "session"},
	"finance":     {"finance", "financial", "payment", "payments", "invoice", "invoices", "refund", "transfer", "billing", "balance", "transaction", "transactions", "order", "orders", "price"},
	"comms":       {"email", "emails", "mail", "message", "messages", "send", "slack", "sms", "chat", "notify", "notification", "post", "publish", "comment"},
	"destructive": {"delete", "remove", "drop", "destroy", "truncate", "purge", "revoke", "deactivate", "disable", "overwrite", "terminate"},
	"external":    {"external", "internet", "web", "browser", "third_party", "thirdparty", "remote", "public"},
}

// Classify returns a sorted set of capabilities suggested by a tool's name,
// description, and MCP annotations. Unknown tools are labeled "unknown" rather
// than being treated as safe.
func Classify(name, description string, annotations map[string]bool) []string {
	capabilities := make(map[string]bool)
	if annotations["readOnlyHint"] {
		capabilities[CapabilityRead] = true
	}
	if annotations["destructiveHint"] {
		capabilities[CapabilityDestructive] = true
	}
	if annotations["openWorldHint"] {
		capabilities[CapabilityExternal] = true
		capabilities[CapabilityNetwork] = true
	}

	tokens := make(map[string]bool)
	for _, token := range tokenize(name + " " + description) {
		tokens[token] = true
	}
	for capability, words := range keywords {
		for _, word := range words {
			if tokens[word] {
				capabilities[capability] = true
				break
			}
		}
	}
	if capabilities[CapabilityDestructive] {
		capabilities[CapabilityWrite] = true
	}
	if len(capabilities) == 0 {
		capabilities[CapabilityUnknown] = true
	}

	result := make([]string, 0, len(capabilities))
	for capability := range capabilities {
		result = append(result, capability)
	}
	sort.Strings(result)
	return result
}

// ClassifyDetailed adds dotted sub-capabilities used by finer-grained policy
// rules while preserving the stable base vocabulary returned by Classify.
func ClassifyDetailed(name, description string, annotations map[string]bool) []string {
	base := Classify(name, description, annotations)
	set := make(map[string]bool, len(base)+4)
	for _, capability := range base {
		set[capability] = true
	}
	tokens := make(map[string]bool)
	for _, token := range tokenize(name + " " + description) {
		tokens[token] = true
	}
	hasAny := func(values ...string) bool {
		for _, value := range values {
			if tokens[value] {
				return true
			}
		}
		return false
	}
	if set[CapabilityFinance] {
		if hasAny("write", "update", "transfer", "pay", "payment", "refund", "create", "modify") {
			set["finance.write"] = true
		}
		if hasAny("approve", "approval", "authorize", "authorise") {
			set["finance.approve"] = true
		}
	}
	if set[CapabilityIdentity] && hasAny("write", "create", "assign", "grant", "update", "revoke", "delete") {
		set["identity.write"] = true
	}
	if set[CapabilityExternal] && hasAny("read", "fetch", "browse", "search", "download") {
		set["external.read"] = true
	}
	result := make([]string, 0, len(set))
	for capability := range set {
		result = append(result, capability)
	}
	sort.Strings(result)
	return result
}

// Sink returns a conservative dotted sink name for policy matching. The
// mapping is a heuristic review/runtime aid, not a proof of dataflow.
func Sink(name string, capabilities []string) string {
	normalized := strings.ToLower(strings.NewReplacer("_", " ", "-", " ", ".", " ").Replace(name))
	has := func(values ...string) bool {
		for _, value := range values {
			if strings.Contains(normalized, value) {
				return true
			}
		}
		return false
	}
	hasCapability := func(value string) bool {
		for _, capability := range capabilities {
			if capability == value {
				return true
			}
		}
		return false
	}
	switch {
	case has("email", "mail") && has("send", "message"):
		return "email.send"
	case has("slack"):
		return "slack.send"
	case has("sms", "text") && has("send"):
		return "sms.send"
	case has("webhook"):
		return "webhook.send"
	case has("upload"):
		return "file.upload"
	case has("web", "browse", "fetch", "scrape") && hasCapability(CapabilityRead):
		return "web.fetch"
	case has("http", "api", "request") && has("post", "put", "write", "send"):
		return "http.post"
	case has("shell", "exec", "command"):
		return "shell.exec"
	case has("database", "sql", "query"):
		return "database.query"
	case has("delete", "remove", "drop", "truncate"):
		return "storage.delete"
	case has("write", "create", "update", "put", "save"):
		return "file.write"
	case has("read", "get", "list", "find", "search"):
		return "file.read"
	default:
		return name
	}
}

func tokenize(value string) []string {
	var tokens []string
	var current []rune
	flush := func() {
		if len(current) > 0 {
			tokens = append(tokens, strings.ToLower(string(current)))
			current = current[:0]
		}
	}
	runes := []rune(value)
	for index, character := range runes {
		if !unicode.IsLetter(character) && !unicode.IsDigit(character) {
			flush()
			continue
		}
		if unicode.IsUpper(character) && len(current) > 0 {
			previous := runes[index-1]
			if unicode.IsLower(previous) || unicode.IsDigit(previous) {
				flush()
			}
		}
		current = append(current, unicode.ToLower(character))
	}
	flush()
	return tokens
}
