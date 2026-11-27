// Package intent compiles a constrained, deterministic subset of natural-language
// security statements into caplock/v1alpha1 policy source.
//
// This is intentionally a template compiler, not a general-purpose language
// model. Unrecognized statements fail with a diagnostic instead of being guessed.
package intent

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/caplock/caplock/internal/policy"
)

const (
	// MaxBytes bounds the natural-language brief Caplock will read.
	MaxBytes = 1 << 20
	// DefaultName is used when no policy name is supplied.
	DefaultName = "draft-policy"
	// DefaultSubject is used when no subject is supplied.
	DefaultSubject = "agent"
	// DefaultParent is used for a generated delegation relationship.
	DefaultParent = "parent-agent"
	// DefaultWindow is used when a finance statement omits a window.
	DefaultWindow = "Mon-Fri 09:00-18:00 Asia/Shanghai"
)

// Options controls policy metadata and generated delegation subjects.
type Options struct {
	Name          string
	Subject       string
	Parent        string
	DefaultWindow string
}

// Diagnostic is one rejected source line.
type Diagnostic struct {
	Line    int
	Message string
}

// CompileError reports all source statements that could not be compiled.
type CompileError struct {
	Diagnostics []Diagnostic
}

func (e *CompileError) Error() string {
	if len(e.Diagnostics) == 0 {
		return "natural-language policy is invalid"
	}
	parts := make([]string, 0, len(e.Diagnostics))
	for _, diagnostic := range e.Diagnostics {
		parts = append(parts, fmt.Sprintf("line %d: %s", diagnostic.Line, diagnostic.Message))
	}
	return strings.Join(parts, "; ")
}

// TemplateInfo describes one supported statement template.
type TemplateInfo struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	Example string `json:"example"`
}

// Match records how a source statement became a policy rule or subject.
type Match struct {
	Line      int    `json:"line"`
	Template  string `json:"template"`
	Statement string `json:"statement"`
	Kind      string `json:"kind"`
	RuleID    string `json:"ruleId,omitempty"`
	Subject   string `json:"subject,omitempty"`
	Parent    string `json:"parent,omitempty"`
}

// Result is a generated policy source document plus a line-level trace.
type Result struct {
	Document policy.Document
	Matches  []Match
}

type statement struct {
	line     int
	text     string
	template string
}

type buildResult struct {
	rule    *policy.Rule
	subject *policy.Subject
}

type template struct {
	info  TemplateInfo
	match func(string) bool
	build func(string, Options) (buildResult, bool)
}

var templates = []template{
	{
		info: TemplateInfo{
			ID:      "delegation-attenuate-only",
			Summary: "Child agents may not exceed their parent's authority",
			Example: "Child agents must not exceed their parent permissions.",
		},
		match: func(text string) bool {
			return hasAny(text, "child agent", "sub-agent", "sub agent", "子 agent", "子agent", "子代理") &&
				hasAny(text, "parent", "父 agent", "父agent", "父代理") &&
				hasAny(text, "must not exceed", "cannot exceed", "may not exceed", "不得超过", "不得高于", "不能超过", "不能高于")
		},
		build: func(_ string, options Options) (buildResult, bool) {
			parent := options.Parent
			return buildResult{subject: &policy.Subject{ID: options.Subject, Parent: parent, Delegation: policy.DelegationAttenuateOnly}}, true
		},
	},
	{
		info: TemplateInfo{
			ID:      "deny-privileged-path-write",
			Summary: "Deny writes below a privileged path",
			Example: "Deny writes below /etc/.",
		},
		match: func(text string) bool {
			return hasDeny(text) && hasWrite(text) && hasAny(text, "/etc/", "/var/", "/root/", "c:\\windows", "system directory", "系统目录")
		},
		build: func(text string, _ Options) (buildResult, bool) {
			prefix := "/etc/"
			for _, candidate := range []string{"/etc/", "/var/", "/root/", "C:\\Windows\\"} {
				if strings.Contains(lower(text), lower(candidate)) {
					prefix = candidate
					break
				}
			}
			return ruleResult("deny-privileged-file-write", policy.EffectDeny, &policy.Match{
				Capability: []string{"write"},
				Args:       map[string]any{"path": map[string]any{"$prefix": prefix}},
			}, 100, "audit", "alert"), true
		},
	},
	{
		info: TemplateInfo{
			ID:      "deny-admin-role-assignment",
			Summary: "Deny assigning administrator or owner roles",
			Example: "Deny assignment of admin, owner, or superuser roles.",
		},
		match: func(text string) bool {
			return hasDeny(text) && hasAny(text, "role", "角色") && hasAny(text, "admin", "owner", "superuser", "administrator", "管理员", "超级用户")
		},
		build: func(_ string, _ Options) (buildResult, bool) {
			return ruleResult("deny-admin-role-assignment", policy.EffectDeny, &policy.Match{
				Capability: []string{"identity"},
				Args:       map[string]any{"role": map[string]any{"$in": []any{"admin", "owner", "superuser"}}},
			}, 100, "audit", "alert"), true
		},
	},
	{
		info: TemplateInfo{
			ID:      "deny-secret-egress",
			Summary: "Deny secret data leaving through outbound tools",
			Example: "Deny secret data from leaving through email, network, or upload tools.",
		},
		match: func(text string) bool {
			return hasDeny(text) && hasAny(text, "secret", "credential", "密钥", "机密", "凭证") && hasEgress(text)
		},
		build: func(_ string, _ Options) (buildResult, bool) {
			return ruleResult("deny-secret-exfiltration", policy.EffectDeny, &policy.Match{
				Capability: []string{"comms", "external", "network"},
				DataClass:  []string{"secret"},
			}, 100, "audit", "alert", "redact"), true
		},
	},
	{
		info: TemplateInfo{
			ID:      "deny-external-provenance-egress",
			Summary: "Deny untrusted external content reaching an outbound sink",
			Example: "External web content must not flow to an email, Slack, or webhook sink.",
		},
		match: func(text string) bool {
			return hasDeny(text) && hasExternal(text) && hasEgress(text)
		},
		build: func(text string, _ Options) (buildResult, bool) {
			match := provenanceEgressMatch(text)
			return ruleResult("deny-external-provenance-egress", policy.EffectDeny, match, 100, "audit", "alert", "redact"), true
		},
	},
	{
		info: TemplateInfo{
			ID:      "require-approval-external-provenance",
			Summary: "Require approval when external content reaches an outbound sink",
			Example: "Require approval when external web content reaches email, Slack, or a webhook.",
		},
		match: func(text string) bool {
			return hasApproval(text) && hasExternal(text) && hasEgress(text)
		},
		build: func(text string, _ Options) (buildResult, bool) {
			match := provenanceEgressMatch(text)
			return ruleResult("approve-external-provenance-egress", policy.EffectRequireApproval, match, 90, "audit", "human_approval", "redact"), true
		},
	},
	{
		info: TemplateInfo{
			ID:      "require-approval-pii-egress",
			Summary: "Require approval when PII leaves through an outbound tool",
			Example: "Require human approval when PII is sent to an external destination.",
		},
		match: func(text string) bool {
			return hasApproval(text) && hasAny(text, "pii", "personal data", "个人信息", "个人数据", "敏感数据") && hasEgress(text)
		},
		build: func(_ string, _ Options) (buildResult, bool) {
			return ruleResult("approve-pii-egress", policy.EffectRequireApproval, &policy.Match{
				Capability: []string{"comms", "external", "network"},
				DataClass:  []string{"pii"},
			}, 85, "audit", "human_approval", "redact"), true
		},
	},
	{
		info: TemplateInfo{
			ID:      "deny-finance-after-hours",
			Summary: "Deny finance writes outside a business-hours window",
			Example: "Deny finance writes outside Mon-Fri 09:00-18:00 Asia/Shanghai.",
		},
		match: func(text string) bool {
			return hasDeny(text) && hasAny(text, "finance", "financial", "财务", "资金") &&
				hasAny(text, "after hours", "outside", "outside business hours", "non-business", "non working", "非工作时间", "非营业时间", "下班")
		},
		build: func(text string, options Options) (buildResult, bool) {
			window := extractWindow(text)
			if window == "" {
				window = options.DefaultWindow
			}
			if _, err := policy.CompileTimeWindow(window); err != nil {
				return buildResult{}, false
			}
			return ruleResult("finance-write-after-hours", policy.EffectDeny, &policy.Match{
				Capability: []string{"finance.write", "finance.approve"},
				Context:    &policy.Context{Time: &policy.TimeWindow{Outside: window}},
			}, 95, "audit", "alert"), true
		},
	},
	{
		info: TemplateInfo{
			ID:      "require-approval-large-finance-transfer",
			Summary: "Require approval for finance operations carrying an amount",
			Example: "Require approval for finance transfers with an amount.",
		},
		match: func(text string) bool {
			return hasApproval(text) && hasAny(text, "finance", "financial", "财务", "资金") &&
				hasAny(text, "transfer", "payment", "amount", "转账", "付款", "金额")
		},
		build: func(_ string, _ Options) (buildResult, bool) {
			return ruleResult("approve-finance-transfer", policy.EffectRequireApproval, &policy.Match{
				Capability: []string{"finance.write"},
				Args:       map[string]any{"amount": map[string]any{"$exists": true}},
			}, 80, "audit", "human_approval"), true
		},
	},
	{
		info: TemplateInfo{
			ID:      "deny-production-destructive",
			Summary: "Deny destructive operations in production",
			Example: "Deny destructive operations in the production environment.",
		},
		match: func(text string) bool {
			return hasDeny(text) && hasDestructive(text) && hasAny(text, "production", "prod", "生产环境", "生产")
		},
		build: func(_ string, _ Options) (buildResult, bool) {
			return ruleResult("deny-production-destructive", policy.EffectDeny, &policy.Match{
				Capability: []string{"destructive"},
				Context:    &policy.Context{Environment: "production"},
			}, 100, "audit", "alert"), true
		},
	},
	{
		info: TemplateInfo{
			ID:      "deny-shell-execution",
			Summary: "Deny shell and command execution",
			Example: "Deny shell command execution.",
		},
		match: func(text string) bool {
			return hasDeny(text) && hasAny(text, "shell", "command execution", "execute command", "命令执行", "执行命令", "终端命令")
		},
		build: func(_ string, _ Options) (buildResult, bool) {
			return ruleResult("deny-shell-execution", policy.EffectDeny, &policy.Match{
				Capability: []string{"execute"},
			}, 100, "audit", "alert"), true
		},
	},
	{
		info: TemplateInfo{
			ID:      "deny-destructive-capability",
			Summary: "Deny destructive tool calls",
			Example: "Deny destructive tool calls.",
		},
		match: func(text string) bool {
			return hasDeny(text) && hasDestructive(text)
		},
		build: func(_ string, _ Options) (buildResult, bool) {
			return ruleResult("deny-destructive", policy.EffectDeny, &policy.Match{
				Capability: []string{"destructive"},
			}, 100, "audit", "alert"), true
		},
	},
	{
		info: TemplateInfo{
			ID:      "deny-plaintext-http",
			Summary: "Deny plaintext HTTP URLs",
			Example: "Deny URLs that use http://.",
		},
		match: func(text string) bool {
			return hasDeny(text) && strings.Contains(lower(text), "http://")
		},
		build: func(_ string, _ Options) (buildResult, bool) {
			return ruleResult("deny-plaintext-http", policy.EffectDeny, &policy.Match{
				Capability: []string{"network"},
				Args:       map[string]any{"url": map[string]any{"$prefix": "http://"}},
			}, 100, "audit", "alert"), true
		},
	},
	{
		info: TemplateInfo{
			ID:      "require-approval-email-send",
			Summary: "Require human approval before sending email",
			Example: "Require approval before sending email.",
		},
		match: func(text string) bool {
			return hasApproval(text) && hasAny(text, "email", "e-mail", "smtp", "邮件", "发邮件")
		},
		build: func(_ string, _ Options) (buildResult, bool) {
			return ruleResult("approve-email-send", policy.EffectRequireApproval, &policy.Match{
				Sink: "email.send",
			}, 80, "audit", "human_approval"), true
		},
	},
	{
		info: TemplateInfo{
			ID:      "require-approval-writes",
			Summary: "Require human approval for write operations",
			Example: "Require approval for all write operations.",
		},
		match: func(text string) bool {
			return hasApproval(text) && hasWrite(text)
		},
		build: func(_ string, _ Options) (buildResult, bool) {
			return ruleResult("approve-write-tools", policy.EffectRequireApproval, &policy.Match{
				Capability: []string{"write"},
			}, 70, "audit", "human_approval"), true
		},
	},
	{
		info: TemplateInfo{
			ID:      "allow-read-only",
			Summary: "Allow read-only tool calls",
			Example: "Allow read-only operations.",
		},
		match: func(text string) bool {
			return hasAllow(text) && hasAny(text, "read-only", "read only", "只读") && !hasDeny(text)
		},
		build: func(_ string, _ Options) (buildResult, bool) {
			return ruleResult("allow-read-only-tools", policy.EffectAllow, &policy.Match{
				Capability: []string{"read"},
			}, 10), true
		},
	},
	{
		info: TemplateInfo{
			ID:      "deny-unknown-capability",
			Summary: "Deny tools whose capability is unknown",
			Example: "Deny unknown capabilities.",
		},
		match: func(text string) bool {
			return hasDeny(text) && hasAny(text, "unknown capabilit", "unknown tool", "未知能力", "未知工具", "未知权限")
		},
		build: func(_ string, _ Options) (buildResult, bool) {
			return ruleResult("deny-unknown-capability", policy.EffectDeny, &policy.Match{
				Capability: []string{"unknown"},
			}, 100, "audit", "alert"), true
		},
	},
}

// Templates returns the supported statement templates in matching order.
func Templates() []TemplateInfo {
	result := make([]TemplateInfo, 0, len(templates))
	for _, item := range templates {
		result = append(result, item.info)
	}
	return result
}

// Compile parses a constrained natural-language policy brief into policy source.
func Compile(data []byte, options Options) (Result, error) {
	if len(data) > MaxBytes {
		return Result{}, fmt.Errorf("natural-language policy exceeds %d bytes", MaxBytes)
	}
	options = normalizeOptions(options)
	statements, diagnostics := parseStatements(data)
	if len(diagnostics) > 0 {
		return Result{}, &CompileError{Diagnostics: diagnostics}
	}
	if len(statements) == 0 {
		return Result{}, errors.New("natural-language policy contains no statements")
	}

	rules := make([]policy.Rule, 0, len(statements))
	matches := make([]Match, 0, len(statements))
	used := make(map[string]int)
	var child *policy.Subject
	for _, item := range statements {
		selected, ok := selectTemplate(item)
		if !ok {
			diagnostics = append(diagnostics, Diagnostic{
				Line:    item.line,
				Message: fmt.Sprintf("no template matched; add @template <id> or rewrite the statement (available templates: %s)", templateIDs()),
			})
			continue
		}
		built, ok := selected.build(item.text, options)
		if !ok {
			diagnostics = append(diagnostics, Diagnostic{Line: item.line, Message: fmt.Sprintf("template %q could not interpret this statement", selected.info.ID)})
			continue
		}
		if built.subject != nil {
			if child != nil {
				diagnostics = append(diagnostics, Diagnostic{Line: item.line, Message: "delegation template may be used only once"})
				continue
			}
			if built.subject.ID == built.subject.Parent {
				diagnostics = append(diagnostics, Diagnostic{Line: item.line, Message: "delegation parent must differ from the child subject"})
				continue
			}
			child = built.subject
			matches = append(matches, Match{
				Line:      item.line,
				Template:  selected.info.ID,
				Statement: item.text,
				Kind:      "subject",
				Subject:   built.subject.ID,
				Parent:    built.subject.Parent,
			})
			continue
		}
		if built.rule == nil {
			diagnostics = append(diagnostics, Diagnostic{Line: item.line, Message: "template produced no output"})
			continue
		}
		baseID := built.rule.ID
		used[baseID]++
		if used[baseID] > 1 {
			built.rule.ID = fmt.Sprintf("%s-%d", baseID, used[baseID])
		}
		rules = append(rules, *built.rule)
		matches = append(matches, Match{
			Line:      item.line,
			Template:  selected.info.ID,
			Statement: item.text,
			Kind:      "rule",
			RuleID:    built.rule.ID,
		})
	}
	if len(diagnostics) > 0 {
		return Result{}, &CompileError{Diagnostics: diagnostics}
	}
	if len(rules) == 0 && child == nil {
		return Result{}, errors.New("natural-language policy produced no rules")
	}

	subjects := []policy.Subject{{ID: options.Subject}}
	if child != nil {
		subjects = []policy.Subject{{ID: options.Parent}, *child}
	}
	sort.SliceStable(subjects, func(i, j int) bool { return subjects[i].ID < subjects[j].ID })
	document := policy.Document{
		APIVersion: policy.APIVersion,
		Kind:       policy.Kind,
		Metadata: policy.Metadata{
			Name:        options.Name,
			Owner:       "security",
			Description: "Drafted from constrained natural-language security statements",
		},
		Spec: &policy.Spec{
			Defaults: policy.Defaults{Effect: policy.EffectDeny},
			Subjects: subjects,
			Rules:    &rules,
		},
	}
	rendered, err := Render(Result{Document: document, Matches: matches})
	if err != nil {
		return Result{}, err
	}
	if _, err := policy.Compile(rendered, "draft.yaml"); err != nil {
		return Result{}, fmt.Errorf("generated policy failed validation: %w", err)
	}
	return Result{Document: document, Matches: matches}, nil
}

// Render emits deterministic caplock/v1alpha1 YAML.
func Render(result Result) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(result.Document); err != nil {
		return nil, err
	}
	if err := encoder.Close(); err != nil {
		return nil, err
	}
	header := "# Generated by `caplock draft` from constrained natural-language statements.\n" +
		"# Review this file, then run `caplock lint` and `caplock test` before use.\n"
	return append([]byte(header), buffer.Bytes()...), nil
}

func normalizeOptions(options Options) Options {
	options.Name = strings.TrimSpace(options.Name)
	if options.Name == "" {
		options.Name = DefaultName
	}
	options.Subject = strings.TrimSpace(options.Subject)
	if options.Subject == "" {
		options.Subject = DefaultSubject
	}
	options.Parent = strings.TrimSpace(options.Parent)
	if options.Parent == "" {
		options.Parent = DefaultParent
	}
	options.DefaultWindow = strings.TrimSpace(options.DefaultWindow)
	if options.DefaultWindow == "" {
		options.DefaultWindow = DefaultWindow
	}
	return options
}

func parseStatements(data []byte) ([]statement, []Diagnostic) {
	lines := strings.Split(strings.TrimPrefix(string(data), "\ufeff"), "\n")
	result := make([]statement, 0, len(lines))
	diagnostics := make([]Diagnostic, 0)
	pendingTemplate := ""
	pendingLine := 0
	for index, raw := range lines {
		line := index + 1
		text := strings.TrimSpace(raw)
		if text == "" || strings.HasPrefix(text, "#") || strings.HasPrefix(text, "//") {
			continue
		}
		if strings.HasPrefix(lower(text), "@template") {
			fields := strings.Fields(text)
			if len(fields) != 2 {
				diagnostics = append(diagnostics, Diagnostic{Line: line, Message: "@template requires exactly one template id"})
				pendingTemplate = ""
				pendingLine = 0
				continue
			}
			id := lower(fields[1])
			if _, ok := findTemplate(id); !ok {
				diagnostics = append(diagnostics, Diagnostic{Line: line, Message: fmt.Sprintf("unknown template %q; available templates: %s", fields[1], templateIDs())})
				pendingTemplate = ""
				pendingLine = 0
				continue
			}
			pendingTemplate = id
			pendingLine = line
			continue
		}
		cleaned := cleanStatement(text)
		if cleaned == "" {
			continue
		}
		result = append(result, statement{line: line, text: cleaned, template: pendingTemplate})
		pendingTemplate = ""
		pendingLine = 0
	}
	if pendingTemplate != "" {
		diagnostics = append(diagnostics, Diagnostic{Line: pendingLine, Message: "@template has no following statement"})
	}
	return result, diagnostics
}

func cleanStatement(text string) string {
	text = strings.TrimSpace(text)
	for _, prefix := range []string{"- ", "* ", "+ "} {
		if strings.HasPrefix(text, prefix) {
			text = strings.TrimSpace(strings.TrimPrefix(text, prefix))
			break
		}
	}
	if index := strings.Index(text, ". "); index > 0 && index <= 3 {
		numeric := true
		for _, character := range text[:index] {
			if character < '0' || character > '9' {
				numeric = false
				break
			}
		}
		if numeric {
			text = strings.TrimSpace(text[index+2:])
		}
	}
	return strings.TrimSpace(text)
}

func selectTemplate(item statement) (template, bool) {
	if item.template != "" {
		return findTemplate(item.template)
	}
	for _, candidate := range templates {
		if candidate.match(lower(item.text)) {
			return candidate, true
		}
	}
	return template{}, false
}

func findTemplate(id string) (template, bool) {
	for _, item := range templates {
		if item.info.ID == id {
			return item, true
		}
	}
	return template{}, false
}

func templateIDs() string {
	ids := make([]string, 0, len(templates))
	for _, item := range templates {
		ids = append(ids, item.info.ID)
	}
	sort.Strings(ids)
	return strings.Join(ids, ", ")
}

func ruleResult(id, effect string, match *policy.Match, rulesPriority int, obligations ...string) buildResult {
	priority := rulesPriority
	return buildResult{rule: &policy.Rule{
		ID:          id,
		Effect:      effect,
		Priority:    &priority,
		Match:       match,
		Obligations: append([]string(nil), obligations...),
	}}
}

func provenanceEgressMatch(text string) *policy.Match {
	match := &policy.Match{
		Capability: []string{"comms", "external", "network"},
		Provenance: &policy.Provenance{Contains: policy.StringList{"external_web"}},
	}
	if sink := outboundSink(text); sink != "" {
		match.Sink = sink
	}
	return match
}

func outboundSink(text string) string {
	sinks := make([]string, 0, 3)
	if hasAny(text, "email", "e-mail", "smtp", "邮件", "发邮件") {
		sinks = append(sinks, "email.send")
	}
	if hasAny(text, "slack") {
		sinks = append(sinks, "slack.send")
	}
	if hasAny(text, "webhook", "回调") {
		sinks = append(sinks, "webhook")
	}
	if len(sinks) == 1 {
		return sinks[0]
	}
	return ""
}

var windowPattern = regexp.MustCompile(`(?i)((?:\*|mon|tue|wed|thu|fri|sat|sun)(?:-[a-z]+)?(?:,(?:\*|[a-z]+)(?:-[a-z]+)?)*\s+\d{1,2}:\d{2}-\d{1,2}:\d{2}\s+[a-z][a-z0-9_+\-/]*)`)

func extractWindow(text string) string {
	match := windowPattern.FindString(text)
	if match == "" {
		return ""
	}
	fields := strings.Fields(match)
	if len(fields) != 3 {
		return ""
	}
	fields[0] = canonicalDays(fields[0])
	return strings.Join(fields, " ")
}

func canonicalDays(value string) string {
	replacements := map[string]string{
		"sun": "Sun", "mon": "Mon", "tue": "Tue", "wed": "Wed", "thu": "Thu", "fri": "Fri", "sat": "Sat",
	}
	parts := strings.Split(value, ",")
	for index, part := range parts {
		rangeParts := strings.Split(part, "-")
		for rangeIndex, rangePart := range rangeParts {
			if replacement, ok := replacements[strings.ToLower(rangePart)]; ok {
				rangeParts[rangeIndex] = replacement
			}
		}
		parts[index] = strings.Join(rangeParts, "-")
	}
	return strings.Join(parts, ",")
}

func lower(text string) string {
	return strings.ToLower(strings.TrimSpace(text))
}

func hasAny(text string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(text, lower(value)) {
			return true
		}
	}
	return false
}

func hasDeny(text string) bool {
	return hasAny(text, "deny", "block", "forbid", "disallow", "must not", "may not", "cannot", "do not", "must never", "never allow", "禁止", "不允许", "不得", "拒绝", "严禁")
}

func hasApproval(text string) bool {
	return hasAny(text, "require approval", "requires approval", "approval required", "human approval", "require human approval", "需要审批", "需审批", "人工审批", "人工确认")
}

func hasAllow(text string) bool {
	return hasAny(text, "allow", "permit", "允许", "准许")
}

func hasWrite(text string) bool {
	return hasAny(text, "write", "writing", "file write", "写入", "写操作", "修改文件")
}

func hasEgress(text string) bool {
	return hasAny(text, "egress", "exfiltrat", "outbound", "leave", "leaving", "send", "sent", "upload", "reach", "flow to", "外发", "外流", "流入", "流出", "发送", "上传", "进入", "到达")
}

func hasExternal(text string) bool {
	return hasAny(text, "external web", "web content", "untrusted", "external content", "外部网页", "外部内容", "不可信内容", "网页内容")
}

func hasDestructive(text string) bool {
	return hasAny(text, "destructive", "delete", "destroy", "drop", "wipe", "破坏", "删除", "销毁", "清空")
}
