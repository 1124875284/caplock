// Package policy loads, compiles, lints, and serializes Caplock policy source.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// APIVersion is the only policy source format accepted by this build.
	APIVersion = "caplock/v1alpha1"
	// Kind is the policy document kind.
	Kind = "PolicySet"
	// IRVersion is the normalized Policy IR version.
	IRVersion = 1
)

// Policy effects define how a matching request is handled.
const (
	EffectAllow           = "allow"
	EffectDeny            = "deny"
	EffectRequireApproval = "require_approval"
)

// DelegationAttenuateOnly requires a child subject to remain within its
// parent's authority.
const (
	DelegationAttenuateOnly = "attenuate-only"
)

// Document is the human-authored caplock/v1alpha1 policy source.
type Document struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       *Spec    `yaml:"spec"`
}

// Metadata identifies a policy set.
type Metadata struct {
	Name        string `yaml:"name" json:"name"`
	Owner       string `yaml:"owner" json:"owner,omitempty"`
	Description string `yaml:"description" json:"description,omitempty"`
}

// Spec is the editable policy content.
type Spec struct {
	Defaults Defaults  `yaml:"defaults" json:"defaults"`
	Subjects []Subject `yaml:"subjects" json:"subjects,omitempty"`
	Rules    *[]Rule   `yaml:"rules" json:"rules"`
}

// Defaults controls the decision when no rule matches.
type Defaults struct {
	Effect string `yaml:"effect" json:"effect"`
}

// Subject identifies an agent or delegated principal.
type Subject struct {
	ID         string `yaml:"id" json:"id"`
	Parent     string `yaml:"parent,omitempty" json:"parent,omitempty"`
	Delegation string `yaml:"delegation,omitempty" json:"delegation,omitempty"`
}

// Rule is one policy decision clause.
type Rule struct {
	ID          string   `yaml:"id" json:"id"`
	Effect      string   `yaml:"effect" json:"effect"`
	Priority    *int     `yaml:"priority,omitempty" json:"priority,omitempty"`
	Match       *Match   `yaml:"match" json:"match"`
	Obligations []string `yaml:"obligations,omitempty" json:"obligations,omitempty"`
	Source      Source   `yaml:"-" json:"source"`
}

// Source points back to the authored policy line.
type Source struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column,omitempty"`
}

// Match selects the requests to which a rule applies.
type Match struct {
	Subject    string         `yaml:"subject,omitempty" json:"subject,omitempty"`
	Tool       []string       `yaml:"tool,omitempty" json:"tool,omitempty"`
	Capability []string       `yaml:"capability,omitempty" json:"capability,omitempty"`
	DataClass  []string       `yaml:"dataClass,omitempty" json:"dataClass,omitempty"`
	Sink       string         `yaml:"sink,omitempty" json:"sink,omitempty"`
	Args       map[string]any `yaml:"args,omitempty" json:"args,omitempty"`
	Context    *Context       `yaml:"context,omitempty" json:"context,omitempty"`
	Provenance *Provenance    `yaml:"provenance,omitempty" json:"provenance,omitempty"`
}

// Context captures request context selectors.
type Context struct {
	Time        *TimeWindow       `yaml:"time,omitempty" json:"time,omitempty"`
	Environment string            `yaml:"environment,omitempty" json:"environment,omitempty"`
	Attributes  map[string]string `yaml:"attributes,omitempty" json:"attributes,omitempty"`
}

// TimeWindow is a human-readable time selector. The evaluator will interpret it;
// compilation only validates its presence and shape.
type TimeWindow struct {
	Outside string `yaml:"outside" json:"outside"`
}

// Provenance selects requests whose data carries a source label.
type Provenance struct {
	Contains StringList `yaml:"contains" json:"contains"`
}

// StringList accepts either a scalar string or a string sequence in YAML/JSON.
type StringList []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *StringList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		if value.Tag != "!!str" || value.Value == "" {
			return errors.New("expected a non-empty string or string array")
		}
		*s = []string{value.Value}
	case yaml.SequenceNode:
		var values []string
		if err := value.Decode(&values); err != nil {
			return err
		}
		*s = values
	default:
		return errors.New("expected a non-empty string or string array")
	}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler for callers embedding policy types.
func (s *StringList) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		if single == "" {
			return errors.New("expected a non-empty string or string array")
		}
		*s = []string{single}
		return nil
	}
	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return errors.New("expected a non-empty string or string array")
	}
	*s = values
	return nil
}

// IR is the normalized, deterministic policy representation.
type IR struct {
	IRVersion int       `json:"irVersion"`
	Policy    string    `json:"policy"`
	Defaults  Defaults  `json:"defaults"`
	Subjects  []Subject `json:"subjects"`
	Rules     []Rule    `json:"rules"`
}

func (m *Match) hasCriteria() bool {
	return m != nil && (m.Subject != "" || len(m.Tool) > 0 || len(m.Capability) > 0 || len(m.DataClass) > 0 || m.Sink != "" || len(m.Args) > 0 || m.Context != nil || m.Provenance != nil)
}

// HasConditionalSelectors reports whether a tool/capability rule also depends
// on request-time facts such as provenance, arguments, time, or environment.
func (m *Match) HasConditionalSelectors() bool {
	return m != nil && (len(m.DataClass) > 0 || m.Sink != "" || len(m.Args) > 0 || m.Context != nil || m.Provenance != nil)
}

func validEffect(effect string) bool {
	switch effect {
	case EffectAllow, EffectDeny, EffectRequireApproval:
		return true
	default:
		return false
	}
}

func validObligation(obligation string) bool {
	switch obligation {
	case "audit", "alert", "redact", "human_approval", "rate_limit":
		return true
	default:
		return false
	}
}

func validateStringArray(label string, values []string) error {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s values must not be empty", label)
		}
		if seen[value] {
			return fmt.Errorf("%s contains duplicate %q", label, value)
		}
		seen[value] = true
	}
	return nil
}
