package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/1124875284/caplock/internal/safefile"
)

const (
	// Name is the default policy filename.
	Name = "caplock.yaml"
	// MaxBytes is the largest policy file Caplock will read.
	MaxBytes = 1 << 20
)

// LoadFile reads and compiles a caplock/v1alpha1 policy file.
func LoadFile(path string) (*IR, error) {
	data, err := safefile.ReadFile(path, MaxBytes)
	if err != nil {
		return nil, fmt.Errorf("read policy %s: %w", path, err)
	}
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) || name == "" {
		name = Name
	}
	return Compile(data, name)
}

// Compile parses YAML or JSON policy source into deterministic Policy IR.
func Compile(data []byte, sourceName string) (*IR, error) {
	if sourceName == "" {
		sourceName = Name
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var document Document
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("policy is empty")
		}
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err == nil {
		return nil, errors.New("policy contains multiple YAML documents")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse policy: %w", err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := validateDocument(&document); err != nil {
		return nil, err
	}

	ir := &IR{
		IRVersion: IRVersion,
		Policy:    document.Metadata.Name,
		Defaults:  document.Spec.Defaults,
		Subjects:  append([]Subject(nil), document.Spec.Subjects...),
		Rules:     make([]Rule, 0, len(*document.Spec.Rules)),
	}
	if ir.Subjects == nil {
		ir.Subjects = []Subject{}
	}
	sort.SliceStable(ir.Subjects, func(i, j int) bool { return ir.Subjects[i].ID < ir.Subjects[j].ID })

	locations := ruleLocations(&root, sourceName)
	for index, rule := range *document.Spec.Rules {
		normalizeRule(&rule)
		if index < len(locations) {
			rule.Source = locations[index]
		} else {
			rule.Source = Source{File: sourceName, Line: 1}
		}
		ir.Rules = append(ir.Rules, rule)
	}
	if _, err := json.Marshal(ir); err != nil {
		return nil, fmt.Errorf("policy contains a value that cannot be serialized: %w", err)
	}
	return ir, nil
}

func validateDocument(document *Document) error {
	if document.APIVersion != APIVersion {
		return fmt.Errorf("apiVersion must be %q", APIVersion)
	}
	if document.Kind != Kind {
		return fmt.Errorf("kind must be %q", Kind)
	}
	if strings.TrimSpace(document.Metadata.Name) == "" {
		return errors.New("metadata.name must not be empty")
	}
	if document.Spec == nil {
		return errors.New("spec is required")
	}
	if !validEffect(document.Spec.Defaults.Effect) {
		return fmt.Errorf("spec.defaults.effect must be allow, deny, or require_approval")
	}
	if document.Spec.Rules == nil {
		return errors.New("spec.rules must be an array")
	}
	if err := validateSubjects(document.Spec.Subjects); err != nil {
		return err
	}
	seenRules := make(map[string]bool, len(*document.Spec.Rules))
	for index := range *document.Spec.Rules {
		rule := &(*document.Spec.Rules)[index]
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("spec.rules[%d].id must not be empty", index)
		}
		if seenRules[rule.ID] {
			return fmt.Errorf("duplicate rule id %q", rule.ID)
		}
		seenRules[rule.ID] = true
		if !validEffect(rule.Effect) {
			return fmt.Errorf("rule %q effect must be allow, deny, or require_approval", rule.ID)
		}
		if rule.Priority != nil && *rule.Priority < 0 {
			return fmt.Errorf("rule %q priority must be greater than or equal to zero", rule.ID)
		}
		if !rule.Match.hasCriteria() {
			return fmt.Errorf("rule %q match must select at least one condition", rule.ID)
		}
		if err := validateMatch(rule.Match); err != nil {
			return fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		if err := validateStringArray("obligations", rule.Obligations); err != nil {
			return fmt.Errorf("rule %q: %w", rule.ID, err)
		}
		for _, obligation := range rule.Obligations {
			if !validObligation(obligation) {
				return fmt.Errorf("rule %q has unknown obligation %q", rule.ID, obligation)
			}
		}
	}
	return nil
}

func validateSubjects(subjects []Subject) error {
	seen := make(map[string]bool, len(subjects))
	for index, subject := range subjects {
		if strings.TrimSpace(subject.ID) == "" {
			return fmt.Errorf("spec.subjects[%d].id must not be empty", index)
		}
		if seen[subject.ID] {
			return fmt.Errorf("duplicate subject id %q", subject.ID)
		}
		seen[subject.ID] = true
		if subject.Delegation != "" && subject.Delegation != DelegationAttenuateOnly {
			return fmt.Errorf("subject %q delegation must be %q", subject.ID, DelegationAttenuateOnly)
		}
	}
	return nil
}

func validateMatch(match *Match) error {
	for label, values := range map[string][]string{
		"match.tool":       match.Tool,
		"match.capability": match.Capability,
		"match.dataClass":  match.DataClass,
	} {
		if err := validateStringArray(label, values); err != nil {
			return err
		}
	}
	if err := validateArgumentSelectors(match.Args); err != nil {
		return err
	}
	if match.Context != nil {
		if match.Context.Time != nil {
			if strings.TrimSpace(match.Context.Time.Outside) == "" {
				return errors.New("match.context.time.outside must not be empty")
			}
			if _, err := parseTimeWindow(match.Context.Time.Outside); err != nil {
				return fmt.Errorf("match.context.time.outside: %w", err)
			}
		}
		for key, value := range match.Context.Attributes {
			if strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
				return errors.New("match.context.attributes keys and values must not be empty")
			}
		}
	}
	if match.Provenance != nil {
		if len(match.Provenance.Contains) == 0 {
			return errors.New("match.provenance.contains must not be empty")
		}
		if err := validateStringArray("match.provenance.contains", match.Provenance.Contains); err != nil {
			return err
		}
	}
	return nil
}

func normalizeRule(rule *Rule) {
	sort.Strings(rule.Obligations)
	sort.Strings(rule.Match.Tool)
	sort.Strings(rule.Match.Capability)
	sort.Strings(rule.Match.DataClass)
	if rule.Match.Provenance != nil {
		sort.Strings(rule.Match.Provenance.Contains)
	}
}

func ruleLocations(root *yaml.Node, sourceName string) []Source {
	node := root
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		node = node.Content[0]
	}
	spec := mappingValue(node, "spec")
	rules := mappingValue(spec, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return nil
	}
	locations := make([]Source, 0, len(rules.Content))
	for _, item := range rules.Content {
		locations = append(locations, Source{File: sourceName, Line: max(item.Line, 1), Column: max(item.Column, 1)})
	}
	return locations
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1]
		}
	}
	return nil
}
