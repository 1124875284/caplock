package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const maxArgumentSelectorSize = 4 << 10

func validateArgumentSelectors(selectors map[string]any) error {
	keys := make([]string, 0, len(selectors))
	for key := range selectors {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if strings.TrimSpace(key) == "" {
			return errors.New("match.args keys must not be empty")
		}
		if err := validateArgumentSelector(selectors[key]); err != nil {
			return fmt.Errorf("match.args.%s: %w", key, err)
		}
	}
	return nil
}

func validateArgumentSelector(selector any) error {
	object, ok := selector.(map[string]any)
	if !ok {
		return nil
	}
	operator := ""
	for key := range object {
		if !strings.HasPrefix(key, "$") {
			continue
		}
		if operator != "" {
			return errors.New("argument selector must contain exactly one operator")
		}
		operator = key
	}
	if operator == "" {
		return nil
	}
	if len(object) != 1 {
		return errors.New("argument selector cannot combine an operator with literal keys")
	}
	value := object[operator]
	switch operator {
	case "$exists":
		if _, ok := value.(bool); !ok {
			return errors.New("$exists must be a boolean")
		}
	case "$regex":
		pattern, ok := value.(string)
		if !ok || len(pattern) > maxArgumentSelectorSize {
			return errors.New("$regex must be a string smaller than 4 KiB")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("$regex is invalid: %w", err)
		}
	case "$prefix", "$suffix":
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s must be a string", operator)
		}
	case "$in":
		values, ok := value.([]any)
		if !ok || len(values) == 0 {
			return errors.New("$in must be a non-empty array")
		}
	case "$contains":
		switch value.(type) {
		case string, []any:
		default:
			return errors.New("$contains must be a string or array")
		}
	case "$ne":
	default:
		return fmt.Errorf("unknown argument operator %q", operator)
	}
	return nil
}

func matchArgumentSelectors(arguments map[string]any, selectors map[string]any) (bool, []string, error) {
	keys := make([]string, 0, len(selectors))
	for key := range selectors {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	reasons := make([]string, 0, len(keys))
	for _, key := range keys {
		matched, err := matchArgumentSelector(arguments, key, selectors[key])
		if err != nil {
			return false, nil, err
		}
		if !matched {
			return false, nil, nil
		}
		reasons = append(reasons, "args."+key)
	}
	return true, reasons, nil
}

func matchArgumentSelector(arguments map[string]any, path string, selector any) (bool, error) {
	actual, exists := lookupArgument(arguments, path)
	object, isObject := selector.(map[string]any)
	if !isObject {
		return exists && equalArgumentValues(actual, selector), nil
	}

	operator, isOperator := singleArgumentOperator(object)
	if !isOperator {
		return exists && equalArgumentValues(actual, selector), nil
	}
	value := object[operator]
	switch operator {
	case "$exists":
		return value.(bool) == exists, nil
	case "$ne":
		return !exists || !equalArgumentValues(actual, value), nil
	}
	if !exists {
		return false, nil
	}
	switch operator {
	case "$in":
		for _, candidate := range value.([]any) {
			if equalArgumentValues(actual, candidate) {
				return true, nil
			}
		}
		return false, nil
	case "$contains":
		switch wanted := value.(type) {
		case string:
			if text, ok := actual.(string); ok {
				return strings.Contains(text, wanted), nil
			}
			if values, ok := actual.([]any); ok {
				for _, item := range values {
					if text, ok := item.(string); ok && strings.Contains(text, wanted) {
						return true, nil
					}
				}
			}
			return false, nil
		case []any:
			values, ok := actual.([]any)
			if !ok {
				return false, nil
			}
			for _, item := range values {
				for _, candidate := range wanted {
					if equalArgumentValues(item, candidate) {
						return true, nil
					}
				}
			}
			return false, nil
		default:
			return false, errors.New("$contains has an invalid value")
		}
	case "$regex":
		text, ok := actual.(string)
		if !ok {
			return false, nil
		}
		pattern := value.(string)
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return false, fmt.Errorf("invalid compiled $regex: %w", err)
		}
		return compiled.MatchString(text), nil
	case "$prefix":
		text, ok := actual.(string)
		return ok && strings.HasPrefix(text, value.(string)), nil
	case "$suffix":
		text, ok := actual.(string)
		return ok && strings.HasSuffix(text, value.(string)), nil
	default:
		return false, fmt.Errorf("unknown argument operator %q", operator)
	}
}

func singleArgumentOperator(object map[string]any) (string, bool) {
	operator := ""
	for key := range object {
		if !strings.HasPrefix(key, "$") {
			return "", false
		}
		if operator != "" {
			return "", false
		}
		operator = key
	}
	return operator, operator != ""
}

func lookupArgument(arguments map[string]any, path string) (any, bool) {
	if value, ok := arguments[path]; ok {
		return value, true
	}
	current := any(arguments)
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func equalArgumentValues(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}
