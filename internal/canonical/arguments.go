// Package canonical implements shared deterministic encodings and privacy
// helpers used by policy traces and the runtime proxy.
package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// RedactedValue replaces a sensitive argument value in a captured trace.
const RedactedValue = "[REDACTED]"

// HashArguments returns the stable digest used for argument correlation. JSON
// object keys are emitted in sorted order by encoding/json.
func HashArguments(arguments map[string]any) (string, error) {
	if arguments == nil {
		arguments = map[string]any{}
	}
	data, err := json.Marshal(arguments)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ParseRedactionKeys parses a comma-separated operator list. Each entry is
// matched case-insensitively either as an object key at any depth or as a
// dotted path such as "nested.password". Empty input means no redaction.
func ParseRedactionKeys(value string) ([]string, error) {
	seen := make(map[string]bool)
	keys := make([]string, 0)
	for _, raw := range strings.Split(value, ",") {
		key := strings.TrimSpace(raw)
		if key == "" {
			continue
		}
		if strings.ContainsAny(key, "\x00\r\n") {
			return nil, fmt.Errorf("redaction key %q contains a control character", key)
		}
		normalized := strings.ToLower(key)
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

// RedactArguments returns a deep copy with matching object keys replaced by a
// fixed marker. It also returns the sorted paths that were redacted. The input
// map is never mutated.
func RedactArguments(arguments map[string]any, keys []string) (map[string]any, []string) {
	if len(keys) == 0 {
		if arguments == nil {
			return nil, []string{}
		}
		return cloneMap(arguments), []string{}
	}
	needles := make(map[string]bool, len(keys))
	for _, key := range keys {
		needles[strings.ToLower(strings.TrimSpace(key))] = true
	}
	paths := make([]string, 0)
	redacted := redactValue(arguments, "", needles, &paths).(map[string]any)
	sort.Strings(paths)
	return redacted, uniqueStrings(paths)
}

func redactValue(value any, path string, needles map[string]bool, paths *[]string) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			if needles[strings.ToLower(key)] || needles[strings.ToLower(childPath)] {
				result[key] = RedactedValue
				*paths = append(*paths, childPath)
				continue
			}
			result[key] = redactValue(child, childPath, needles, paths)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = redactValue(child, fmt.Sprintf("%s[%d]", path, index), needles, paths)
		}
		return result
	default:
		return value
	}
}

func cloneMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	result := make(map[string]any, len(value))
	for key, child := range value {
		switch typed := child.(type) {
		case map[string]any:
			result[key] = cloneMap(typed)
		case []any:
			items := make([]any, len(typed))
			copy(items, typed)
			result[key] = items
		default:
			result[key] = typed
		}
	}
	return result
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	result := values[:1]
	for _, value := range values[1:] {
		if result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

// VerifyArguments checks a recorded digest against captured arguments.
func VerifyArguments(hash string, arguments map[string]any) error {
	if strings.TrimSpace(hash) == "" {
		return nil
	}
	calculated, err := HashArguments(arguments)
	if err != nil {
		return fmt.Errorf("hash captured arguments: %w", err)
	}
	if calculated != hash {
		return errors.New("argsHash does not match captured arguments")
	}
	return nil
}
