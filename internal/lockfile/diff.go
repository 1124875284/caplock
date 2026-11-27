package lockfile

import (
	"reflect"
	"slices"
	"sort"
)

// Change describes a server whose permission surface differs between lockfiles.
type Change struct {
	Before      Server       `json:"before"`
	After       Server       `json:"after"`
	Fields      []string     `json:"fields"`
	ToolChanges []ToolChange `json:"toolChanges,omitempty"`
}

// ToolChange describes one tool added, removed, or changed inside a server.
type ToolChange struct {
	Action string   `json:"action"`
	Name   string   `json:"name"`
	Fields []string `json:"fields,omitempty"`
	Before *Tool    `json:"before,omitempty"`
	After  *Tool    `json:"after,omitempty"`
}

// Diff is the semantic difference between two lockfiles.
type Diff struct {
	Added   []Server `json:"added"`
	Removed []Server `json:"removed"`
	Changed []Change `json:"changed"`
}

// HasChanges reports whether any servers were added, removed, or changed.
func (d Diff) HasChanges() bool {
	return len(d.Added) > 0 || len(d.Removed) > 0 || len(d.Changed) > 0
}

// CompareLockfiles compares servers by (name, source) and reports semantic
// changes. Ordering is deterministic.
func CompareLockfiles(oldFile, newFile *File) Diff {
	oldIndex := index(oldFile)
	newIndex := index(newFile)
	result := Diff{Added: []Server{}, Removed: []Server{}, Changed: []Change{}}

	keys := make([]serverKey, 0, len(oldIndex)+len(newIndex))
	seen := make(map[serverKey]bool, len(oldIndex)+len(newIndex))
	for key := range oldIndex {
		seen[key] = true
		keys = append(keys, key)
	}
	for key := range newIndex {
		if !seen[key] {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		return keys[i].source < keys[j].source
	})

	for _, key := range keys {
		before, existedBefore := oldIndex[key]
		after, existsAfter := newIndex[key]
		switch {
		case !existedBefore:
			result.Added = append(result.Added, after)
		case !existsAfter:
			result.Removed = append(result.Removed, before)
		default:
			fields := changedFields(before, after)
			if len(fields) > 0 {
				result.Changed = append(result.Changed, Change{
					Before:      before,
					After:       after,
					Fields:      fields,
					ToolChanges: compareTools(before.Tools, after.Tools),
				})
			}
		}
	}
	return result
}

type serverKey struct {
	source string
	name   string
}

func index(file *File) map[serverKey]Server {
	result := make(map[serverKey]Server, len(file.Servers))
	for _, server := range file.Servers {
		result[serverKey{source: server.Source, name: server.Name}] = server
	}
	return result
}

func changedFields(before, after Server) []string {
	fields := make([]string, 0, 3)
	if before.ConfigHash != after.ConfigHash {
		fields = append(fields, "config")
	}
	if !reflect.DeepEqual(before.Tools, after.Tools) {
		fields = append(fields, "tools")
	}
	if before.Transport != after.Transport {
		fields = append(fields, "transport")
	}
	if !equalStringPointers(before.Command, after.Command) {
		fields = append(fields, "command")
	}
	if !slices.Equal(before.Args, after.Args) {
		fields = append(fields, "args")
	}
	if !equalStringPointers(before.URL, after.URL) {
		fields = append(fields, "url")
	}
	if !slices.Equal(before.EnvKeys, after.EnvKeys) {
		fields = append(fields, "envKeys")
	}
	if !slices.Equal(before.HeaderKeys, after.HeaderKeys) {
		fields = append(fields, "headerKeys")
	}
	sort.Strings(fields)
	return fields
}

func equalStringPointers(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func compareTools(before, after *[]Tool) []ToolChange {
	beforeIndex := toolIndex(before)
	afterIndex := toolIndex(after)
	names := make([]string, 0, len(beforeIndex)+len(afterIndex))
	seen := make(map[string]bool, len(beforeIndex)+len(afterIndex))
	for name := range beforeIndex {
		seen[name] = true
		names = append(names, name)
	}
	for name := range afterIndex {
		if !seen[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	changes := make([]ToolChange, 0)
	for _, name := range names {
		oldTool, existedBefore := beforeIndex[name]
		newTool, existsAfter := afterIndex[name]
		switch {
		case !existedBefore:
			changes = append(changes, ToolChange{Action: "added", Name: name, After: &newTool})
		case !existsAfter:
			changes = append(changes, ToolChange{Action: "removed", Name: name, Before: &oldTool})
		default:
			fields := changedToolFields(oldTool, newTool)
			if len(fields) > 0 {
				changes = append(changes, ToolChange{Action: "changed", Name: name, Fields: fields, Before: &oldTool, After: &newTool})
			}
		}
	}
	return changes
}

func toolIndex(tools *[]Tool) map[string]Tool {
	result := make(map[string]Tool)
	if tools == nil {
		return result
	}
	for _, tool := range *tools {
		result[tool.Name] = tool
	}
	return result
}

func changedToolFields(before, after Tool) []string {
	fields := make([]string, 0, 4)
	if before.DescriptionHash != after.DescriptionHash {
		fields = append(fields, "description")
	}
	if before.InputSchemaHash != after.InputSchemaHash {
		fields = append(fields, "inputSchema")
	}
	if !reflect.DeepEqual(before.Annotations, after.Annotations) {
		fields = append(fields, "annotations")
	}
	if !reflect.DeepEqual(before.Capabilities, after.Capabilities) {
		fields = append(fields, "capabilities")
	}
	sort.Strings(fields)
	return fields
}
