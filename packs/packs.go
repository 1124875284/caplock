// Package packs exposes the policy packs and attack corpus embedded in Caplock.
package packs

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
)

//go:embed attacks/*.yaml policies/*.yaml templates/*.yaml
var content embed.FS

// Read returns one embedded pack by slash-separated path.
func Read(name string) ([]byte, error) {
	data, err := content.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("read embedded pack %q: %w", name, err)
	}
	return data, nil
}

// Names lists embedded files in deterministic order.
func Names() ([]string, error) {
	names := make([]string, 0)
	err := fs.WalkDir(content, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			names = append(names, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}
