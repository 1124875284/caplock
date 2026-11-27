// Package safefile provides bounded, read-only file access for user-selected
// configuration and lockfile paths.
package safefile

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ReadFile opens path read-only, verifies it is a regular file after opening,
// and refuses files larger than maxBytes. The post-open check avoids trusting a
// path that may have changed after an earlier stat call.
func ReadFile(path string, maxBytes int64) ([]byte, error) {
	// #nosec G304 -- the CLI intentionally reads a user-selected config or lockfile path.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	return data, nil
}
