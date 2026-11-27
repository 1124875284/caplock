package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	data, err := ReadFile(path, 1024)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got, want := string(data), `{"ok":true}`; got != want {
		t.Fatalf("data = %q, want %q", got, want)
	}
}

func TestReadFileRejectsDirectory(t *testing.T) {
	_, err := ReadFile(t.TempDir(), 1024)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("ReadFile() error = %v, want not a regular file", err)
	}
}

func TestReadFileRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 1025)), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, err := ReadFile(path, 1024)
	if err == nil || !strings.Contains(err.Error(), "exceeds 1024 bytes") {
		t.Fatalf("ReadFile() error = %v, want size error", err)
	}
}

func TestReadFileRejectsMissingFile(t *testing.T) {
	_, err := ReadFile(filepath.Join(t.TempDir(), "missing"), 1024)
	if !os.IsNotExist(err) {
		t.Fatalf("ReadFile() error = %v, want not exist", err)
	}
}
