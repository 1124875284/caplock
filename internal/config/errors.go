package config

import "fmt"

// Error is a user-facing configuration error. Paths are retained for debugging;
// configuration values are never included in error messages.
type Error struct {
	Path string
	Msg  string
	Err  error
}

func (e *Error) Error() string {
	if e.Path == "" {
		return e.Msg
	}
	return fmt.Sprintf("%s: %s", e.Path, e.Msg)
}

func (e *Error) Unwrap() error { return e.Err }

func configError(path, format string, args ...any) *Error {
	return &Error{Path: path, Msg: fmt.Sprintf(format, args...)}
}
