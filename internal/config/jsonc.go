package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// normalizeJSONC accepts the JSON-with-comments dialect commonly used by editor
// configuration files. It removes comments and trailing commas while preserving
// newlines so parser errors still point at approximately the right line.
func normalizeJSONC(src []byte) ([]byte, error) {
	out := append([]byte(nil), src...)
	if bytes.HasPrefix(out, []byte{0xEF, 0xBB, 0xBF}) {
		out[0], out[1], out[2] = ' ', ' ', ' '
	}

	inString := false
	escaped := false
	for i := 0; i < len(out); i++ {
		switch {
		case inString:
			if escaped {
				escaped = false
				continue
			}
			switch out[i] {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
		case out[i] == '"':
			inString = true
		case out[i] == '/' && i+1 < len(out) && out[i+1] == '/':
			out[i], out[i+1] = ' ', ' '
			i += 2
			for ; i < len(out) && out[i] != '\n' && out[i] != '\r'; i++ {
				out[i] = ' '
			}
			i--
		case out[i] == '/' && i+1 < len(out) && out[i+1] == '*':
			start := i
			out[i], out[i+1] = ' ', ' '
			i += 2
			closed := false
			for ; i < len(out); i++ {
				if out[i] == '*' && i+1 < len(out) && out[i+1] == '/' {
					out[i], out[i+1] = ' ', ' '
					i++
					closed = true
					break
				}
				if out[i] != '\n' && out[i] != '\r' {
					out[i] = ' '
				}
			}
			if !closed {
				return nil, fmt.Errorf("unterminated block comment at %s", lineColumn(src, start))
			}
		}
	}

	inString = false
	escaped = false
	for i := 0; i < len(out); i++ {
		switch {
		case inString:
			if escaped {
				escaped = false
				continue
			}
			switch out[i] {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
		case out[i] == '"':
			inString = true
		case out[i] == ',':
			j := i + 1
			for j < len(out) && isJSONWhitespace(out[j]) {
				j++
			}
			if j < len(out) && (out[j] == '}' || out[j] == ']') {
				out[i] = ' '
			}
		}
	}
	return out, nil
}

func isJSONWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func lineColumn(src []byte, offset int) string {
	if offset < 0 {
		offset = 0
	}
	if offset > len(src) {
		offset = len(src)
	}
	line := 1 + bytes.Count(src[:offset], []byte{'\n'})
	lastNewline := bytes.LastIndexByte(src[:offset], '\n')
	column := offset + 1
	if lastNewline >= 0 {
		column = offset - lastNewline
	}
	return fmt.Sprintf("line %d, column %d", line, column)
}

func parseJSONC(src []byte) (any, error) {
	normalized, err := normalizeJSONC(src)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(normalized))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return nil, fmt.Errorf("invalid JSONC at %s: %w", lineColumn(src, int(syntaxErr.Offset-1)), err)
		}
		return nil, fmt.Errorf("invalid JSONC: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, errors.New("invalid JSONC: multiple top-level values")
		}
		return nil, fmt.Errorf("invalid JSONC after top-level value: %w", err)
	}
	return value, nil
}
