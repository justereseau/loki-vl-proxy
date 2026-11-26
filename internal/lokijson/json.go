// Package lokijson contains small append-style JSON helpers used on the hot
// path: scanning VictoriaLogs JSON lines without allocating and writing Loki
// responses directly into reusable buffers.
package lokijson

import (
	"errors"
	"strconv"
	"unicode/utf8"
)

// Field is a key/value pair of a flat JSON object. Both slices point into the
// scanned line and still contain JSON escape sequences (they are "raw").
type Field struct {
	Key, Value []byte
	// Quoted is false when the value was not a JSON string (number, bool, ...).
	Quoted bool
}

var errBadJSON = errors.New("invalid JSON object")

// ScanObject parses a flat JSON object such as the lines produced by
// /select/logsql/query. dst is reused to avoid allocations.
func ScanObject(line []byte, dst []Field) ([]Field, error) {
	dst = dst[:0]
	i := skipWS(line, 0)
	if i >= len(line) || line[i] != '{' {
		return dst, errBadJSON
	}
	i++
	for {
		i = skipWS(line, i)
		if i >= len(line) {
			return dst, errBadJSON
		}
		if line[i] == '}' {
			return dst, nil
		}
		if line[i] == ',' {
			i = skipWS(line, i+1)
		}
		if i >= len(line) || line[i] != '"' {
			return dst, errBadJSON
		}
		ke := stringEnd(line, i+1)
		if ke < 0 {
			return dst, errBadJSON
		}
		key := line[i+1 : ke]
		i = skipWS(line, ke+1)
		if i >= len(line) || line[i] != ':' {
			return dst, errBadJSON
		}
		i = skipWS(line, i+1)
		if i >= len(line) {
			return dst, errBadJSON
		}
		if line[i] == '"' {
			ve := stringEnd(line, i+1)
			if ve < 0 {
				return dst, errBadJSON
			}
			dst = append(dst, Field{Key: key, Value: line[i+1 : ve], Quoted: true})
			i = ve + 1
			continue
		}
		// non-string scalar (VictoriaLogs only emits strings, but be lenient)
		s := i
		depth := 0
		for i < len(line) {
			c := line[i]
			if c == '{' || c == '[' {
				depth++
			} else if c == '}' || c == ']' {
				if depth == 0 {
					break
				}
				depth--
			} else if c == ',' && depth == 0 {
				break
			} else if c == '"' {
				e := stringEnd(line, i+1)
				if e < 0 {
					return dst, errBadJSON
				}
				i = e
			}
			i++
		}
		dst = append(dst, Field{Key: key, Value: trimWS(line[s:i])})
	}
}

func skipWS(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

func trimWS(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}

// stringEnd returns the index of the closing quote of a JSON string starting at i.
func stringEnd(b []byte, i int) int {
	for i < len(b) {
		switch b[i] {
		case '\\':
			i += 2
			continue
		case '"':
			return i
		}
		i++
	}
	return -1
}

// HasEscape reports whether a raw JSON string contains escape sequences.
func HasEscape(raw []byte) bool {
	for _, c := range raw {
		if c == '\\' {
			return true
		}
	}
	return false
}

// Unescape decodes a raw JSON string body into dst.
func Unescape(dst, raw []byte) []byte {
	if !HasEscape(raw) {
		return append(dst, raw...)
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c != '\\' || i+1 >= len(raw) {
			dst = append(dst, c)
			continue
		}
		i++
		switch raw[i] {
		case 'n':
			dst = append(dst, '\n')
		case 't':
			dst = append(dst, '\t')
		case 'r':
			dst = append(dst, '\r')
		case 'b':
			dst = append(dst, '\b')
		case 'f':
			dst = append(dst, '\f')
		case 'u':
			if i+4 < len(raw) {
				r, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 32)
				if err == nil {
					i += 4
					ru := rune(r)
					if ru >= 0xD800 && ru < 0xDC00 && i+6 < len(raw) && raw[i+1] == '\\' && raw[i+2] == 'u' {
						if r2, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 32); err == nil {
							ru = (ru-0xD800)<<10 + (rune(r2) - 0xDC00) + 0x10000
							i += 6
						}
					}
					dst = utf8.AppendRune(dst, ru)
					continue
				}
			}
			dst = append(dst, 'u')
		default:
			dst = append(dst, raw[i])
		}
	}
	return dst
}

const hex = "0123456789abcdef"

// AppendString appends s as a quoted JSON string.
func AppendString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c != '"' && c != '\\' && c < 0x7f {
			continue
		}
		if c >= 0x80 {
			continue // UTF-8 passes through
		}
		dst = append(dst, s[start:i]...)
		switch c {
		case '"', '\\':
			dst = append(dst, '\\', c)
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
		}
		start = i + 1
	}
	dst = append(dst, s[start:]...)
	return append(dst, '"')
}

// AppendBytesString appends b as a quoted JSON string.
func AppendBytesString(dst, b []byte) []byte {
	return AppendString(dst, unsafeString(b))
}

// AppendRaw appends an already-escaped JSON string body inside quotes.
func AppendRaw(dst, raw []byte) []byte {
	dst = append(dst, '"')
	dst = append(dst, raw...)
	return append(dst, '"')
}

// LabelNameOK reports whether s is a valid Prometheus/Loki label name.
func LabelNameOK(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// SanitizeLabelName converts a VictoriaLogs field name (e.g. service.name)
// into a valid Loki label name (service_name).
func SanitizeLabelName(s string) string {
	if LabelNameOK(s) {
		return s
	}
	b := make([]byte, 0, len(s)+1)
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		b = append(b, '_')
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b = append(b, c)
		} else {
			b = append(b, '_')
		}
	}
	return string(b)
}

// AppendSanitizedName appends the sanitized label name for a raw (escaped)
// JSON key without allocating in the common case.
func AppendSanitizedName(dst, rawKey []byte) []byte {
	dst = append(dst, '"')
	if HasEscape(rawKey) {
		var tmp [128]byte
		rawKey = Unescape(tmp[:0], rawKey)
	}
	if len(rawKey) > 0 && rawKey[0] >= '0' && rawKey[0] <= '9' {
		dst = append(dst, '_')
	}
	for _, c := range rawKey {
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			dst = append(dst, c)
		} else {
			dst = append(dst, '_')
		}
	}
	return append(dst, '"')
}
