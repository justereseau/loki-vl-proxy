// Package logql implements a small, allocation-conscious parser for the subset
// of LogQL that Grafana (Explore, Logs Drilldown) sends to Loki.
package logql

import (
	"fmt"
	"strconv"
	"strings"
)

type tokKind uint8

const (
	tEOF tokKind = iota
	tIdent
	tString   // value holds the decoded string
	tNumber   // plain number: 12, 0.5, 1e3
	tDuration // number with a unit suffix: 5m, 1h30m, 10MB (also bytes)
	tFlag     // --strict
	tLBrace
	tRBrace
	tLParen
	tRParen
	tLBrack
	tRBrack
	tComma
	tPipe      // |
	tPipeEq    // |=
	tPipeRe    // |~
	tPipeMatch // |>
	tNeq       // !=
	tNre       // !~
	tNMatch    // !>
	tEq        // =
	tEqEq      // ==
	tRe        // =~
	tGt        // >
	tGte       // >=
	tLt        // <
	tLte       // <=
	tAdd
	tSub
	tMul
	tDiv
	tMod
	tPow
)

var tokNames = [...]string{
	tEOF: "end of query", tIdent: "identifier", tString: "string", tNumber: "number",
	tDuration: "duration", tFlag: "flag", tLBrace: "{", tRBrace: "}", tLParen: "(",
	tRParen: ")", tLBrack: "[", tRBrack: "]", tComma: ",", tPipe: "|", tPipeEq: "|=",
	tPipeRe: "|~", tPipeMatch: "|>", tNeq: "!=", tNre: "!~", tNMatch: "!>", tEq: "=",
	tEqEq: "==", tRe: "=~", tGt: ">", tGte: ">=", tLt: "<", tLte: "<=", tAdd: "+",
	tSub: "-", tMul: "*", tDiv: "/", tMod: "%", tPow: "^",
}

func (k tokKind) String() string { return tokNames[k] }

type token struct {
	kind tokKind
	val  string
	pos  int
}

// lex tokenizes the whole query up front. Queries are short, so a single
// slice of tokens keeps the parser simple and allocation count low.
func lex(s string) ([]token, error) {
	toks := make([]token, 0, len(s)/3+4)
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
			continue
		case c == '#': // comment until end of line
			for i < len(s) && s[i] != '\n' {
				i++
			}
			continue
		case c == '"' || c == '`':
			v, n, err := lexString(s[i:])
			if err != nil {
				return nil, fmt.Errorf("parse error at line 1, col %d: %w", i+1, err)
			}
			toks = append(toks, token{tString, v, i})
			i += n
			continue
		case isDigit(c) || (c == '.' && i+1 < len(s) && isDigit(s[i+1])):
			start := i
			kind := tNumber
			for i < len(s) && (isDigit(s[i]) || s[i] == '.' || s[i] == '_') {
				i++
			}
			// exponent
			if i < len(s) && (s[i] == 'e' || s[i] == 'E') && i+1 < len(s) && (isDigit(s[i+1]) || ((s[i+1] == '+' || s[i+1] == '-') && i+2 < len(s) && isDigit(s[i+2]))) {
				i += 2
				for i < len(s) && isDigit(s[i]) {
					i++
				}
			}
			// unit suffix(es): durations (1h30m) and byte sizes (10MiB)
			for i < len(s) && isLetter(s[i]) {
				kind = tDuration
				for i < len(s) && (isLetter(s[i]) || s[i] == 'µ') {
					i++
				}
				for i < len(s) && (isDigit(s[i]) || s[i] == '.') {
					i++
				}
			}
			toks = append(toks, token{kind, s[start:i], start})
			continue
		case isIdentStart(c):
			start := i
			for i < len(s) && isIdentChar(s[i]) {
				i++
			}
			toks = append(toks, token{tIdent, s[start:i], start})
			continue
		}

		two := ""
		if i+1 < len(s) {
			two = s[i : i+2]
		}
		var k tokKind
		n := 2
		switch two {
		case "|=":
			k = tPipeEq
		case "|~":
			k = tPipeRe
		case "|>":
			k = tPipeMatch
		case "!=":
			k = tNeq
		case "!~":
			k = tNre
		case "!>":
			k = tNMatch
		case "==":
			k = tEqEq
		case "=~":
			k = tRe
		case ">=":
			k = tGte
		case "<=":
			k = tLte
		case "--":
			start := i
			i += 2
			for i < len(s) && (isIdentChar(s[i]) || s[i] == '-') {
				i++
			}
			if i == start+2 {
				return nil, fmt.Errorf("parse error at line 1, col %d: unexpected %q", start+1, "--")
			}
			toks = append(toks, token{tFlag, s[start:i], start})
			continue
		default:
			n = 1
			switch c {
			case '{':
				k = tLBrace
			case '}':
				k = tRBrace
			case '(':
				k = tLParen
			case ')':
				k = tRParen
			case '[':
				k = tLBrack
			case ']':
				k = tRBrack
			case ',':
				k = tComma
			case '|':
				k = tPipe
			case '=':
				k = tEq
			case '>':
				k = tGt
			case '<':
				k = tLt
			case '+':
				k = tAdd
			case '-':
				k = tSub
			case '*':
				k = tMul
			case '/':
				k = tDiv
			case '%':
				k = tMod
			case '^':
				k = tPow
			default:
				return nil, fmt.Errorf("parse error at line 1, col %d: unexpected character %q", i+1, c)
			}
		}
		toks = append(toks, token{k, s[i : i+n], i})
		i += n
	}
	toks = append(toks, token{tEOF, "", len(s)})
	return toks, nil
}

// lexString decodes a Go-style double-quoted or backtick-quoted string,
// which is what LogQL accepts. It returns the decoded value and the number of
// consumed bytes.
func lexString(s string) (string, int, error) {
	q := s[0]
	if q == '`' {
		end := strings.IndexByte(s[1:], '`')
		if end < 0 {
			return "", 0, fmt.Errorf("unterminated raw string")
		}
		return s[1 : end+1], end + 2, nil
	}
	escaped := false
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			escaped = true
			i++
		case '"':
			if !escaped {
				return s[1:i], i + 1, nil
			}
			v, err := strconv.Unquote(s[:i+1])
			if err != nil {
				return "", 0, fmt.Errorf("invalid string %s: %w", s[:i+1], err)
			}
			return v, i + 1, nil
		}
	}
	return "", 0, fmt.Errorf("unterminated string")
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isIdentStart(c byte) bool {
	return isLetter(c) || c == '_'
}

// isIdentChar accepts dots in addition to the Prometheus label charset, so
// that VictoriaLogs field names such as `service.name` can be referenced.
func isIdentChar(c byte) bool {
	return isLetter(c) || isDigit(c) || c == '_' || c == '.'
}
