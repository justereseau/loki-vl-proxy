package translate

import (
	"strconv"
	"strings"

	"github.com/Justereseau/loki-vl-proxy/internal/logql"
)

// Loki normalizes detected_level values; Logs Drilldown relies on them for
// colors and filters. The aliases follow Loki's level detection.
var levelAliases = [...]struct {
	norm    string
	aliases []string
}{
	{"trace", []string{"trace", "trc"}},
	{"debug", []string{"debug", "dbg"}},
	{"info", []string{"info", "inf", "information", "informational", "notice"}},
	{"warn", []string{"warn", "warning", "wrn"}},
	{"error", []string{"error", "err", "eror"}},
	{"critical", []string{"critical", "crit", "fatal", "emerg", "emergency", "alert", "panic"}},
}

// UnknownLevel is reported for unrecognized level values.
const UnknownLevel = "unknown"

var levelNorm = func() map[string]string {
	m := map[string]string{}
	for _, l := range levelAliases {
		for _, a := range l.aliases {
			m[a] = l.norm
		}
	}
	return m
}()

// NormalizeLevel maps a raw level value to Loki's normalized level.
func NormalizeLevel(v string) string {
	if n, ok := levelNorm[v]; ok {
		return n
	}
	if n, ok := levelNorm[strings.ToLower(strings.TrimSpace(v))]; ok {
		return n
	}
	return UnknownLevel
}

// NormalizeLevelBytes is NormalizeLevel without allocating for known values.
func NormalizeLevelBytes(b []byte) string {
	if n, ok := levelNorm[string(b)]; ok {
		return n
	}
	return NormalizeLevel(string(b))
}

// levelVariants returns the raw spellings matching a normalized level
// (lowercase, UPPERCASE and Titlecase of every alias).
func levelVariants(norm string) []string {
	for _, l := range levelAliases {
		if l.norm != norm {
			continue
		}
		out := make([]string, 0, 3*len(l.aliases))
		for _, a := range l.aliases {
			out = append(out, a, strings.ToUpper(a), strings.ToUpper(a[:1])+a[1:])
		}
		return out
	}
	return nil
}

func allLevelVariants() []string {
	var out []string
	for _, l := range levelAliases {
		out = append(out, levelVariants(l.norm)...)
	}
	return out
}

// levelFilter renders a filter on detected_level over the configured level
// fields, expanding normalized values into their raw spellings.
func levelFilter(c *logql.LabelCmp, o *Options) string {
	anyOf := func(vals []string) string {
		q := make([]string, len(vals))
		for i, v := range vals {
			q[i] = strconv.Quote(v)
		}
		in := ":in(" + strings.Join(q, ", ") + ")"
		parts := make([]string, len(o.LevelFields))
		for i, f := range o.LevelFields {
			parts[i] = fieldName(f) + in
		}
		if len(parts) == 1 {
			return parts[0]
		}
		return "(" + strings.Join(parts, " or ") + ")"
	}
	present := func() string {
		parts := make([]string, len(o.LevelFields))
		for i, f := range o.LevelFields {
			parts[i] = fieldName(f) + ":*"
		}
		if len(parts) == 1 {
			return parts[0]
		}
		return "(" + strings.Join(parts, " or ") + ")"
	}

	var alts []string
	negated := false
	switch c.Op {
	case logql.CmpEq, logql.CmpNeq:
		negated = c.Op == logql.CmpNeq
		if c.Value == "" {
			if negated {
				return present()
			}
			return "!" + present()
		}
		alts = []string{c.Value}
	case logql.CmpRe, logql.CmpNre:
		negated = c.Op == logql.CmpNre
		if c.Value == ".+" {
			if negated {
				return "!" + present()
			}
			return present()
		}
		if c.Value == ".*" {
			if negated {
				return "!*"
			}
			return ""
		}
		var ok bool
		if lit, isLit := literalRegex(c.Value); isLit {
			alts = []string{lit}
		} else if alts, ok = literalAlternation(c.Value); !ok {
			// arbitrary regexp: apply it to the raw values
			parts := make([]string, len(o.LevelFields))
			for i, f := range o.LevelFields {
				parts[i] = regexFieldFilter(fieldName(f), c.Value)
			}
			f := "(" + strings.Join(parts, " or ") + ")"
			if negated {
				return "!" + f
			}
			return f
		}
	default:
		return ""
	}

	var parts, raw []string
	for _, a := range alts {
		switch {
		case !o.NormalizeLevels:
			raw = append(raw, a)
		case a == UnknownLevel:
			parts = append(parts, "!"+anyOf(allLevelVariants()))
		default:
			if v := levelVariants(a); v != nil {
				raw = append(raw, v...)
			} else {
				raw = append(raw, a) // not a normalized name: match the raw value
			}
		}
	}
	if len(raw) > 0 {
		parts = append([]string{anyOf(raw)}, parts...)
	}
	f := parts[0]
	if len(parts) > 1 {
		f = "(" + strings.Join(parts, " or ") + ")"
	}
	if negated {
		return "!" + f
	}
	return f
}
