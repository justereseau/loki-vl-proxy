// Package translate converts parsed LogQL expressions into LogsQL.
package translate

import (
	"fmt"
	"regexp/syntax"
	"strconv"
	"strings"

	"github.com/Justereseau/loki-vl-proxy/internal/logql"
)

// Options control the translation.
type Options struct {
	// LevelFields are the VictoriaLogs fields exposed as Loki's
	// `detected_level` (the first non-empty one wins). Empty disables the mapping.
	LevelFields []string
	// NormalizeLevels maps raw level values (ERR, Warning, ...) to Loki's
	// normalized detected_level values (error, warn, ...).
	NormalizeLevels bool
	// IgnoreParsers drops `| json`, `| logfmt` and `| unpack` stages. Use it when
	// logs are stored as structured fields in VictoriaLogs (the common case),
	// so no per-query parsing is needed.
	IgnoreParsers bool
	// IsNative reports whether a VictoriaLogs field is stored natively (as
	// opposed to only existing after | json / | logfmt). Filters on native
	// fields placed before parsers are hoisted into the indexed filter part of
	// the query; others run after the parsers. nil means "all native".
	IsNative func(field string) bool
	// ResolveName maps a Loki label name (e.g. service_name) to the
	// VictoriaLogs field name (e.g. service.name). nil means identity.
	ResolveName func(string) string
}

// DetectedLevel is Loki's synthetic level label.
const DetectedLevel = "detected_level"

// Field maps a Loki label name to the VictoriaLogs field name.
func (o *Options) Field(name string) string {
	if name == DetectedLevel && len(o.LevelFields) > 0 {
		if len(o.LevelFields) == 1 {
			return o.LevelFields[0]
		}
		// several candidate fields: the caller must materialize
		// detected_level with LevelCoalescePipe before using it as a field.
		return DetectedLevel
	}
	if o.ResolveName != nil {
		return o.ResolveName(name)
	}
	return name
}

// MultiLevel reports whether detected_level is computed from several fields.
func (o *Options) MultiLevel() bool { return len(o.LevelFields) > 1 }

// LevelCoalescePipe returns the pipe materializing detected_level from LevelFields.
func (o *Options) LevelCoalescePipe() string {
	names := make([]string, len(o.LevelFields))
	for i, f := range o.LevelFields {
		names[i] = fieldName(f)
	}
	return "coalesce (" + strings.Join(names, ", ") + ") as " + DetectedLevel
}

// Log translates a log query into a LogsQL query.
func Log(e *logql.LogExpr, o *Options) (string, error) {
	q, _, err := LogWithMeta(e, o)
	return q, err
}

// LogMeta describes how results of a translated log query must be rendered.
type LogMeta struct {
	// LabelsFromFields is set when the pipeline changes the label set
	// (drop, keep, label_format): stream labels must then be read from the
	// returned fields instead of the original `_stream` value.
	LabelsFromFields bool
}

// LogWithMeta translates a log query and reports rendering hints.
func LogWithMeta(e *logql.LogExpr, o *Options) (string, LogMeta, error) {
	var b builder
	if err := b.logExpr(e, o); err != nil {
		return "", LogMeta{}, err
	}
	return b.String(), LogMeta{LabelsFromFields: b.labelsMutated}, nil
}

// LabelsSelector translates a bare stream selector (used by /labels?query=,
// /series, /index/*) into LogsQL filters. An empty selector matches everything.
func LabelsSelector(q string, o *Options) (string, error) {
	q = strings.TrimSpace(q)
	if q == "" || q == "{}" {
		return "*", nil
	}
	e, err := logql.ParseLog(q)
	if err != nil {
		return "", err
	}
	return Log(e, o)
}

// builder accumulates top-level filters and pipes.
type builder struct {
	filters []string
	pipes   []string
	// opaque is set once a pipe that may create or modify arbitrary fields was
	// added; later label filters must then run as `| filter` pipes.
	opaque bool
	// msgChanged is set once `_msg` may have been rewritten (line_format).
	msgChanged bool
	// parsersLeft counts parser stages not yet emitted; deferred holds
	// filters on non-native fields waiting for the last parser.
	parsersLeft int
	deferred    []string
	// labelsMutated is set by drop / keep / label_format.
	labelsMutated bool
}

func (b *builder) String() string {
	var sb strings.Builder
	if len(b.filters) == 0 {
		sb.WriteString("*")
	} else {
		for i, f := range b.filters {
			if i > 0 {
				sb.WriteByte(' ')
			}
			sb.WriteString(f)
		}
	}
	for _, p := range b.pipes {
		sb.WriteString(" | ")
		sb.WriteString(p)
	}
	return sb.String()
}

func (b *builder) addFilter(f string, hoist bool) {
	if f == "" {
		return
	}
	if hoist {
		b.filters = append(b.filters, f)
	} else {
		b.pipes = append(b.pipes, "filter "+f)
	}
}

func (b *builder) logExpr(e *logql.LogExpr, o *Options) error {
	if s := streamFilter(e.Matchers, o); s != "" {
		b.filters = append(b.filters, s)
	}
	for _, st := range e.Stages {
		if ps, ok := st.(*logql.ParserStage); ok && (!o.IgnoreParsers || !isUnpackParser(ps.Kind)) {
			b.parsersLeft++
		}
	}
	for _, st := range e.Stages {
		if err := b.stage(st, o); err != nil {
			return err
		}
	}
	for _, f := range b.deferred { // defensive: no parser consumed them
		b.pipes = append(b.pipes, "filter "+f)
	}
	b.deferred = nil
	return nil
}

func isUnpackParser(kind string) bool { return kind == "json" || kind == "logfmt" || kind == "unpack" }

// labelFields collects the VictoriaLogs fields referenced by a label filter.
func labelFields(f logql.LabelFilter, o *Options, dst []string) []string {
	switch x := f.(type) {
	case *logql.LabelBinary:
		dst = labelFields(x.L, o, dst)
		return labelFields(x.R, o, dst)
	case *logql.LabelCmp:
		if isErrorLabel(x.Name) {
			return dst
		}
		if x.Name == DetectedLevel && len(o.LevelFields) > 0 {
			return append(dst, o.LevelFields...)
		}
		return append(dst, o.Field(x.Name))
	}
	return dst
}

func (b *builder) stage(st logql.Stage, o *Options) error {
	switch s := st.(type) {
	case *logql.LineFilter:
		f, err := lineFilter(s)
		if err != nil {
			return err
		}
		b.addFilter(f, !b.msgChanged)
	case *logql.LabelFilterStage:
		f := labelFilter(s.Filter, o)
		if f == "" {
			return nil
		}
		if b.opaque {
			b.pipes = append(b.pipes, "filter "+f)
			return nil
		}
		if b.parsersLeft > 0 && o.IsNative != nil {
			for _, name := range labelFields(s.Filter, o, nil) {
				if !o.IsNative(name) {
					// the field may only exist once the line is parsed
					b.deferred = append(b.deferred, f)
					return nil
				}
			}
		}
		b.filters = append(b.filters, f)
	case *logql.ParserStage:
		return b.parser(s, o)
	case *logql.LineFormat:
		tmpl, err := convertTemplate(s.Template, o)
		if err != nil {
			return err
		}
		b.pipes = append(b.pipes, "format "+strconv.Quote(tmpl)+" as _msg")
		b.msgChanged = true
	case *logql.LabelFormat:
		for _, it := range s.Items {
			if it.IsTemplate {
				tmpl, err := convertTemplate(it.Src, o)
				if err != nil {
					return err
				}
				b.pipes = append(b.pipes, "format "+strconv.Quote(tmpl)+" as "+fieldName(o.Field(it.Dst)))
			} else {
				b.pipes = append(b.pipes, "rename "+fieldName(o.Field(it.Src))+" as "+fieldName(o.Field(it.Dst)))
			}
		}
		b.opaque = true
		b.labelsMutated = true
	case *logql.Drop:
		var names []string
		changed := false
		for _, it := range s.Items {
			if isErrorLabel(it.Name) {
				continue // VictoriaLogs never sets __error__
			}
			changed = true
			if it.Matcher != nil {
				cond := labelFilter(it.Matcher, o)
				b.pipes = append(b.pipes, "format if ("+cond+") \"\" as "+fieldName(o.Field(it.Name)))
				continue
			}
			names = append(names, fieldName(o.Field(it.Name)))
		}
		if len(names) > 0 {
			b.pipes = append(b.pipes, "delete "+strings.Join(names, ", "))
		}
		if changed {
			b.opaque = true
			b.labelsMutated = true
		}
	case *logql.Keep:
		names := []string{"_time", "_stream", "_stream_id", "_msg"}
		for _, it := range s.Items {
			if isErrorLabel(it.Name) {
				continue
			}
			f := fieldName(o.Field(it.Name))
			if it.Matcher != nil {
				// keep name="value": the label is kept only when it matches
				b.pipes = append(b.pipes, "format if (!("+labelFilter(it.Matcher, o)+")) \"\" as "+f)
			}
			names = append(names, f)
		}
		b.pipes = append(b.pipes, "fields "+strings.Join(names, ", "))
		b.opaque = true
		b.labelsMutated = true
	case *logql.Decolorize:
		b.pipes = append(b.pipes, "decolorize")
		b.msgChanged = true
	case *logql.Unwrap:
		return fmt.Errorf("unwrap is only allowed inside range aggregations")
	default:
		return fmt.Errorf("unsupported pipeline stage %T", st)
	}
	return nil
}

func isErrorLabel(n string) bool { return n == "__error__" || n == "__error_details__" }

func (b *builder) parser(s *logql.ParserStage, o *Options) error {
	if err := b.parserPipes(s, o); err != nil {
		return err
	}
	if !o.IgnoreParsers || !isUnpackParser(s.Kind) {
		b.parsersLeft--
		if b.parsersLeft == 0 {
			for _, f := range b.deferred {
				b.pipes = append(b.pipes, "filter "+f)
			}
			b.deferred = nil
		}
	}
	return nil
}

func (b *builder) parserPipes(s *logql.ParserStage, o *Options) error {
	switch s.Kind {
	case "json", "unpack", "logfmt":
		if o.IgnoreParsers {
			return nil
		}
		pipe := "unpack_json"
		if s.Kind == "logfmt" {
			pipe = "unpack_logfmt"
		}
		if len(s.Params) == 0 {
			b.pipes = append(b.pipes, pipe+" keep_original_fields")
			b.opaque = true
			if s.Kind == "unpack" {
				// unpack replaces the log line with the packed `_entry` property
				b.pipes = append(b.pipes, `format if (_entry:*) "<_entry>" as _msg`, "delete _entry")
				b.msgChanged = true
			}
			return nil
		}
		srcs := make([]string, 0, len(s.Params))
		var renames []string
		for _, p := range s.Params {
			src := jsonPath(p.Expr)
			srcs = append(srcs, fieldName(src))
			if dst := o.Field(p.Name); dst != src {
				renames = append(renames, "rename "+fieldName(src)+" as "+fieldName(dst))
			}
		}
		b.pipes = append(b.pipes, pipe+" fields ("+strings.Join(srcs, ", ")+") keep_original_fields")
		b.pipes = append(b.pipes, renames...)
		b.opaque = true
	case "regexp":
		b.pipes = append(b.pipes, "extract_regexp "+strconv.Quote(s.Arg)+" keep_original_fields")
		b.opaque = true
	case "pattern":
		// Loki patterns are anchored at the start of the line, VictoriaLogs
		// `extract` searches the first literal anywhere: apply it only to
		// lines starting with that literal.
		cond := ""
		if i := strings.IndexByte(s.Arg, '<'); i != 0 {
			prefix := s.Arg
			if i > 0 {
				prefix = s.Arg[:i]
			}
			cond = "if (_msg:=" + strconv.Quote(prefix) + "*) "
		}
		b.pipes = append(b.pipes, "extract "+cond+strconv.Quote(s.Arg)+" keep_original_fields")
		b.opaque = true
	default:
		return fmt.Errorf("unsupported parser %q", s.Kind)
	}
	return nil
}

// jsonPath converts Loki json expressions (a.b, a["b"]) to VictoriaLogs
// flattened field names (a.b).
func jsonPath(expr string) string {
	if !strings.ContainsAny(expr, `["]`) {
		return expr
	}
	r := strings.NewReplacer(`["`, ".", `"]`, "", `['`, ".", `']`, "", "[", ".", "]", "")
	return strings.TrimPrefix(r.Replace(expr), ".")
}

// streamFilter renders the Loki stream selector as a LogsQL stream filter.
func streamFilter(ms []logql.Matcher, o *Options) string {
	var sb strings.Builder
	n := 0
	for _, m := range ms {
		if m.Name == "__stream_shard__" { // Loki sharding hint, meaningless here
			continue
		}
		if m.Op == logql.MatchRe && (m.Value == ".*" || m.Value == "") {
			continue // matches everything
		}
		if n == 0 {
			sb.WriteByte('{')
		} else {
			sb.WriteByte(',')
		}
		n++
		sb.WriteString(streamLabelName(o.Field(m.Name)))
		sb.WriteString(m.Op.String())
		sb.WriteString(strconv.Quote(m.Value))
	}
	if n == 0 {
		return ""
	}
	sb.WriteByte('}')
	return sb.String()
}

func streamLabelName(n string) string {
	if isPlainName(n) {
		return n
	}
	return strconv.Quote(n)
}

func lineFilter(s *logql.LineFilter) (string, error) {
	parts := make([]string, 0, len(s.Values))
	for _, v := range s.Values {
		var f string
		switch s.Op {
		case logql.LineContains, logql.LineNotContains:
			if v == "" {
				f = "*" // every line contains the empty string
			} else {
				f = "*" + strconv.Quote(v) + "*"
			}
		case logql.LineRegex, logql.LineNotRegex:
			if v == "" || v == ".*" {
				f = "*"
			} else {
				if _, err := syntax.Parse(v, syntax.Perl); err != nil {
					return "", fmt.Errorf("invalid regexp %q: %w", v, err)
				}
				// In LogQL line filters `.` also matches newlines.
				if strings.Contains(v, ".") && !strings.HasPrefix(v, "(?s") {
					v = "(?s)" + v
				}
				f = "~" + strconv.Quote(v)
			}
		case logql.LinePattern, logql.LineNotPattern:
			f = patternFilter(v)
		}
		parts = append(parts, f)
	}
	var f string
	if len(parts) == 1 {
		f = parts[0]
	} else {
		f = "(" + strings.Join(parts, " or ") + ")"
	}
	if s.Op.Negated() {
		if f == "*" {
			return "!*", nil
		}
		return "!" + f, nil
	}
	if f == "*" {
		return "", nil
	}
	return f, nil
}

// vlPlaceholders are the placeholders understood by VictoriaLogs pattern_match
// filters (and produced by `collapse_nums prettify`, which backs /patterns).
var vlPlaceholders = map[string]bool{
	"N": true, "UUID": true, "IP4": true, "TIME": true, "DATE": true, "DATETIME": true, "W": true,
}

// patternFilter converts a Loki `|> "pattern"` filter. Patterns that only use
// VictoriaLogs placeholders are translated to pattern_match_full(); patterns
// with Loki `<_>` / named captures fall back to an anchored regexp.
func patternFilter(p string) string {
	onlyVL := true
	var re strings.Builder
	re.WriteString("(?s)^")
	rest := p
	for {
		i := strings.IndexByte(rest, '<')
		if i < 0 {
			re.WriteString(regexpQuote(rest))
			break
		}
		j := strings.IndexByte(rest[i:], '>')
		if j < 0 {
			re.WriteString(regexpQuote(rest))
			break
		}
		name := rest[i+1 : i+j]
		if !isPlaceholderName(name) {
			re.WriteString(regexpQuote(rest[:i+1]))
			rest = rest[i+1:]
			continue
		}
		if !vlPlaceholders[name] {
			onlyVL = false
		}
		re.WriteString(regexpQuote(rest[:i]))
		re.WriteString(".*?")
		rest = rest[i+j+1:]
	}
	if onlyVL {
		return "pattern_match_full(" + strconv.Quote(p) + ")"
	}
	re.WriteString("$")
	return "~" + strconv.Quote(re.String())
}

func isPlaceholderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func regexpQuote(s string) string {
	const meta = `\.+*?()|[]{}^$`
	if !strings.ContainsAny(s, meta) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(meta, s[i]) >= 0 {
			sb.WriteByte('\\')
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

// labelFilter renders a label filter expression; OR groups are parenthesized.
func labelFilter(f logql.LabelFilter, o *Options) string {
	switch x := f.(type) {
	case *logql.LabelBinary:
		l := labelFilter(x.L, o)
		r := labelFilter(x.R, o)
		if x.Or {
			if l == "" || r == "" { // one side matches everything
				return ""
			}
			return "(" + l + " or " + r + ")"
		}
		switch {
		case l == "":
			return r
		case r == "":
			return l
		}
		return l + " " + r
	case *logql.LabelCmp:
		return labelCmp(x, o)
	}
	return ""
}

func labelCmp(c *logql.LabelCmp, o *Options) string {
	if isErrorLabel(c.Name) {
		// VictoriaLogs never sets __error__: `__error__=""` is always true and
		// `__error__!=""` always false.
		switch c.Op {
		case logql.CmpEq:
			if c.Value == "" {
				return ""
			}
			return "!*"
		case logql.CmpNeq:
			if c.Value == "" {
				return "!*"
			}
			return ""
		}
	}
	if c.Name == DetectedLevel && len(o.LevelFields) > 0 && c.Kind == logql.ValString {
		return levelFilter(c, o)
	}
	name := fieldName(o.Field(c.Name))
	switch c.Kind {
	case logql.ValIP:
		fn := "ipv4_range"
		if strings.Contains(c.Value, ":") {
			fn = "ipv6_range"
		}
		f := name + ":" + fn + "(" + strconv.Quote(c.Value) + ")"
		if c.Op == logql.CmpNeq {
			return "!" + f
		}
		return f
	case logql.ValNumber, logql.ValDuration:
		c = normalizeNumericLiteral(c)
		switch c.Op {
		case logql.CmpGt, logql.CmpGte, logql.CmpLt, logql.CmpLte:
			return name + ":" + c.Op.String() + c.Value
		case logql.CmpEq:
			return name + ":range[" + c.Value + ", " + c.Value + "]"
		case logql.CmpNeq:
			return "!" + name + ":range[" + c.Value + ", " + c.Value + "]"
		}
	}
	switch c.Op {
	case logql.CmpEq:
		return name + ":=" + strconv.Quote(c.Value)
	case logql.CmpNeq:
		if c.Value == "" {
			return name + ":*"
		}
		return "!" + name + ":=" + strconv.Quote(c.Value)
	case logql.CmpRe:
		return regexFieldFilter(name, c.Value)
	case logql.CmpNre:
		f := regexFieldFilter(name, c.Value)
		if f == "" {
			return "!*"
		}
		return "!" + f
	default:
		// string comparison with > / <
		return name + ":" + c.Op.String() + strconv.Quote(c.Value)
	}
}

// regexFieldFilter renders a fully-anchored Loki label regexp as the cheapest
// equivalent LogsQL filter. Empty result means "matches everything".
func regexFieldFilter(name, re string) string {
	switch re {
	case ".*", "":
		if re == "" {
			return name + `:=""`
		}
		return ""
	case ".+":
		return name + ":*"
	}
	if lit, ok := literalRegex(re); ok {
		return name + ":=" + strconv.Quote(lit)
	}
	if alts, ok := literalAlternation(re); ok {
		q := make([]string, len(alts))
		for i, a := range alts {
			q[i] = strconv.Quote(a)
		}
		return name + ":in(" + strings.Join(q, ", ") + ")"
	}
	if strings.HasSuffix(re, ".*") {
		if lit, ok := literalRegex(re[:len(re)-2]); ok && lit != "" {
			return name + ":=" + strconv.Quote(lit) + "*"
		}
	}
	return name + ":~" + strconv.Quote("^(?:"+re+")$")
}

// literalRegex reports whether re matches exactly one literal string.
func literalRegex(re string) (string, bool) {
	if re == "" {
		return "", true
	}
	r, err := syntax.Parse(re, syntax.Perl)
	if err != nil {
		return "", false
	}
	r = r.Simplify()
	if r.Op == syntax.OpLiteral && r.Flags&syntax.FoldCase == 0 {
		return string(r.Rune), true
	}
	return "", false
}

func literalAlternation(re string) ([]string, bool) {
	if !strings.Contains(re, "|") || strings.ContainsAny(re, "()[]") || strings.Contains(re, `\|`) {
		return nil, false
	}
	parts := strings.Split(re, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		lit, ok := literalRegex(p)
		if !ok {
			return nil, false
		}
		out = append(out, lit)
	}
	return out, true
}

// convertTemplate converts the Go-template subset `text {{.field}} text` used by
// line_format / label_format into the LogsQL `format` syntax `text <field> text`.
func convertTemplate(t string, o *Options) (string, error) {
	var sb strings.Builder
	for {
		i := strings.Index(t, "{{")
		if i < 0 {
			sb.WriteString(t)
			return sb.String(), nil
		}
		sb.WriteString(t[:i])
		j := strings.Index(t[i:], "}}")
		if j < 0 {
			return "", fmt.Errorf("unterminated template action in %q", t)
		}
		action := strings.TrimSpace(strings.Trim(strings.TrimSpace(t[i+2:i+j]), "-"))
		if action == "__line__" {
			sb.WriteString("<_msg>")
			t = t[i+j+2:]
			continue
		}
		if len(action) < 2 || action[0] != '.' || strings.ContainsAny(action, " ()|$\"") {
			return "", fmt.Errorf("unsupported template action {{%s}}: only {{.field}} references are supported", action)
		}
		sb.WriteByte('<')
		sb.WriteString(o.Field(action[1:]))
		sb.WriteByte('>')
		t = t[i+j+2:]
	}
}

var logsqlKeywords = map[string]bool{"and": true, "or": true, "not": true, "by": true, "if": true, "as": true}

func isPlainName(n string) bool {
	if n == "" || logsqlKeywords[strings.ToLower(n)] {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (i == 0 || (c != '.' && (c < '0' || c > '9'))) {
			return false
		}
	}
	return true
}

// fieldName quotes a LogsQL field name when needed.
func fieldName(n string) string {
	if isPlainName(n) {
		return n
	}
	return strconv.Quote(n)
}

// byteUnits are the LogQL byte-size units (label filter values and bytes()).
var byteUnits = map[string]float64{
	"b": 1, "kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12, "pb": 1e15,
	"kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "tib": 1 << 40, "pib": 1 << 50,
}

// normalizeNumericLiteral converts LogQL byte sizes (42MB, 1.5KiB, 20B, 3kB)
// to plain numbers, since VictoriaLogs only understands a subset of the units.
// Durations are passed through: LogsQL accepts the same units.
func normalizeNumericLiteral(c *logql.LabelCmp) *logql.LabelCmp {
	if c.Kind != logql.ValDuration {
		return c
	}
	v := strings.TrimPrefix(c.Value, "-")
	i := 0
	for i < len(v) && (v[i] == '.' || (v[i] >= '0' && v[i] <= '9')) {
		i++
	}
	mul, ok := byteUnits[strings.ToLower(v[i:])]
	if !ok || i == 0 {
		return c
	}
	n, err := strconv.ParseFloat(v[:i], 64)
	if err != nil {
		return c
	}
	cc := *c
	cc.Kind = logql.ValNumber
	cc.Value = strconv.FormatFloat(n*mul, 'f', -1, 64)
	if strings.HasPrefix(c.Value, "-") {
		cc.Value = "-" + cc.Value
	}
	return &cc
}
