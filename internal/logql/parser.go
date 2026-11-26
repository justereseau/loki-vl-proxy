package logql

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Parse parses a LogQL query.
func Parse(q string) (Expr, error) {
	toks, err := lex(q)
	if err != nil {
		return nil, err
	}
	p := &parser{src: q, toks: toks}
	e, err := p.parseExpr(0)
	if err != nil {
		return nil, err
	}
	if t := p.peek(); t.kind != tEOF {
		return nil, p.errf(t, "unexpected %s %q", t.kind, t.val)
	}
	return e, nil
}

// ParseLog parses a query that must be a log query (stream selector + pipeline).
func ParseLog(q string) (*LogExpr, error) {
	e, err := Parse(q)
	if err != nil {
		return nil, err
	}
	le, ok := e.(*LogExpr)
	if !ok {
		return nil, fmt.Errorf("expected a log query, got a metric query")
	}
	return le, nil
}

var rangeAggs = map[string]bool{
	"count_over_time": true, "rate": true, "bytes_over_time": true, "bytes_rate": true,
	"sum_over_time": true, "avg_over_time": true, "max_over_time": true, "min_over_time": true,
	"first_over_time": true, "last_over_time": true, "stddev_over_time": true,
	"stdvar_over_time": true, "quantile_over_time": true, "absent_over_time": true,
	"rate_counter": true,
}

var vectorAggs = map[string]bool{
	"sum": true, "avg": true, "min": true, "max": true, "count": true, "stddev": true,
	"stdvar": true, "topk": true, "bottomk": true, "sort": true, "sort_desc": true,
}

type parser struct {
	src  string
	toks []token
	pos  int
}

func (p *parser) peek() token { return p.toks[p.pos] }
func (p *parser) peekAt(n int) token {
	if p.pos+n < len(p.toks) {
		return p.toks[p.pos+n]
	}
	return p.toks[len(p.toks)-1]
}
func (p *parser) next() token {
	t := p.toks[p.pos]
	if t.kind != tEOF {
		p.pos++
	}
	return t
}

// errf formats errors like Loki: "parse error at line 1, col 5: ...".
func (p *parser) errf(t token, format string, args ...any) error {
	line, col := 1, 1
	for i := 0; i < t.pos && i < len(p.src); i++ {
		if p.src[i] == '\n' {
			line, col = line+1, 1
		} else {
			col++
		}
	}
	return fmt.Errorf("parse error at line %d, col %d: %s", line, col, fmt.Sprintf(format, args...))
}

func (p *parser) expect(k tokKind) (token, error) {
	t := p.next()
	if t.kind != k {
		return t, p.errf(t, "expected %s, got %s %q", k, t.kind, t.val)
	}
	return t, nil
}

func (p *parser) isIdent(v string) bool {
	t := p.peek()
	return t.kind == tIdent && t.val == v
}

// binary operator precedence, lowest first (Prometheus semantics)
func binPrec(t token) (string, int) {
	switch t.kind {
	case tIdent:
		switch t.val {
		case "or":
			return "or", 1
		case "and", "unless":
			return t.val, 2
		}
	case tEqEq, tNeq, tGt, tGte, tLt, tLte:
		return t.val, 3
	case tAdd, tSub:
		return t.val, 4
	case tMul, tDiv, tMod:
		return t.val, 5
	case tPow:
		return t.val, 6
	}
	return "", 0
}

func (p *parser) parseExpr(minPrec int) (Expr, error) {
	lhs, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		op, prec := binPrec(p.peek())
		if prec == 0 || prec <= minPrec {
			return lhs, nil
		}
		p.next()
		b := &BinOp{Op: op, L: lhs}
		if p.isIdent("bool") {
			p.next()
			b.Bool = true
		}
		nextMin := prec
		if op == "^" { // right associative
			nextMin = prec - 1
		}
		rhs, err := p.parseExpr(nextMin)
		if err != nil {
			return nil, err
		}
		b.R = rhs
		lhs = b
	}
}

func (p *parser) parseUnary() (Expr, error) {
	t := p.peek()
	if t.kind == tSub || t.kind == tAdd {
		p.next()
		e, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		if t.kind == tAdd {
			return e, nil
		}
		if n, ok := e.(*NumberLit); ok {
			return &NumberLit{V: -n.V}, nil
		}
		return &BinOp{Op: "*", L: e, R: &NumberLit{V: -1}}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Expr, error) {
	t := p.peek()
	switch t.kind {
	case tLBrace:
		return p.parseLogExpr()
	case tNumber:
		p.next()
		v, err := parseFloat(t.val)
		if err != nil {
			return nil, p.errf(t, "invalid number %q", t.val)
		}
		return &NumberLit{V: v}, nil
	case tLParen:
		p.next()
		e, err := p.parseExpr(0)
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tRParen); err != nil {
			return nil, err
		}
		return e, nil
	case tIdent:
		switch {
		case rangeAggs[t.val]:
			return p.parseRangeAgg()
		case vectorAggs[t.val]:
			return p.parseVectorAgg()
		case t.val == "vector":
			p.next()
			if _, err := p.expect(tLParen); err != nil {
				return nil, err
			}
			e, err := p.parseExpr(0)
			if err != nil {
				return nil, err
			}
			n, ok := e.(*NumberLit)
			if !ok {
				return nil, p.errf(t, "vector() expects a scalar")
			}
			if _, err := p.expect(tRParen); err != nil {
				return nil, err
			}
			return &VectorLit{V: n.V}, nil
		}
		return nil, p.errf(t, "unsupported function or identifier %q", t.val)
	}
	return nil, p.errf(t, "unexpected %s %q", t.kind, t.val)
}

func parseFloat(s string) (float64, error) {
	return strconv.ParseFloat(strings.ReplaceAll(s, "_", ""), 64)
}

func (p *parser) parseGrouping() (*Grouping, error) {
	t := p.next() // by / without
	g := &Grouping{Without: t.val == "without"}
	if _, err := p.expect(tLParen); err != nil {
		return nil, err
	}
	for p.peek().kind != tRParen {
		id, err := p.expect(tIdent)
		if err != nil {
			return nil, err
		}
		g.Labels = append(g.Labels, id.val)
		if p.peek().kind == tComma {
			p.next()
		}
	}
	p.next()
	return g, nil
}

func (p *parser) parseVectorAgg() (Expr, error) {
	op := p.next().val
	v := &VectorAgg{Op: op}
	var err error
	if p.isIdent("by") || p.isIdent("without") {
		if v.Grouping, err = p.parseGrouping(); err != nil {
			return nil, err
		}
	}
	if _, err := p.expect(tLParen); err != nil {
		return nil, err
	}
	if op == "topk" || op == "bottomk" {
		t, err := p.expect(tNumber)
		if err != nil {
			return nil, err
		}
		if v.Param, err = parseFloat(t.val); err != nil {
			return nil, p.errf(t, "invalid parameter %q", t.val)
		}
		v.HasParam = true
		if _, err := p.expect(tComma); err != nil {
			return nil, err
		}
	}
	if v.Inner, err = p.parseExpr(0); err != nil {
		return nil, err
	}
	if _, err := p.expect(tRParen); err != nil {
		return nil, err
	}
	if v.Grouping == nil && (p.isIdent("by") || p.isIdent("without")) {
		if v.Grouping, err = p.parseGrouping(); err != nil {
			return nil, err
		}
	}
	return v, nil
}

func (p *parser) parseRangeAgg() (Expr, error) {
	r := &RangeAgg{Op: p.next().val}
	if _, err := p.expect(tLParen); err != nil {
		return nil, err
	}
	if r.Op == "quantile_over_time" {
		t, err := p.expect(tNumber)
		if err != nil {
			return nil, err
		}
		if r.Param, err = parseFloat(t.val); err != nil {
			return nil, p.errf(t, "invalid parameter %q", t.val)
		}
		r.HasParam = true
		if _, err := p.expect(tComma); err != nil {
			return nil, err
		}
	}
	if err := p.parseLogRange(r); err != nil {
		return nil, err
	}
	if _, err := p.expect(tRParen); err != nil {
		return nil, err
	}
	if p.isIdent("by") || p.isIdent("without") {
		g, err := p.parseGrouping()
		if err != nil {
			return nil, err
		}
		r.Grouping = g
	}
	return r, nil
}

// parseLogRange parses `{sel} pipeline [5m] offset 1m`, `{sel}[5m] pipeline`
// and the parenthesized form `({sel} pipeline)[5m]`.
func (p *parser) parseLogRange(r *RangeAgg) error {
	paren := false
	if p.peek().kind == tLParen {
		p.next()
		paren = true
	}
	le, err := p.parseLogExpr()
	if err != nil {
		return err
	}
	if paren {
		if _, err := p.expect(tRParen); err != nil {
			return err
		}
	}
	if p.peek().kind != tLBrack {
		return p.errf(p.peek(), "expected range such as [5m]")
	}
	p.next()
	t := p.next()
	if t.kind != tDuration && t.kind != tNumber {
		return p.errf(t, "invalid range %q", t.val)
	}
	if r.Range, err = ParseDuration(t.val); err != nil {
		return p.errf(t, "%s", err)
	}
	if _, err := p.expect(tRBrack); err != nil {
		return err
	}
	// pipeline after the range: {sel}[5m] | json
	if !paren {
		if err := p.parsePipeline(le); err != nil {
			return err
		}
	}
	if p.isIdent("offset") {
		p.next()
		t := p.next()
		if r.Offset, err = ParseDuration(t.val); err != nil {
			return p.errf(t, "%s", err)
		}
	}
	// split the stages around unwrap
	for i, st := range le.Stages {
		if u, ok := st.(*Unwrap); ok {
			r.Unwrap = u
			r.Post = le.Stages[i+1:]
			le.Stages = le.Stages[:i]
			break
		}
	}
	r.Log = le
	return nil
}

func (p *parser) parseLogExpr() (*LogExpr, error) {
	if _, err := p.expect(tLBrace); err != nil {
		return nil, err
	}
	le := &LogExpr{}
	for p.peek().kind != tRBrace {
		name := p.next()
		if name.kind != tIdent && name.kind != tString {
			return nil, p.errf(name, "expected label name, got %s %q", name.kind, name.val)
		}
		var op MatchOp
		switch t := p.next(); t.kind {
		case tEq:
			op = MatchEq
		case tNeq:
			op = MatchNeq
		case tRe:
			op = MatchRe
		case tNre:
			op = MatchNre
		default:
			return nil, p.errf(t, "expected matcher operator, got %q", t.val)
		}
		val, err := p.expect(tString)
		if err != nil {
			return nil, err
		}
		le.Matchers = append(le.Matchers, Matcher{Name: name.val, Op: op, Value: val.val})
		if p.peek().kind == tComma {
			p.next()
		}
	}
	p.next()
	if err := p.parsePipeline(le); err != nil {
		return nil, err
	}
	return le, nil
}

func (p *parser) parsePipeline(le *LogExpr) error {
	for {
		t := p.peek()
		var op LineOp
		switch t.kind {
		case tPipeEq:
			op = LineContains
		case tNeq:
			op = LineNotContains
		case tPipeRe:
			op = LineRegex
		case tNre:
			op = LineNotRegex
		case tPipeMatch:
			op = LinePattern
		case tNMatch:
			op = LineNotPattern
		case tPipe:
			p.next()
			st, err := p.parseStage()
			if err != nil {
				return err
			}
			if st != nil {
				le.Stages = append(le.Stages, st)
			}
			continue
		default:
			return nil
		}
		p.next()
		lf := &LineFilter{Op: op}
		for {
			v := p.peek()
			if v.kind == tIdent && v.val == "ip" {
				return p.errf(v, "ip() line filters are not supported")
			}
			s, err := p.expect(tString)
			if err != nil {
				return err
			}
			lf.Values = append(lf.Values, s.val)
			if p.isIdent("or") && p.peekAt(1).kind == tString {
				p.next()
				continue
			}
			break
		}
		le.Stages = append(le.Stages, lf)
	}
}

func isCmpTok(k tokKind) bool {
	switch k {
	case tEq, tEqEq, tNeq, tRe, tNre, tGt, tGte, tLt, tLte:
		return true
	}
	return false
}

func (p *parser) parseStage() (Stage, error) {
	t := p.peek()
	if t.kind == tIdent && !isCmpTok(p.peekAt(1).kind) {
		switch t.val {
		case "json", "logfmt":
			p.next()
			ps := &ParserStage{Kind: t.val}
			for p.peek().kind == tFlag {
				ps.Flags = append(ps.Flags, p.next().val)
			}
			for p.peek().kind == tIdent && !isKeywordAfterStage(p.peek().val) {
				name := p.next().val
				ex := LabelExtraction{Name: name, Expr: name}
				if p.peek().kind == tEq {
					p.next()
					s, err := p.expect(tString)
					if err != nil {
						return nil, err
					}
					ex.Expr = s.val
				}
				ps.Params = append(ps.Params, ex)
				if p.peek().kind != tComma {
					break
				}
				p.next()
			}
			return ps, nil
		case "regexp", "pattern":
			p.next()
			s, err := p.expect(tString)
			if err != nil {
				return nil, err
			}
			return &ParserStage{Kind: t.val, Arg: s.val}, nil
		case "unpack":
			p.next()
			return &ParserStage{Kind: "unpack"}, nil
		case "line_format":
			p.next()
			s, err := p.expect(tString)
			if err != nil {
				return nil, err
			}
			return &LineFormat{Template: s.val}, nil
		case "label_format":
			p.next()
			lf := &LabelFormat{}
			for {
				dst, err := p.expect(tIdent)
				if err != nil {
					return nil, err
				}
				if _, err := p.expect(tEq); err != nil {
					return nil, err
				}
				src := p.next()
				switch src.kind {
				case tIdent:
					lf.Items = append(lf.Items, LabelFormatItem{Dst: dst.val, Src: src.val})
				case tString:
					lf.Items = append(lf.Items, LabelFormatItem{Dst: dst.val, Src: src.val, IsTemplate: true})
				default:
					return nil, p.errf(src, "unexpected %q in label_format", src.val)
				}
				if p.peek().kind != tComma {
					break
				}
				p.next()
			}
			return lf, nil
		case "drop", "keep":
			p.next()
			var items []FieldItem
			for {
				id, err := p.expect(tIdent)
				if err != nil {
					return nil, err
				}
				it := FieldItem{Name: id.val}
				if isCmpTok(p.peek().kind) {
					p.pos--
					c, err := p.parseLabelCmp()
					if err != nil {
						return nil, err
					}
					it.Matcher = c
				}
				items = append(items, it)
				if p.peek().kind != tComma {
					break
				}
				p.next()
			}
			if t.val == "drop" {
				return &Drop{Items: items}, nil
			}
			return &Keep{Items: items}, nil
		case "decolorize":
			p.next()
			return &Decolorize{}, nil
		case "unwrap":
			p.next()
			u := &Unwrap{}
			id, err := p.expect(tIdent)
			if err != nil {
				return nil, err
			}
			if p.peek().kind == tLParen {
				switch id.val {
				case "duration", "duration_seconds", "bytes":
				default:
					return nil, p.errf(id, "unsupported unwrap conversion %q", id.val)
				}
				u.Conv = id.val
				p.next()
				lbl, err := p.expect(tIdent)
				if err != nil {
					return nil, err
				}
				u.Label = lbl.val
				if _, err := p.expect(tRParen); err != nil {
					return nil, err
				}
			} else {
				u.Label = id.val
			}
			return u, nil
		}
	}
	f, err := p.parseLabelOr()
	if err != nil {
		return nil, err
	}
	return &LabelFilterStage{Filter: f}, nil
}

func isKeywordAfterStage(s string) bool {
	// identifiers that cannot be json/logfmt params because they start something else
	switch s {
	case "or", "and", "by", "without", "offset":
		return true
	}
	return false
}

func (p *parser) parseLabelOr() (LabelFilter, error) {
	l, err := p.parseLabelAnd()
	if err != nil {
		return nil, err
	}
	for p.isIdent("or") {
		p.next()
		r, err := p.parseLabelAnd()
		if err != nil {
			return nil, err
		}
		l = &LabelBinary{Or: true, L: l, R: r}
	}
	return l, nil
}

func (p *parser) parseLabelAnd() (LabelFilter, error) {
	l, err := p.parseLabelUnary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		switch {
		case t.kind == tIdent && t.val == "and", t.kind == tComma:
			p.next()
		case t.kind == tLParen, t.kind == tIdent && t.val != "or" && isCmpTok(p.peekAt(1).kind):
			// implicit "and": `| a="b" c="d"`
		default:
			return l, nil
		}
		r, err := p.parseLabelUnary()
		if err != nil {
			return nil, err
		}
		l = &LabelBinary{L: l, R: r}
	}
}

func (p *parser) parseLabelUnary() (LabelFilter, error) {
	if p.peek().kind == tLParen {
		p.next()
		f, err := p.parseLabelOr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(tRParen); err != nil {
			return nil, err
		}
		return f, nil
	}
	return p.parseLabelCmp()
}

func (p *parser) parseLabelCmp() (*LabelCmp, error) {
	name := p.next()
	if name.kind != tIdent {
		return nil, p.errf(name, "expected label filter, got %s %q", name.kind, name.val)
	}
	c := &LabelCmp{Name: name.val}
	switch t := p.next(); t.kind {
	case tEq, tEqEq:
		c.Op = CmpEq
	case tNeq:
		c.Op = CmpNeq
	case tRe:
		c.Op = CmpRe
	case tNre:
		c.Op = CmpNre
	case tGt:
		c.Op = CmpGt
	case tGte:
		c.Op = CmpGte
	case tLt:
		c.Op = CmpLt
	case tLte:
		c.Op = CmpLte
	default:
		return nil, p.errf(t, "expected comparison operator after %q, got %q", name.val, t.val)
	}
	v := p.next()
	switch v.kind {
	case tString:
		c.Kind = ValString
	case tNumber:
		c.Kind = ValNumber
	case tDuration:
		c.Kind = ValDuration
	case tSub: // negative number
		n := p.next()
		if n.kind != tNumber && n.kind != tDuration {
			return nil, p.errf(n, "expected number after '-'")
		}
		c.Kind = ValNumber
		if n.kind == tDuration {
			c.Kind = ValDuration
		}
		c.Value = "-" + n.val
		return c, nil
	case tIdent:
		if v.val == "ip" && p.peek().kind == tLParen {
			p.next()
			s, err := p.expect(tString)
			if err != nil {
				return nil, err
			}
			if _, err := p.expect(tRParen); err != nil {
				return nil, err
			}
			c.Kind = ValIP
			c.Value = s.val
			return c, nil
		}
		return nil, p.errf(v, "unexpected identifier %q in label filter", v.val)
	default:
		return nil, p.errf(v, "unexpected %s %q in label filter", v.kind, v.val)
	}
	if (c.Op == CmpRe || c.Op == CmpNre) && c.Kind != ValString {
		return nil, p.errf(v, "regexp matcher expects a string")
	}
	c.Value = v.val
	return c, nil
}

// ParseDuration parses Prometheus/Loki durations such as 1h30m, 5m, 10s, 100ms, 1d, 1w, 1y.
// A plain number is interpreted as seconds.
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return time.Duration(f * float64(time.Second)), nil
	}
	var total float64
	orig := s
	for s != "" {
		i := 0
		for i < len(s) && (isDigit(s[i]) || s[i] == '.') {
			i++
		}
		if i == 0 {
			return 0, fmt.Errorf("invalid duration %q", orig)
		}
		n, err := strconv.ParseFloat(s[:i], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", orig)
		}
		s = s[i:]
		j := 0
		for j < len(s) && !isDigit(s[j]) && s[j] != '.' {
			j++
		}
		var unit float64
		switch s[:j] {
		case "ns":
			unit = 1
		case "us", "µs":
			unit = 1e3
		case "ms":
			unit = 1e6
		case "s":
			unit = 1e9
		case "m":
			unit = 60e9
		case "h":
			unit = 3600e9
		case "d":
			unit = 86400e9
		case "w":
			unit = 7 * 86400e9
		case "y":
			unit = 365 * 86400e9
		default:
			return 0, fmt.Errorf("invalid duration unit in %q", orig)
		}
		total += n * unit
		s = s[j:]
	}
	return time.Duration(total), nil
}
