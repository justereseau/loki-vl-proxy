package logql

import "time"

// Expr is either a *LogExpr (log query) or one of the metric expression types.
type Expr interface{ isExpr() }

// MatchOp is a stream selector / label matcher operator.
type MatchOp uint8

const (
	MatchEq  MatchOp = iota // =
	MatchNeq                // !=
	MatchRe                 // =~
	MatchNre                // !~
)

func (op MatchOp) String() string {
	return [...]string{"=", "!=", "=~", "!~"}[op]
}

// Matcher is a single `name op "value"` stream selector matcher.
type Matcher struct {
	Name  string
	Op    MatchOp
	Value string
}

// LogExpr is a stream selector followed by an optional pipeline.
type LogExpr struct {
	Matchers []Matcher
	Stages   []Stage
}

func (*LogExpr) isExpr() {}

// Stage is one pipeline stage.
type Stage interface{ isStage() }

// LineOp is a line filter operator.
type LineOp uint8

const (
	LineContains    LineOp = iota // |=
	LineNotContains               // !=
	LineRegex                     // |~
	LineNotRegex                  // !~
	LinePattern                   // |>
	LineNotPattern                // !>
)

// Negated reports whether the line filter excludes matching lines.
func (op LineOp) Negated() bool {
	return op == LineNotContains || op == LineNotRegex || op == LineNotPattern
}

// LineFilter is `|= "a" or "b"`. Values are OR-ed.
type LineFilter struct {
	Op     LineOp
	Values []string
}

// ParserStage is json / logfmt / regexp / pattern / unpack.
type ParserStage struct {
	Kind   string            // json, logfmt, regexp, pattern, unpack
	Arg    string            // regexp / pattern expression
	Params []LabelExtraction // json a="path" / logfmt a="key"
	Flags  []string          // --strict, --keep-empty
}

// LabelExtraction is `name="expression"` inside json / logfmt.
type LabelExtraction struct {
	Name string
	Expr string
}

// LabelFilterStage is `| <label filter expression>`.
type LabelFilterStage struct {
	Filter LabelFilter
}

// LabelFilter is either *LabelCmp or *LabelBinary.
type LabelFilter interface{ isLabelFilter() }

// ValueKind is the lexical kind of a label filter's right-hand side.
type ValueKind uint8

const (
	ValString ValueKind = iota
	ValNumber
	ValDuration // duration or byte size literal such as 10s / 5MB
	ValIP       // ip("...")
)

// CmpOp is a label filter comparison operator.
type CmpOp uint8

const (
	CmpEq CmpOp = iota
	CmpNeq
	CmpRe
	CmpNre
	CmpGt
	CmpGte
	CmpLt
	CmpLte
)

func (op CmpOp) String() string {
	return [...]string{"=", "!=", "=~", "!~", ">", ">=", "<", "<="}[op]
}

// LabelCmp is `name op value`.
type LabelCmp struct {
	Name  string
	Op    CmpOp
	Value string
	Kind  ValueKind
}

// LabelBinary is `l and r` / `l or r`.
type LabelBinary struct {
	Or   bool
	L, R LabelFilter
}

func (*LabelCmp) isLabelFilter()    {}
func (*LabelBinary) isLabelFilter() {}

// LineFormat is `| line_format "template"`.
type LineFormat struct{ Template string }

// LabelFormatItem is one `dst=src` or `dst="template"` assignment.
type LabelFormatItem struct {
	Dst        string
	Src        string
	IsTemplate bool
}

// LabelFormat is `| label_format a=b, c="{{.d}}"`.
type LabelFormat struct{ Items []LabelFormatItem }

// FieldItem is an entry of drop / keep: a bare name or a matcher.
type FieldItem struct {
	Name    string
	Matcher *LabelCmp
}

// Drop is `| drop a, b="c"`.
type Drop struct{ Items []FieldItem }

// Keep is `| keep a, b`.
type Keep struct{ Items []FieldItem }

// Decolorize is `| decolorize`.
type Decolorize struct{}

// Unwrap is `| unwrap [conv(]label[)]`. It is only valid inside range aggregations.
type Unwrap struct {
	Conv  string // "", "duration", "duration_seconds", "bytes"
	Label string
}

func (*LineFilter) isStage()       {}
func (*ParserStage) isStage()      {}
func (*LabelFilterStage) isStage() {}
func (*LineFormat) isStage()       {}
func (*LabelFormat) isStage()      {}
func (*Drop) isStage()             {}
func (*Keep) isStage()             {}
func (*Decolorize) isStage()       {}
func (*Unwrap) isStage()           {}

// Grouping is `by (a, b)` or `without (a)`.
type Grouping struct {
	Without bool
	Labels  []string
}

// RangeAgg is a range aggregation such as count_over_time(<log range>).
type RangeAgg struct {
	Op       string
	Param    float64 // quantile_over_time parameter
	HasParam bool
	Log      *LogExpr // pipeline stages before unwrap
	Unwrap   *Unwrap
	Post     []Stage // stages after unwrap (label filters such as __error__="")
	Range    time.Duration
	Offset   time.Duration
	Grouping *Grouping
}

// VectorAgg is sum / avg / min / max / count / stddev / stdvar / topk / bottomk / sort / sort_desc.
type VectorAgg struct {
	Op       string
	Param    float64
	HasParam bool
	Grouping *Grouping
	Inner    Expr
}

// BinOp is a binary operation between two expressions.
type BinOp struct {
	Op   string
	Bool bool
	L, R Expr
}

// NumberLit is a scalar literal.
type NumberLit struct{ V float64 }

// VectorLit is vector(<scalar>).
type VectorLit struct{ V float64 }

func (*RangeAgg) isExpr()  {}
func (*VectorAgg) isExpr() {}
func (*BinOp) isExpr()     {}
func (*NumberLit) isExpr() {}
func (*VectorLit) isExpr() {}
