package translate

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Justereseau/loki-vl-proxy/internal/logql"
)

// SlideKind tells how per-step buckets can be combined into a sliding window
// when the LogQL range is larger than the query step.
type SlideKind uint8

const (
	SlideNone SlideKind = iota
	SlideSum
	SlideMax
	SlideMin
)

// PostKind is a post-processing operation applied by the proxy to the series
// returned by VictoriaLogs.
type PostKind uint8

const (
	PostScale       PostKind = iota // v *= F
	PostScaleWindow                 // v /= window seconds (rate)
	PostSquare                      // v = v*v (stdvar)
	PostScalarOp                    // v = v <Op> F (or F <Op> v when ScalarLeft)
	PostCompare                     // keep (or 0/1 with Bool) where v <Op> F
	PostTopK                        // keep K largest per timestamp (Bottom: smallest)
	PostSort                        // instant: sort by value (Desc)
	PostAbsent                      // absent_over_time: 1 where no sample exists, with Labels
)

// PostOp is a single post-processing step.
type PostOp struct {
	Kind       PostKind
	F          float64
	Op         string
	ScalarLeft bool
	Bool       bool
	K          int
	Bottom     bool
	Desc       bool
	By         []string          // topk grouping (VL field names)
	Labels     map[string]string // absent_over_time labels
}

// MetricQuery is the translation result of a LogQL metric query.
type MetricQuery struct {
	// LogsQL ends with one or more `stats` pipes producing a field named `v`.
	LogsQL string
	// Range is the LogQL range ([5m]); Offset is the LogQL offset.
	Range  time.Duration
	Offset time.Duration
	// Slide tells whether step buckets can be combined into Range-wide windows.
	Slide SlideKind
	// ExpandStream is set when the result is grouped by `_stream`, whose value
	// must be expanded into individual labels.
	ExpandStream bool
	// Renames maps VictoriaLogs result label names to the Loki label names
	// requested by the query (e.g. level -> detected_level).
	Renames map[string]string
	Post    []PostOp
	// NameAsLabel turns each stats result name into a label with an empty
	// value (Loki /index/volume?aggregateBy=labels).
	NameAsLabel bool
	// Const is set for constant expressions such as vector(1)+vector(1)
	// (used by the Grafana data source health check).
	Const *float64
}

// ValueField is the name of the stats result field.
const ValueField = "v"

type statsLevel struct {
	by []string // VL field names, may include _stream
	fn string   // LogsQL stats function call, e.g. count()
}

type plan struct {
	base     string
	levels   []statsLevel
	labels   []string // current output labels (VL names); nil with perStream
	stream   bool     // current output keyed by _stream
	additive bool     // inner function can be re-grouped with sum
	minmax   string   // "min" / "max" when the inner function is min/max
	rng      time.Duration
	offset   time.Duration
	scale    float64
	window   bool // pending division by the window (rate)
	slide    SlideKind
	post     []PostOp
	renames  map[string]string
	coalesce bool // detected_level must be materialized before stats
}

// Metric translates a LogQL metric expression.
func Metric(e logql.Expr, o *Options) (*MetricQuery, error) {
	if v, ok := constValue(e); ok {
		return &MetricQuery{Const: &v}, nil
	}
	p, err := planExpr(e, o)
	if err != nil {
		return nil, err
	}
	p.flushScale()
	var sb strings.Builder
	sb.WriteString(p.base)
	if p.coalesce {
		sb.WriteString(" | " + o.LevelCoalescePipe())
	}
	for _, l := range p.levels {
		sb.WriteString(" | stats ")
		if len(l.by) > 0 {
			sb.WriteString("by (")
			for i, b := range l.by {
				if i > 0 {
					sb.WriteString(", ")
				}
				sb.WriteString(fieldName(b))
			}
			sb.WriteString(") ")
		}
		sb.WriteString(l.fn)
		sb.WriteString(" as " + ValueField)
	}
	return &MetricQuery{
		LogsQL:       sb.String(),
		Range:        p.rng,
		Offset:       p.offset,
		Slide:        p.slide,
		ExpandStream: p.stream,
		Renames:      p.renames,
		Post:         p.post,
	}, nil
}

func constValue(e logql.Expr) (float64, bool) {
	switch x := e.(type) {
	case *logql.NumberLit:
		return x.V, true
	case *logql.VectorLit:
		return x.V, true
	case *logql.BinOp:
		l, ok1 := constValue(x.L)
		r, ok2 := constValue(x.R)
		if !ok1 || !ok2 {
			return 0, false
		}
		v, ok := applyScalar(x.Op, l, r)
		return v, ok
	}
	return 0, false
}

// applyScalar evaluates arithmetic and comparison operators. Comparisons
// return 1/0 and ok=false when the comparison is false (filtered sample).
func applyScalar(op string, l, r float64) (float64, bool) {
	switch op {
	case "+":
		return l + r, true
	case "-":
		return l - r, true
	case "*":
		return l * r, true
	case "/":
		return l / r, true
	case "%":
		return float64(int64(l) % max(int64(r), 1)), true
	case "^":
		v := 1.0
		for i := 0; i < int(r); i++ {
			v *= l
		}
		return v, true
	case "==":
		return b2f(l == r), l == r
	case "!=":
		return b2f(l != r), l != r
	case ">":
		return b2f(l > r), l > r
	case ">=":
		return b2f(l >= r), l >= r
	case "<":
		return b2f(l < r), l < r
	case "<=":
		return b2f(l <= r), l <= r
	}
	return 0, false
}

// ApplyScalar is exported for the proxy post-processing.
func ApplyScalar(op string, l, r float64) (float64, bool) { return applyScalar(op, l, r) }

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func planExpr(e logql.Expr, o *Options) (*plan, error) {
	switch x := e.(type) {
	case *logql.RangeAgg:
		return planRange(x, o)
	case *logql.VectorAgg:
		return planVector(x, o)
	case *logql.BinOp:
		return planBinOp(x, o)
	case *logql.LogExpr:
		return nil, fmt.Errorf("a log query cannot be used where a metric query is expected")
	}
	return nil, fmt.Errorf("unsupported expression %T", e)
}

func planRange(r *logql.RangeAgg, o *Options) (*plan, error) {
	var b builder
	if err := b.logExpr(r.Log, o); err != nil {
		return nil, err
	}
	p := &plan{rng: r.Range, offset: r.Offset, scale: 1, renames: map[string]string{}}

	var arg string
	if r.Unwrap != nil {
		arg = fieldName(o.Field(r.Unwrap.Label))
		for _, st := range r.Post {
			lf, ok := st.(*logql.LabelFilterStage)
			if !ok {
				return nil, fmt.Errorf("only label filters are allowed after unwrap")
			}
			// filters after unwrap never move before the unwrap point
			if f := labelFilter(lf.Filter, o, true); f != "" {
				b.pipes = append(b.pipes, "filter "+f)
			}
		}
		if r.Unwrap.Conv == "duration" || r.Unwrap.Conv == "duration_seconds" {
			// VictoriaLogs parses "1.5s" into nanoseconds
			p.scale = 1e-9
		}
	}
	needUnwrap := func() error {
		if r.Unwrap == nil {
			return fmt.Errorf("%s requires | unwrap", r.Op)
		}
		return nil
	}
	// LogQL: grouping is only allowed on unwrapped range aggregations, except
	// sum_over_time, absent_over_time, rate and rate_counter.
	if r.Grouping != nil {
		switch {
		case r.Unwrap == nil, r.Op == "sum_over_time", r.Op == "absent_over_time", r.Op == "rate", r.Op == "rate_counter":
			return nil, fmt.Errorf("grouping not allowed for %s aggregation", r.Op)
		}
	}
	var fn string
	switch r.Op {
	case "absent_over_time":
		labels := map[string]string{}
		for _, m := range r.Log.Matchers {
			if m.Op == logql.MatchEq {
				labels[m.Name] = m.Value
			}
		}
		p.base = b.String()
		p.levels = []statsLevel{{fn: "count()"}}
		p.post = append(p.post, PostOp{Kind: PostAbsent, Labels: labels})
		p.slide = SlideSum
		return p, nil
	case "count_over_time":
		fn, p.additive, p.slide = "count()", true, SlideSum
		p.scale = 1
	case "rate":
		if r.Unwrap != nil {
			fn = "sum(" + arg + ")"
		} else {
			fn = "count()"
			p.scale = 1
		}
		p.additive, p.window, p.slide = true, true, SlideSum
	case "bytes_over_time":
		fn, p.additive, p.slide = "sum_len(_msg)", true, SlideSum
		p.scale = 1
	case "bytes_rate":
		fn, p.additive, p.window, p.slide = "sum_len(_msg)", true, true, SlideSum
		p.scale = 1
	case "sum_over_time":
		if err := needUnwrap(); err != nil {
			return nil, err
		}
		fn, p.additive, p.slide = "sum("+arg+")", true, SlideSum
	case "avg_over_time":
		if err := needUnwrap(); err != nil {
			return nil, err
		}
		fn = "avg(" + arg + ")"
	case "max_over_time":
		if err := needUnwrap(); err != nil {
			return nil, err
		}
		fn, p.minmax, p.slide = "max("+arg+")", "max", SlideMax
	case "min_over_time":
		if err := needUnwrap(); err != nil {
			return nil, err
		}
		fn, p.minmax, p.slide = "min("+arg+")", "min", SlideMin
	case "stddev_over_time", "stdvar_over_time":
		if err := needUnwrap(); err != nil {
			return nil, err
		}
		fn = "stddev(" + arg + ")"
	case "quantile_over_time":
		if err := needUnwrap(); err != nil {
			return nil, err
		}
		fn = "quantile(" + strconv.FormatFloat(r.Param, 'g', -1, 64) + ", " + arg + ")"
	default:
		return nil, fmt.Errorf("%s is not supported", r.Op)
	}

	lvl := statsLevel{fn: fn}
	switch {
	case r.Grouping == nil, r.Grouping.Without && len(r.Grouping.Labels) == 0:
		lvl.by = []string{"_stream"}
		p.stream = true
	case r.Grouping.Without:
		return nil, fmt.Errorf("without (...) grouping is not supported")
	default:
		lvl.by = p.groupBy(r.Grouping.Labels, o)
		p.labels = lvl.by
	}
	p.base = b.String()
	p.levels = []statsLevel{lvl}
	if r.Op == "stdvar_over_time" {
		p.flushScale()
		p.post = append(p.post, PostOp{Kind: PostSquare})
		p.slide = SlideNone
	}
	return p, nil
}

// groupBy maps Loki grouping labels to VL fields and records renames.
func (p *plan) groupBy(labels []string, o *Options) []string {
	out := make([]string, 0, len(labels))
	for _, l := range labels {
		f := o.Field(l)
		if f != l {
			p.renames[f] = l
		}
		if l == DetectedLevel && o.MultiLevel() {
			p.coalesce = true
		}
		out = append(out, f)
	}
	return out
}

// flushScale materializes pending scaling into post ops. It must run before
// any non-homogeneous operation.
func (p *plan) flushScale() {
	if p.scale != 1 {
		p.post = append(p.post, PostOp{Kind: PostScale, F: p.scale})
		p.scale = 1
	}
	if p.window {
		p.post = append(p.post, PostOp{Kind: PostScaleWindow})
		p.window = false
	}
}

var vectorStatsFn = map[string]string{
	"sum": "sum(v)", "avg": "avg(v)", "min": "min(v)", "max": "max(v)",
	"count": "count()", "stddev": "stddev(v)", "stdvar": "stddev(v)",
}

func planVector(v *logql.VectorAgg, o *Options) (*plan, error) {
	p, err := planExpr(v.Inner, o)
	if err != nil {
		return nil, err
	}
	switch v.Op {
	case "topk", "bottomk":
		k := int(v.Param)
		if k <= 0 {
			return nil, fmt.Errorf("%s: k must be positive", v.Op)
		}
		op := PostOp{Kind: PostTopK, K: k, Bottom: v.Op == "bottomk"}
		if v.Grouping != nil {
			if v.Grouping.Without {
				return nil, fmt.Errorf("%s without (...) is not supported", v.Op)
			}
			op.By = p.groupBy(v.Grouping.Labels, o)
		}
		p.post = append(p.post, op)
		return p, nil
	case "sort", "sort_desc":
		p.post = append(p.post, PostOp{Kind: PostSort, Desc: v.Op == "sort_desc"})
		return p, nil
	}

	if len(p.post) > 0 {
		return nil, fmt.Errorf("%s over a post-processed expression is not supported", v.Op)
	}
	var by []string
	if v.Grouping != nil {
		if v.Grouping.Without {
			if len(v.Grouping.Labels) > 0 {
				return nil, fmt.Errorf("%s without (...) is not supported", v.Op)
			}
			return p, nil // without () keeps all labels: identity
		}
		by = p.groupBy(v.Grouping.Labels, o)
	}

	single := len(p.levels) == 1
	collapse := single && ((v.Op == "sum" && p.additive) || (p.minmax != "" && v.Op == p.minmax))
	if collapse {
		p.levels[0].by = by
		p.labels, p.stream = by, false
		return p, nil
	}

	fn, ok := vectorStatsFn[v.Op]
	if !ok {
		return nil, fmt.Errorf("aggregation %s is not supported", v.Op)
	}
	// Lower levels must carry the grouping labels up to this level.
	extra := by
	if !p.stream {
		extra = intersect(by, p.labels)
	}
	for i := range p.levels {
		p.levels[i].by = union(p.levels[i].by, extra)
	}
	p.levels = append(p.levels, statsLevel{by: by, fn: fn})
	p.labels, p.stream = by, false
	p.additive, p.minmax, p.slide = false, "", SlideNone
	switch v.Op {
	case "count":
		p.scale, p.window = 1, false // the number of series does not depend on scaling
	case "stdvar":
		p.flushScale()
		p.post = append(p.post, PostOp{Kind: PostSquare})
	}
	return p, nil
}

func planBinOp(b *logql.BinOp, o *Options) (*plan, error) {
	lv, lconst := constValue(b.L)
	rv, rconst := constValue(b.R)
	if lconst == rconst {
		return nil, fmt.Errorf("binary operations between two metric queries are not supported")
	}
	var p *plan
	var err error
	var f float64
	if lconst {
		p, err = planExpr(b.R, o)
		f = lv
	} else {
		p, err = planExpr(b.L, o)
		f = rv
	}
	if err != nil {
		return nil, err
	}
	p.flushScale()
	p.slide = SlideNone
	switch b.Op {
	case "+", "-", "*", "/", "%", "^":
		p.post = append(p.post, PostOp{Kind: PostScalarOp, Op: b.Op, F: f, ScalarLeft: lconst})
	case "==", "!=", ">", ">=", "<", "<=":
		p.post = append(p.post, PostOp{Kind: PostCompare, Op: b.Op, F: f, ScalarLeft: lconst, Bool: b.Bool})
	default:
		return nil, fmt.Errorf("operator %q is not supported", b.Op)
	}
	return p, nil
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		for _, y := range b {
			if x == y {
				out = append(out, x)
				break
			}
		}
	}
	return out
}

func union(a, b []string) []string {
	out := append([]string(nil), a...)
	for _, x := range b {
		found := false
		for _, y := range out {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			out = append(out, x)
		}
	}
	return out
}

// MetricPlan is the evaluation tree of a metric query. Leaves are evaluated
// by VictoriaLogs; binary operations between vectors, vector() and scalars
// are evaluated by the proxy with Prometheus/LogQL semantics.
type MetricPlan struct {
	Query  *MetricQuery // leaf
	Op     string       // binary operation between L and R
	Bool   bool
	L, R   *MetricPlan
	Vector *float64 // vector(n): one series without labels
	Scalar *float64 // scalar literal (instant queries return resultType "scalar")
	Post   []PostOp // applied after evaluating a binary node
}

// Plan builds the evaluation tree of a metric expression.
func Plan(e logql.Expr, o *Options) (*MetricPlan, error) {
	if v, ok := constValue(e); ok {
		if hasVectorLit(e) {
			return &MetricPlan{Vector: &v}, nil
		}
		return &MetricPlan{Scalar: &v}, nil
	}
	switch x := e.(type) {
	case *logql.BinOp:
		lScalar, rScalar := isScalarTree(x.L), isScalarTree(x.R)
		if lScalar || rScalar {
			other, f := x.R, 0.0
			if lScalar {
				f, _ = constValue(x.L)
			} else {
				other = x.L
				f, _ = constValue(x.R)
			}
			if !hasVectorBinOp(other) {
				return leaf(e, o)
			}
			p, err := Plan(other, o)
			if err != nil {
				return nil, err
			}
			switch x.Op {
			case "+", "-", "*", "/", "%", "^":
				p.Post = append(p.Post, PostOp{Kind: PostScalarOp, Op: x.Op, F: f, ScalarLeft: lScalar})
			default:
				p.Post = append(p.Post, PostOp{Kind: PostCompare, Op: x.Op, F: f, ScalarLeft: lScalar, Bool: x.Bool})
			}
			return p, nil
		}
		switch x.Op {
		case "and", "or", "unless", "+", "-", "*", "/", "%", "^", "==", "!=", ">", ">=", "<", "<=":
		default:
			return nil, fmt.Errorf("operator %q is not supported", x.Op)
		}
		l, err := Plan(x.L, o)
		if err != nil {
			return nil, err
		}
		r, err := Plan(x.R, o)
		if err != nil {
			return nil, err
		}
		return &MetricPlan{Op: x.Op, Bool: x.Bool, L: l, R: r}, nil
	case *logql.VectorAgg:
		if hasVectorBinOp(x.Inner) {
			p, err := Plan(x.Inner, o)
			if err != nil {
				return nil, err
			}
			switch x.Op {
			case "topk", "bottomk":
				if x.Grouping != nil {
					return nil, fmt.Errorf("%s by (...) over a binary operation is not supported", x.Op)
				}
				p.Post = append(p.Post, PostOp{Kind: PostTopK, K: int(x.Param), Bottom: x.Op == "bottomk"})
				return p, nil
			case "sort", "sort_desc":
				p.Post = append(p.Post, PostOp{Kind: PostSort, Desc: x.Op == "sort_desc"})
				return p, nil
			}
			return nil, fmt.Errorf("%s over a binary operation between vectors is not supported", x.Op)
		}
	}
	return leaf(e, o)
}

func leaf(e logql.Expr, o *Options) (*MetricPlan, error) {
	q, err := Metric(e, o)
	if err != nil {
		return nil, err
	}
	if q.Const != nil {
		return &MetricPlan{Scalar: q.Const}, nil
	}
	return &MetricPlan{Query: q}, nil
}

func isScalarTree(e logql.Expr) bool {
	switch x := e.(type) {
	case *logql.NumberLit:
		return true
	case *logql.BinOp:
		return isScalarTree(x.L) && isScalarTree(x.R)
	}
	return false
}

func hasVectorLit(e logql.Expr) bool {
	switch x := e.(type) {
	case *logql.VectorLit:
		return true
	case *logql.BinOp:
		return hasVectorLit(x.L) || hasVectorLit(x.R)
	}
	return false
}

// hasVectorBinOp reports whether e contains a binary operation between two
// vectors (or a vector() literal), which VictoriaLogs cannot evaluate.
func hasVectorBinOp(e logql.Expr) bool {
	switch x := e.(type) {
	case *logql.BinOp:
		if !isScalarTree(x.L) && !isScalarTree(x.R) {
			return true
		}
		return hasVectorBinOp(x.L) || hasVectorBinOp(x.R)
	case *logql.VectorAgg:
		return hasVectorBinOp(x.Inner)
	case *logql.VectorLit:
		return true
	}
	return false
}
