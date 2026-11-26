package proxy

import (
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Justereseau/loki-vl-proxy/internal/logql"
	"github.com/Justereseau/loki-vl-proxy/internal/translate"
)

// Request handling follows the Loki HTTP API reference:
// https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-logs-within-a-range-of-time
// https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-logs-at-a-single-point-in-time

func categorize(r *http.Request) bool {
	return strings.Contains(r.Header.Get("X-Loki-Response-Encoding-Flags"), "categorize-labels")
}

func (s *Server) parseQuery(r *http.Request) (logql.Expr, error) {
	q := r.Form.Get("query")
	if strings.TrimSpace(q) == "" {
		return nil, httpError(http.StatusBadRequest, "query parameter is required")
	}
	e, err := logql.Parse(q)
	if err != nil {
		return nil, badRequest(err)
	}
	return e, nil
}

// handleQueryRange serves /loki/api/v1/query_range.
func (s *Server) handleQueryRange(w http.ResponseWriter, r *http.Request) error {
	began := time.Now()
	if err := parseForm(r); err != nil {
		return err
	}
	tenant, err := s.tenant(r)
	if err != nil {
		return err
	}
	expr, err := s.parseQuery(r)
	if err != nil {
		return err
	}
	start, end, err := timeRange(r)
	if err != nil {
		return badRequest(err)
	}
	opts := s.translateOptions(r, tenant)

	if le, ok := expr.(*logql.LogExpr); ok {
		lq, err := s.logQuery(r, le, opts, start, end)
		if err != nil {
			return err
		}
		return s.streamLogs(w, r, tenant, lq)
	}

	step, err := queryStep(r, start, end)
	if err != nil {
		return err
	}
	plan, err := translate.Plan(expr, opts)
	if err != nil {
		return badRequest(err)
	}
	ev := &evalCtx{start: start, end: end, step: step}
	series, err := s.evalPlan(r, tenant, plan, ev)
	if err != nil {
		return err
	}
	bp := getBuf()
	defer putBuf(bp)
	*bp = appendMatrix(*bp, series, time.Since(began))
	writeJSON(w, *bp)
	return nil
}

// handleQuery serves /loki/api/v1/query (instant queries).
func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) error {
	began := time.Now()
	if err := parseForm(r); err != nil {
		return err
	}
	tenant, err := s.tenant(r)
	if err != nil {
		return err
	}
	expr, err := s.parseQuery(r)
	if err != nil {
		return err
	}
	ts, err := parseLokiTime(r.Form.Get("time"), time.Now())
	if err != nil {
		return badRequest(err)
	}
	if _, ok := expr.(*logql.LogExpr); ok {
		// "Instant queries are only used for metric type LogQL queries and will
		// return a 400 (Bad Request) in case a log type query is provided."
		return httpError(http.StatusBadRequest, "log queries are not supported as an instant query type, please change your query to a range query type")
	}
	plan, err := translate.Plan(expr, s.translateOptions(r, tenant))
	if err != nil {
		return badRequest(err)
	}
	ev := &evalCtx{instant: true, ts: ts}
	series, err := s.evalPlan(r, tenant, plan, ev)
	if err != nil {
		return err
	}
	bp := getBuf()
	defer putBuf(bp)
	if plan.Scalar != nil {
		*bp = appendScalar(*bp, ts.UnixMilli(), *plan.Scalar, time.Since(began))
	} else {
		*bp = appendVector(*bp, series, time.Since(began))
	}
	writeJSON(w, *bp)
	return nil
}

func (s *Server) logQuery(r *http.Request, le *logql.LogExpr, opts *translate.Options, start, end time.Time) (*logQuery, error) {
	logsql, meta, err := translate.LogWithMeta(le, opts)
	if err != nil {
		return nil, badRequest(err)
	}
	limit, err := s.parseLimit(r.Form.Get("limit"))
	if err != nil {
		return nil, err
	}
	forward, err := parseDirection(r.Form.Get("direction"))
	if err != nil {
		return nil, err
	}
	var interval time.Duration
	if v := r.Form.Get("interval"); v != "" {
		if interval, err = parseLokiDuration(v); err != nil || interval < 0 {
			return nil, httpError(http.StatusBadRequest, "invalid interval %q", v)
		}
	}
	return &logQuery{
		logsql:     logsql,
		start:      start,
		end:        end,
		limit:      limit,
		forward:    forward,
		interval:   interval,
		categorize: categorize(r),
		fromFields: meta.LabelsFromFields,
	}, nil
}

// parseLimit implements Loki's `limit`: default 100, must be positive and not
// above max_entries_limit_per_query.
func (s *Server) parseLimit(v string) (int, error) {
	if v == "" {
		return 100, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, httpError(http.StatusBadRequest, "invalid limit %q", v)
	}
	if n <= 0 {
		return 0, httpError(http.StatusBadRequest, "limit must be a positive value")
	}
	if n > s.cfg.MaxLimit {
		return 0, httpError(http.StatusBadRequest, "max entries limit per query exceeded, limit > max_entries_limit_per_query (%d > %d)", n, s.cfg.MaxLimit)
	}
	return n, nil
}

func parseDirection(v string) (forward bool, err error) {
	switch strings.ToLower(v) {
	case "", "backward":
		return false, nil
	case "forward":
		return true, nil
	}
	return false, httpError(http.StatusBadRequest, "invalid direction %q: supported values are forward and backward", v)
}

// queryStep implements Loki's `step`: a duration or a float number of
// seconds, defaulting to max(ceil(range/250s), 1s).
func queryStep(r *http.Request, start, end time.Time) (time.Duration, error) {
	if v := r.Form.Get("step"); v != "" {
		d, err := parseLokiDuration(v)
		if err != nil || d <= 0 {
			return 0, httpError(http.StatusBadRequest, "zero or negative query resolution step widths are not accepted. Try a positive integer")
		}
		if end.Sub(start)/d > 11000 {
			return 0, httpError(http.StatusBadRequest, "exceeded maximum resolution of 11,000 points per timeseries. Try increasing the value of the step parameter")
		}
		return d, nil
	}
	sec := math.Ceil(end.Sub(start).Seconds() / 250)
	return time.Duration(max(sec, 1)) * time.Second, nil
}

// evalCtx is the evaluation context of a metric query.
type evalCtx struct {
	instant    bool
	ts         time.Time // instant queries
	start, end time.Time // range queries
	step       time.Duration
}

// grid is the set of Loki evaluation timestamps (milliseconds).
type grid struct {
	instant          bool
	ts               int64
	start, end, step int64
}

func (ev *evalCtx) grid() grid {
	if ev.instant {
		return grid{instant: true, ts: ev.ts.UnixMilli()}
	}
	return grid{start: ev.start.UnixMilli(), end: ev.end.UnixMilli(), step: ev.step.Milliseconds()}
}

// evalPlan evaluates a metric plan; both sides of a binary operation run concurrently.
func (s *Server) evalPlan(r *http.Request, tenant tenantID, p *translate.MetricPlan, ev *evalCtx) ([]*mseries, error) {
	var (
		series []*mseries
		err    error
	)
	switch {
	case p.Query != nil:
		if ev.instant {
			series, err = s.evalInstant(r, tenant, p.Query, ev.ts)
		} else {
			series, err = s.evalRange(r, tenant, p.Query, ev.start, ev.end, ev.step)
		}
		if err != nil {
			return nil, err
		}
	case p.Vector != nil, p.Scalar != nil:
		v := p.Vector
		if v == nil {
			v = p.Scalar
		}
		if ev.instant {
			series = []*mseries{{pts: []point{{t: ev.ts.UnixMilli(), v: *v}}}}
		} else {
			series = constMatrix(*v, ev.start, ev.end, ev.step)
		}
	default:
		var l, rr []*mseries
		var lerr error
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, lerr = s.evalPlan(r, tenant, p.L, ev)
		}()
		rr, err = s.evalPlan(r, tenant, p.R, ev)
		wg.Wait()
		if lerr != nil {
			return nil, lerr
		}
		if err != nil {
			return nil, err
		}
		series = binaryOp(p.Op, p.Bool, l, rr)
	}
	if len(p.Post) > 0 {
		series = applyPost(series, p.Post, 0, ev.grid())
	}
	return series, nil
}

// evalRange evaluates a VictoriaLogs-backed query over [start, end].
//
// /select/logsql/stats_query_range returns, at T, the stats of logs in
// [T, T+step); its docs advise moving every timestamp one step forward to get
// Prometheus/Loki semantics (value at t covers the preceding window). The
// `offset` argument aligns buckets on Loki's start + k*step evaluation grid.
// When range > step, consecutive buckets are combined into sliding windows
// for aggregations that allow it; otherwise the window is the step.
func (s *Server) evalRange(r *http.Request, tenant tenantID, mq *translate.MetricQuery, start, end time.Time, step time.Duration) ([]*mseries, error) {
	window := mq.Range
	if window <= 0 {
		window = step
	}
	slide := mq.Slide != translate.SlideNone && window > step && window%step == 0
	eff := step
	if slide {
		eff = window
	}
	qStart := start.Add(-eff - mq.Offset)
	align := (step - time.Duration(qStart.UnixNano())%step) % step
	ctx, cancel := s.ctx(r)
	defer cancel()
	form := url.Values{
		"query": {mq.LogsQL},
		"start": {vlTime(qStart)},
		"end":   {vlTime(end.Add(-mq.Offset))},
		"step":  {vlDuration(step)},
	}
	if align != 0 {
		form.Set("offset", vlDuration(align))
	}
	var resp promResponse
	if err := s.getJSON(ctx, r, tenant, "/select/logsql/stats_query_range", form, &resp); err != nil {
		return nil, err
	}
	series := s.convertSeries(tenant, &resp, mq)
	shift := (step + mq.Offset).Milliseconds()
	stepMs := step.Milliseconds()
	startMs, endMs := start.UnixMilli(), end.UnixMilli()
	for _, sr := range series {
		for i := range sr.pts {
			// snap to the exact start + k*step grid (VictoriaLogs reports
			// fractional-second bucket timestamps)
			t := sr.pts[i].t + shift - startMs
			sr.pts[i].t = startMs + int64(math.Round(float64(t)/float64(stepMs)))*stepMs
		}
		if slide {
			sr.pts = slideWindow(sr.pts, mq.Slide, stepMs, window.Milliseconds())
		}
		pts := sr.pts[:0]
		for _, p := range sr.pts {
			if p.t >= startMs && p.t <= endMs {
				pts = append(pts, p)
			}
		}
		sr.pts = pts
	}
	g := grid{start: startMs, end: endMs, step: stepMs}
	return applyPost(series, mq.Post, eff.Seconds(), g), nil
}

// evalInstant evaluates a VictoriaLogs-backed query at ts over its range,
// using /select/logsql/stats_query with an explicit `time`.
func (s *Server) evalInstant(r *http.Request, tenant tenantID, mq *translate.MetricQuery, ts time.Time) ([]*mseries, error) {
	window := mq.Range
	if window <= 0 {
		window = 5 * time.Minute
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	evalAt := ts.Add(-mq.Offset)
	form := url.Values{
		"query": {mq.LogsQL},
		"time":  {vlTime(evalAt)},
		"start": {vlTime(evalAt.Add(-window))},
		"end":   {vlTime(evalAt)},
	}
	var resp promResponse
	if err := s.getJSON(ctx, r, tenant, "/select/logsql/stats_query", form, &resp); err != nil {
		return nil, err
	}
	series := s.convertSeries(tenant, &resp, mq)
	for _, sr := range series {
		for i := range sr.pts {
			sr.pts[i].t = ts.UnixMilli()
		}
	}
	return applyPost(series, mq.Post, window.Seconds(), grid{instant: true, ts: ts.UnixMilli()}), nil
}

func constMatrix(v float64, start, end time.Time, step time.Duration) []*mseries {
	sr := &mseries{}
	for t := start; !t.After(end); t = t.Add(step) {
		sr.pts = append(sr.pts, point{t: t.UnixMilli(), v: v})
	}
	return []*mseries{sr}
}
