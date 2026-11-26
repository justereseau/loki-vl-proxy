package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Justereseau/loki-vl-proxy/internal/logql"
	"github.com/Justereseau/loki-vl-proxy/internal/lokijson"
	"github.com/Justereseau/loki-vl-proxy/internal/translate"
)

// selectorQuery translates the optional `query` parameter (a stream selector,
// possibly with a pipeline) used by metadata endpoints.
func (s *Server) selectorQuery(r *http.Request, tenant tenantID, q string) (string, error) {
	out, err := translate.LabelsSelector(q, s.translateOptions(r, tenant))
	if err != nil {
		return "", badRequest(err)
	}
	return out, nil
}

func timeForm(start, end time.Time) url.Values {
	return url.Values{"start": {vlTime(start)}, "end": {vlTime(end)}}
}

func appendStringArray(dst []byte, vals []string) []byte {
	dst = append(dst, '[')
	for i, v := range vals {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = lokijson.AppendString(dst, v)
	}
	return append(dst, ']')
}

func writeDataStrings(w http.ResponseWriter, vals []string) {
	bp := getBuf()
	defer putBuf(bp)
	b := append(*bp, `{"status":"success","data":`...)
	b = appendStringArray(b, vals)
	b = append(b, '}')
	*bp = b
	writeJSON(w, b)
}

// handleLabels serves /labels: VictoriaLogs stream fields are Loki labels.
func (s *Server) handleLabels(w http.ResponseWriter, r *http.Request) error {
	if err := parseForm(r); err != nil {
		return err
	}
	tenant, err := s.tenant(r)
	if err != nil {
		return err
	}
	start, end, err := timeRangeDefault(r, labelsLookback)
	if err != nil {
		return badRequest(err)
	}
	q, err := s.selectorQuery(r, tenant, r.Form.Get("query"))
	if err != nil {
		return err
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	form := timeForm(start, end)
	form.Set("query", q)
	form.Set("ignore_pipes", "1")
	var resp valuesResponse
	if err := s.getJSON(ctx, r, tenant, "/select/logsql/stream_field_names", form, &resp); err != nil {
		return err
	}
	names := make([]string, 0, len(resp.Values))
	raw := make([]string, 0, len(resp.Values))
	seen := map[string]bool{}
	for _, v := range resp.Values {
		raw = append(raw, v.Value)
		n := lokijson.SanitizeLabelName(v.Value)
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	s.names.learn(tenant, raw...)
	sort.Strings(names)
	writeDataStrings(w, names)
	return nil
}

// handleLabelValues serves /label/{name}/values. Stream fields are looked up
// first; other fields (e.g. detected_level) fall back to field_values.
func (s *Server) handleLabelValues(w http.ResponseWriter, r *http.Request) error {
	if err := parseForm(r); err != nil {
		return err
	}
	tenant, err := s.tenant(r)
	if err != nil {
		return err
	}
	start, end, err := timeRangeDefault(r, labelsLookback)
	if err != nil {
		return badRequest(err)
	}
	vals, err := s.labelValues(r, tenant, r.PathValue("name"), r.Form.Get("query"), start, end, true, 0)
	if err != nil {
		return err
	}
	writeDataStrings(w, vals)
	return nil
}

func (s *Server) labelValues(r *http.Request, tenant tenantID, name, selector string, start, end time.Time, streamFirst bool, limit int) ([]string, error) {
	opts := s.translateOptions(r, tenant)
	q, err := s.selectorQuery(r, tenant, selector)
	if err != nil {
		return nil, err
	}
	field := opts.Field(name)
	if name == translate.DetectedLevel && opts.MultiLevel() {
		q += " | " + opts.LevelCoalescePipe()
		streamFirst = false
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	form := timeForm(start, end)
	form.Set("query", q)
	form.Set("field", field)
	if limit <= 0 {
		limit = 10000
	}
	form.Set("limit", strconv.Itoa(limit))
	var resp valuesResponse
	if streamFirst && name != translate.DetectedLevel {
		f2 := cloneForm(form)
		f2.Set("ignore_pipes", "1")
		if err := s.getJSON(ctx, r, tenant, "/select/logsql/stream_field_values", f2, &resp); err != nil {
			return nil, err
		}
	}
	if len(resp.Values) == 0 {
		if err := s.getJSON(ctx, r, tenant, "/select/logsql/field_values", form, &resp); err != nil {
			return nil, err
		}
	}
	vals := make([]string, 0, len(resp.Values))
	seen := map[string]bool{}
	for _, v := range resp.Values {
		val := v.Value
		if val == "" {
			continue
		}
		if name == translate.DetectedLevel && s.cfg.NormalizeLevels {
			val = translate.NormalizeLevel(val)
		}
		if !seen[val] {
			seen[val] = true
			vals = append(vals, val)
		}
	}
	sort.Strings(vals)
	return vals, nil
}

func cloneForm(f url.Values) url.Values {
	out := make(url.Values, len(f))
	for k, v := range f {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// streams fetches stream label sets matching a LogsQL query.
func (s *Server) streams(ctx context.Context, r *http.Request, tenant tenantID, q string, start, end time.Time, limit int) ([][]label, error) {
	form := timeForm(start, end)
	form.Set("query", q)
	form.Set("ignore_pipes", "1")
	if limit > 0 {
		form.Set("limit", strconv.Itoa(limit))
	}
	var resp valuesResponse
	if err := s.getJSON(ctx, r, tenant, "/select/logsql/streams", form, &resp); err != nil {
		return nil, err
	}
	out := make([][]label, 0, len(resp.Values))
	var learned []string
	for _, v := range resp.Values {
		var lbls []label
		lokijson.ParseStreamLabels([]byte(v.Value), func(name, value []byte) {
			if len(value) > 0 {
				learned = append(learned, string(name))
				lbls = append(lbls, label{lokijson.SanitizeLabelName(string(name)), string(value)})
			}
		})
		out = append(out, lbls)
	}
	s.names.learn(tenant, learned...)
	return out, nil
}

// handleSeries serves /series?match[]=...
func (s *Server) handleSeries(w http.ResponseWriter, r *http.Request) error {
	if err := parseForm(r); err != nil {
		return err
	}
	tenant, err := s.tenant(r)
	if err != nil {
		return err
	}
	start, end, err := timeRange(r)
	if err != nil {
		return badRequest(err)
	}
	matches := r.Form["match[]"]
	if len(matches) == 0 {
		matches = r.Form["match"]
	}
	if len(matches) == 0 {
		return httpError(http.StatusBadRequest, "at least one match[] argument must be provided")
	}
	var parts []string
	for _, m := range matches {
		q, err := s.selectorQuery(r, tenant, m)
		if err != nil {
			return err
		}
		parts = append(parts, "("+q+")")
	}
	q := "*"
	if len(parts) > 0 {
		q = strings.Join(parts, " or ")
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	sets, err := s.streams(ctx, r, tenant, q, start, end, 0)
	if err != nil {
		return err
	}
	bp := getBuf()
	defer putBuf(bp)
	b := append(*bp, `{"status":"success","data":[`...)
	for i, l := range sets {
		if i > 0 {
			b = append(b, ',')
		}
		sort.Slice(l, func(a, c int) bool { return l[a].name < l[c].name })
		b = appendLabels(b, l)
	}
	b = append(b, ']', '}')
	*bp = b
	writeJSON(w, b)
	return nil
}

// handleIndexStats serves /index/stats (used by Grafana for query size hints).
func (s *Server) handleIndexStats(w http.ResponseWriter, r *http.Request) error {
	if err := parseForm(r); err != nil {
		return err
	}
	tenant, err := s.tenant(r)
	if err != nil {
		return err
	}
	start, end, err := timeRange(r)
	if err != nil {
		return badRequest(err)
	}
	q, err := s.selectorQuery(r, tenant, r.Form.Get("query"))
	if err != nil {
		return err
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	form := timeForm(start, end)
	stats := " | stats count() as entries, count_uniq(_stream_id) as streams"
	if s.cfg.IndexStatsBytes {
		stats += ", sum_len(_msg) as bytes"
	}
	form.Set("query", q+stats)
	var resp promResponse
	if err := s.getJSON(ctx, r, tenant, "/select/logsql/stats_query", form, &resp); err != nil {
		return err
	}
	var entries, streams, bytes float64
	for _, res := range resp.Data.Result {
		if res.Value == nil {
			continue
		}
		switch res.Metric["__name__"] {
		case "entries":
			entries = res.Value.v
		case "streams":
			streams = res.Value.v
		case "bytes":
			bytes = res.Value.v
		}
	}
	b := []byte(`{"streams":`)
	b = strconv.AppendInt(b, int64(streams), 10)
	b = append(b, `,"chunks":`...)
	b = strconv.AppendInt(b, int64(streams), 10)
	b = append(b, `,"entries":`...)
	b = strconv.AppendInt(b, int64(entries), 10)
	b = append(b, `,"bytes":`...)
	b = strconv.AppendInt(b, int64(bytes), 10)
	b = append(b, '}')
	writeJSON(w, b)
	return nil
}

// volumeQuery builds the metric query behind /index/volume[_range]
// (https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-log-volume).
// Series aggregate on targetLabels, or on the labels of the selector matchers;
// aggregateBy=labels returns one series per label with an empty value.
// Volumes are counted in log entries, not bytes.
func (s *Server) volumeQuery(r *http.Request, tenant tenantID) (*translate.MetricQuery, error) {
	opts := s.translateOptions(r, tenant)
	sel := strings.TrimSpace(r.Form.Get("query"))
	var le *logql.LogExpr
	if sel != "" && sel != "{}" {
		var err error
		if le, err = logql.ParseLog(sel); err != nil {
			return nil, badRequest(err)
		}
	} else {
		le = &logql.LogExpr{}
	}
	q, err := translate.Log(le, opts)
	if err != nil {
		return nil, badRequest(err)
	}
	var target []string
	if t := r.Form.Get("targetLabels"); t != "" {
		for _, l := range strings.Split(t, ",") {
			if l = strings.TrimSpace(l); l != "" {
				target = append(target, l)
			}
		}
	} else {
		for _, m := range le.Matchers {
			if m.Name != "__stream_shard__" {
				target = append(target, m.Name)
			}
		}
	}
	mq := &translate.MetricQuery{Renames: map[string]string{}, Slide: translate.SlideSum}
	switch r.Form.Get("aggregateBy") {
	case "", "series":
	case "labels":
		if len(target) == 0 {
			return nil, httpError(http.StatusBadRequest, "aggregateBy=labels needs targetLabels or label matchers")
		}
		parts := make([]string, 0, len(target))
		for _, t := range target {
			f := opts.Field(t)
			alias := "l" + strconv.Itoa(len(parts))
			mq.Renames[alias] = t
			parts = append(parts, "count() if ("+quoteField(f)+":*) as "+alias)
		}
		if contains(target, translate.DetectedLevel) && opts.MultiLevel() {
			q += " | " + opts.LevelCoalescePipe()
		}
		mq.LogsQL = q + " | stats " + strings.Join(parts, ", ")
		mq.NameAsLabel = true
		return mq, nil
	default:
		return nil, httpError(http.StatusBadRequest, "invalid aggregateBy %q: supported values are series and labels", r.Form.Get("aggregateBy"))
	}
	var by []string
	coalesce := false
	for _, t := range target {
		f := opts.Field(t)
		if f != t {
			mq.Renames[f] = t
		}
		if t == translate.DetectedLevel && opts.MultiLevel() {
			coalesce = true
		}
		by = append(by, quoteField(f))
	}
	if coalesce {
		q += " | " + opts.LevelCoalescePipe()
	}
	if len(by) == 0 {
		mq.LogsQL = q + " | stats by (_stream) count() as v"
		mq.ExpandStream = true
	} else {
		mq.LogsQL = q + " | stats by (" + strings.Join(by, ", ") + ") count() as v"
	}
	return mq, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// volumeLimit parses `limit` (default 100) and keeps the biggest series.
func volumeLimit(r *http.Request, series []*mseries) ([]*mseries, error) {
	limit := 100
	if v := r.Form.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, httpError(http.StatusBadRequest, "invalid limit %q", v)
		}
		limit = n
	}
	total := func(sr *mseries) (t float64) {
		for _, p := range sr.pts {
			t += p.v
		}
		return
	}
	sort.SliceStable(series, func(a, b int) bool { return total(series[a]) > total(series[b]) })
	if len(series) > limit {
		series = series[:limit]
	}
	return series, nil
}

var plainField = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

func quoteField(f string) string {
	if plainField.MatchString(f) {
		return f
	}
	return strconv.Quote(f)
}

func (s *Server) handleVolume(w http.ResponseWriter, r *http.Request) error {
	if err := parseForm(r); err != nil {
		return err
	}
	tenant, err := s.tenant(r)
	if err != nil {
		return err
	}
	start, end, err := timeRange(r)
	if err != nil {
		return badRequest(err)
	}
	mq, err := s.volumeQuery(r, tenant)
	if err != nil {
		return err
	}
	began := time.Now()
	mq.Range = end.Sub(start)
	series, err := s.evalInstant(r, tenant, mq, end)
	if err != nil {
		return err
	}
	if series, err = volumeLimit(r, series); err != nil {
		return err
	}
	bp := getBuf()
	defer putBuf(bp)
	*bp = appendVector(*bp, series, time.Since(began))
	writeJSON(w, *bp)
	return nil
}

func (s *Server) handleVolumeRange(w http.ResponseWriter, r *http.Request) error {
	if err := parseForm(r); err != nil {
		return err
	}
	tenant, err := s.tenant(r)
	if err != nil {
		return err
	}
	start, end, err := timeRange(r)
	if err != nil {
		return badRequest(err)
	}
	step, err := queryStep(r, start, end)
	if err != nil {
		return err
	}
	mq, err := s.volumeQuery(r, tenant)
	if err != nil {
		return err
	}
	began := time.Now()
	series, err := s.evalRange(r, tenant, mq, start, end, step)
	if err != nil {
		return err
	}
	if series, err = volumeLimit(r, series); err != nil {
		return err
	}
	bp := getBuf()
	defer putBuf(bp)
	*bp = appendMatrix(*bp, series, time.Since(began))
	writeJSON(w, *bp)
	return nil
}

// handleDetectedLabels serves /detected_labels: stream labels and their cardinality.
func (s *Server) handleDetectedLabels(w http.ResponseWriter, r *http.Request) error {
	if err := parseForm(r); err != nil {
		return err
	}
	tenant, err := s.tenant(r)
	if err != nil {
		return err
	}
	start, end, err := timeRange(r)
	if err != nil {
		return badRequest(err)
	}
	q, err := s.selectorQuery(r, tenant, r.Form.Get("query"))
	if err != nil {
		return err
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	sets, err := s.streams(ctx, r, tenant, q, start, end, 100000)
	if err != nil {
		return err
	}
	uniq := map[string]map[string]struct{}{}
	for _, set := range sets {
		for _, l := range set {
			m := uniq[l.name]
			if m == nil {
				m = map[string]struct{}{}
				uniq[l.name] = m
			}
			m[l.value] = struct{}{}
		}
	}
	type dl struct {
		Label       string `json:"label"`
		Cardinality int    `json:"cardinality"`
	}
	out := struct {
		DetectedLabels []dl `json:"detectedLabels"`
	}{DetectedLabels: []dl{}}
	for name, vals := range uniq {
		out.DetectedLabels = append(out.DetectedLabels, dl{name, len(vals)})
	}
	sort.Slice(out.DetectedLabels, func(a, b int) bool { return out.DetectedLabels[a].Label < out.DetectedLabels[b].Label })
	return writeJSONValue(w, out)
}

func writeJSONValue(w http.ResponseWriter, v any) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	return json.NewEncoder(w).Encode(v)
}

var (
	reInt      = regexp.MustCompile(`^[-+]?\d+$`)
	reFloat    = regexp.MustCompile(`^[-+]?(\d+\.\d*|\.\d+|\d+)([eE][-+]?\d+)?$`)
	reDuration = regexp.MustCompile(`^[-+]?(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$`)
	reBytes    = regexp.MustCompile(`^\d+(\.\d+)?\s?([KMGTPE]i?)?B$`)
)

// handleDetectedFieldValues serves /detected_field/{name}/values.
func (s *Server) handleDetectedFieldValues(w http.ResponseWriter, r *http.Request) error {
	if err := parseForm(r); err != nil {
		return err
	}
	tenant, err := s.tenant(r)
	if err != nil {
		return err
	}
	start, end, err := timeRange(r)
	if err != nil {
		return badRequest(err)
	}
	began := time.Now()
	limit, err := fieldLimit(r)
	if err != nil {
		return err
	}
	vals, err := s.labelValues(r, tenant, r.PathValue("name"), r.Form.Get("query"), start, end, false, limit)
	if err != nil {
		return err
	}
	if len(vals) > limit {
		vals = vals[:limit]
	}
	bp := getBuf()
	defer putBuf(bp)
	b := append(*bp, `{"values":`...)
	b = appendStringArray(b, vals)
	b = append(b, `,"limit":`...)
	b = strconv.AppendInt(b, int64(limit), 10)
	b = append(b, ',')
	b = appendStats(b, time.Since(began), len(vals))
	b = append(b, '}')
	*bp = b
	writeJSON(w, b)
	return nil
}

const maxPatterns = 50

// vlPlaceholder matches the placeholders produced by `collapse_nums prettify`.
var vlPlaceholder = regexp.MustCompile(`<(?:N|UUID|IP4|TIME|DATE|DATETIME|W)>`)

// fieldLimit parses `limit` (alias `field_limit`) for detected fields/values; default 1000.
func fieldLimit(r *http.Request) (int, error) {
	v := r.Form.Get("limit")
	if v == "" {
		v = r.Form.Get("field_limit")
	}
	if v == "" {
		return 1000, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, httpError(http.StatusBadRequest, "invalid limit %q", v)
	}
	return n, nil
}

// handlePatterns serves /patterns on a best-effort basis: log messages are
// normalized with `collapse_nums prettify`, the most frequent shapes are
// returned with their counts over time. Placeholders (<N>, <UUID>, <IP4>,
// ...) round-trip into `|>` filters, translated to pattern_match_full().
func (s *Server) handlePatterns(w http.ResponseWriter, r *http.Request) error {
	if err := parseForm(r); err != nil {
		return err
	}
	if !s.cfg.Patterns {
		writeJSON(w, []byte(`{"status":"success","data":[]}`))
		return nil
	}
	tenant, err := s.tenant(r)
	if err != nil {
		return err
	}
	start, end, err := timeRange(r)
	if err != nil {
		return badRequest(err)
	}
	step, err := queryStep(r, start, end)
	if err != nil {
		return err
	}
	q, err := s.selectorQuery(r, tenant, r.Form.Get("query"))
	if err != nil {
		return err
	}
	ctx, cancel := s.ctx(r)
	defer cancel()
	// 1. top patterns over the whole range
	form := timeForm(start, end)
	form.Set("query", q+" | collapse_nums prettify | stats by (_msg) count() as v | sort by (v desc) limit "+strconv.Itoa(maxPatterns))
	var top promResponse
	if err := s.getJSON(ctx, r, tenant, "/select/logsql/stats_query", form, &top); err != nil {
		return err
	}
	if len(top.Data.Result) == 0 {
		writeJSON(w, []byte(`{"status":"success","data":[]}`))
		return nil
	}
	pats := make([]string, 0, len(top.Data.Result))
	quoted := make([]string, 0, len(top.Data.Result))
	for _, res := range top.Data.Result {
		p := res.Metric["_msg"]
		if p == "" {
			continue
		}
		pats = append(pats, p)
		quoted = append(quoted, strconv.Quote(p))
	}
	// 2. their samples over time
	form = timeForm(start, end)
	form.Set("step", vlDuration(step))
	form.Set("query", q+" | collapse_nums prettify | filter _msg:in("+strings.Join(quoted, ",")+") | stats by (_msg) count() as v")
	var rng promResponse
	if err := s.getJSON(ctx, r, tenant, "/select/logsql/stats_query_range", form, &rng); err != nil {
		return err
	}
	// Loki patterns use the <_> placeholder; several VictoriaLogs shapes may
	// map to the same Loki pattern, so their samples are summed.
	type patSamples struct {
		pattern string
		total   float64
		samples map[int64]float64
	}
	byPattern := map[string]*patSamples{}
	var ordered []*patSamples
	stepSec := int64(step.Seconds())
	for _, res := range rng.Data.Result {
		p := res.Metric["_msg"]
		if p == "" || len(res.Values) == 0 {
			continue
		}
		p = vlPlaceholder.ReplaceAllString(p, "<_>")
		ps := byPattern[p]
		if ps == nil {
			ps = &patSamples{pattern: p, samples: map[int64]float64{}}
			byPattern[p] = ps
			ordered = append(ordered, ps)
		}
		for _, sp := range res.Values {
			// bucket [T, T+step) is reported at its end, like Loki samples
			ps.samples[sp.t/1000+stepSec] += sp.v
			ps.total += sp.v
		}
	}
	sort.SliceStable(ordered, func(a, b int) bool { return ordered[a].total > ordered[b].total })
	bp := getBuf()
	defer putBuf(bp)
	b := append(*bp, `{"status":"success","data":[`...)
	for n, ps := range ordered {
		if n > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"pattern":`...)
		b = lokijson.AppendString(b, ps.pattern)
		b = append(b, `,"samples":[`...)
		ts := make([]int64, 0, len(ps.samples))
		for t := range ps.samples {
			ts = append(ts, t)
		}
		sort.Slice(ts, func(a, c int) bool { return ts[a] < ts[c] })
		for i, t := range ts {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(b, '[')
			b = strconv.AppendInt(b, t, 10)
			b = append(b, ',')
			b = strconv.AppendInt(b, int64(ps.samples[t]), 10)
			b = append(b, ']')
		}
		b = append(b, ']', '}')
	}
	b = append(b, ']', '}')
	*bp = b
	writeJSON(w, b)
	return nil
}

// handleDrilldownLimits serves the Logs Drilldown configuration endpoint.
func (s *Server) handleDrilldownLimits(w http.ResponseWriter, _ *http.Request) error {
	levelFields := s.cfg.LevelFields
	if levelFields == nil {
		levelFields = []string{}
	}
	return writeJSONValue(w, map[string]any{
		"limits": map[string]any{
			"discover_log_levels":         true,
			"discover_service_name":       []string{},
			"log_level_fields":            levelFields,
			"max_entries_limit_per_query": s.cfg.MaxLimit,
			"max_line_size_truncate":      false,
			"max_query_bytes_read":        "0B",
			"max_query_length":            "0s",
			"max_query_lookback":          "0s",
			"max_query_range":             "0s",
			"max_query_series":            5000,
			"metric_aggregation_enabled":  false,
			"pattern_persistence_enabled": false,
			"query_timeout":               s.cfg.QueryTimeout.String(),
			"retention_period":            "0s",
			"volume_enabled":              true,
			"volume_max_series":           1000,
		},
		"pattern_ingester_enabled": s.cfg.Patterns,
		"version":                  s.cfg.LokiVersion,
	})
}

func (s *Server) handleBuildInfo(w http.ResponseWriter, _ *http.Request) error {
	return writeJSONValue(w, map[string]string{
		"version":   s.cfg.LokiVersion,
		"revision":  "loki-vl-proxy-" + s.cfg.Version,
		"branch":    "",
		"buildUser": "",
		"buildDate": "",
		"goVersion": runtime.Version(),
	})
}

// handleFormatQuery validates a query and echoes it back.
func (s *Server) handleFormatQuery(w http.ResponseWriter, r *http.Request) error {
	if err := parseForm(r); err != nil {
		return err
	}
	q := r.Form.Get("query")
	if _, err := logql.Parse(q); err != nil {
		return badRequest(err)
	}
	return writeJSONValue(w, map[string]string{"status": "success", "data": q})
}
