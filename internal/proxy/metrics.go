package proxy

import (
	"bytes"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Justereseau/loki-vl-proxy/internal/lokijson"
	"github.com/Justereseau/loki-vl-proxy/internal/translate"
)

// promResponse is the Prometheus-compatible response of
// /select/logsql/stats_query and /select/logsql/stats_query_range.
type promResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Value  *samplePair       `json:"value"`
			Values []samplePair      `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

// samplePair decodes [1700000000.5,"12"] without intermediate allocations.
type samplePair struct {
	t int64 // milliseconds
	v float64
}

var errBadSample = errors.New("invalid sample")

func (sp *samplePair) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) < 5 || b[0] != '[' || b[len(b)-1] != ']' {
		return errBadSample
	}
	b = b[1 : len(b)-1]
	i := bytes.IndexByte(b, ',')
	if i < 0 {
		return errBadSample
	}
	ts, err := strconv.ParseFloat(string(bytes.TrimSpace(b[:i])), 64)
	if err != nil {
		return errBadSample
	}
	sp.t = int64(math.Round(ts * 1000))
	vs := bytes.Trim(bytes.TrimSpace(b[i+1:]), `"`)
	switch string(vs) {
	case "NaN":
		sp.v = math.NaN()
	case "+Inf", "Inf":
		sp.v = math.Inf(1)
	case "-Inf":
		sp.v = math.Inf(-1)
	default:
		if sp.v, err = strconv.ParseFloat(string(vs), 64); err != nil {
			return errBadSample
		}
	}
	return nil
}

type point struct {
	t int64 // milliseconds
	v float64
}

type label struct{ name, value string }

type mseries struct {
	labels []label
	key    string
	pts    []point
}

// convertSeries turns VictoriaLogs series into Loki series: it drops
// __name__, expands _stream, renames grouping labels and sanitizes names.
func (s *Server) convertSeries(tenant tenantID, resp *promResponse, mq *translate.MetricQuery) []*mseries {
	out := make([]*mseries, 0, len(resp.Data.Result))
	byKey := make(map[string]*mseries, len(resp.Data.Result))
	var learned []string
	for i := range resp.Data.Result {
		res := &resp.Data.Result[i]
		var lbls []label
		if mq.NameAsLabel {
			name := res.Metric["__name__"]
			if l, ok := mq.Renames[name]; ok {
				name = l
			}
			lbls = append(lbls, label{lokijson.SanitizeLabelName(name), ""})
		}
		for k, v := range res.Metric {
			if k == "__name__" || v == "" {
				continue
			}
			if k == "_stream" && mq.ExpandStream {
				lokijson.ParseStreamLabels([]byte(v), func(name, value []byte) {
					if len(value) > 0 {
						learned = append(learned, string(name))
						lbls = append(lbls, label{lokijson.SanitizeLabelName(string(name)), string(value)})
					}
				})
				continue
			}
			name, ok := mq.Renames[k]
			if !ok {
				learned = append(learned, k)
				name = lokijson.SanitizeLabelName(k)
			}
			if name == translate.DetectedLevel && s.cfg.NormalizeLevels {
				v = translate.NormalizeLevel(v)
			}
			lbls = append(lbls, label{name, v})
		}
		sort.Slice(lbls, func(a, b int) bool { return lbls[a].name < lbls[b].name })
		key := labelsKey(lbls)
		sr := byKey[key]
		if sr == nil {
			sr = &mseries{labels: lbls, key: key}
			byKey[key] = sr
			out = append(out, sr)
		}
		// VictoriaLogs reports NaN for buckets without numeric values; Loki
		// simply has no sample there.
		if res.Value != nil && !math.IsNaN(res.Value.v) {
			sr.pts = append(sr.pts, point{res.Value.t, res.Value.v})
		}
		for _, sp := range res.Values {
			if !math.IsNaN(sp.v) {
				sr.pts = append(sr.pts, point{sp.t, sp.v})
			}
		}
	}
	s.names.learn(tenant, learned...)
	for _, sr := range out {
		sort.Slice(sr.pts, func(a, b int) bool { return sr.pts[a].t < sr.pts[b].t })
		// series merged by label normalization: sum samples at equal timestamps
		pts := sr.pts[:0]
		for _, p := range sr.pts {
			if n := len(pts); n > 0 && pts[n-1].t == p.t {
				pts[n-1].v += p.v
				continue
			}
			pts = append(pts, p)
		}
		sr.pts = pts
	}
	sort.Slice(out, func(a, b int) bool { return out[a].key < out[b].key })
	return out
}

func labelsKey(lbls []label) string {
	var sb strings.Builder
	for _, l := range lbls {
		sb.WriteString(l.name)
		sb.WriteByte(0)
		sb.WriteString(l.value)
		sb.WriteByte(0)
	}
	return sb.String()
}

// slideWindow combines step buckets into windows of `window` ms ending at each
// output timestamp. pts must be sorted; output timestamps stay on the step grid.
func slideWindow(pts []point, kind translate.SlideKind, step, window int64) []point {
	if len(pts) == 0 {
		return pts
	}
	out := make([]point, 0, len(pts)+int(window/step))
	lo := 0
	t := pts[0].t
	last := pts[len(pts)-1].t + window - step
	for t <= last {
		// drop buckets that left the window (t-window, t]
		for lo < len(pts) && pts[lo].t <= t-window {
			lo++
		}
		if lo >= len(pts) {
			break
		}
		if pts[lo].t > t { // gap: jump to the next bucket
			t = pts[lo].t
			continue
		}
		var v float64
		first := true
		for j := lo; j < len(pts) && pts[j].t <= t; j++ {
			x := pts[j].v
			switch {
			case first:
				v, first = x, false
			case kind == translate.SlideSum:
				v += x
			case kind == translate.SlideMax:
				v = math.Max(v, x)
			case kind == translate.SlideMin:
				v = math.Min(v, x)
			}
		}
		out = append(out, point{t, v})
		t += step
	}
	return out
}

// applyPost runs the post-processing operations of a translated query.
func applyPost(series []*mseries, ops []translate.PostOp, windowSec float64, g grid) []*mseries {
	instant := g.instant
	for _, op := range ops {
		switch op.Kind {
		case translate.PostAbsent:
			series = absent(series, op.Labels, g)
		case translate.PostScale, translate.PostScaleWindow, translate.PostSquare, translate.PostScalarOp, translate.PostCompare:
			for _, sr := range series {
				pts := sr.pts[:0]
				for _, p := range sr.pts {
					keep := true
					switch op.Kind {
					case translate.PostScale:
						p.v *= op.F
					case translate.PostScaleWindow:
						p.v /= windowSec
					case translate.PostSquare:
						p.v *= p.v
					case translate.PostScalarOp:
						if op.ScalarLeft {
							p.v, _ = translate.ApplyScalar(op.Op, op.F, p.v)
						} else {
							p.v, _ = translate.ApplyScalar(op.Op, p.v, op.F)
						}
					case translate.PostCompare:
						var res float64
						var ok bool
						if op.ScalarLeft {
							res, ok = translate.ApplyScalar(op.Op, op.F, p.v)
						} else {
							res, ok = translate.ApplyScalar(op.Op, p.v, op.F)
						}
						if op.Bool {
							p.v = res
						} else {
							keep = ok
						}
					}
					if keep {
						pts = append(pts, p)
					}
				}
				sr.pts = pts
			}
		case translate.PostTopK:
			series = topK(series, op)
		case translate.PostSort:
			if instant {
				sort.SliceStable(series, func(a, b int) bool {
					va, vb := firstValue(series[a]), firstValue(series[b])
					if op.Desc {
						return va > vb
					}
					return va < vb
				})
			}
		}
	}
	out := series[:0]
	for _, sr := range series {
		if len(sr.pts) > 0 {
			out = append(out, sr)
		}
	}
	return out
}

// absent implements absent_over_time: a sample with value 1 at every
// evaluation timestamp where the input has no sample.
func absent(series []*mseries, labels map[string]string, g grid) []*mseries {
	// `stats count()` without grouping reports 0 when nothing matched
	seen := map[int64]bool{}
	for _, sr := range series {
		for _, p := range sr.pts {
			if p.v != 0 {
				seen[p.t] = true
			}
		}
	}
	out := &mseries{}
	for name, v := range labels {
		out.labels = append(out.labels, label{name, v})
	}
	sort.Slice(out.labels, func(a, b int) bool { return out.labels[a].name < out.labels[b].name })
	if g.instant {
		if len(seen) == 0 {
			out.pts = []point{{g.ts, 1}}
		}
	} else {
		for t := g.start; t <= g.end; t += g.step {
			if !seen[t] {
				out.pts = append(out.pts, point{t, 1})
			}
		}
	}
	return []*mseries{out}
}

// binaryOp evaluates a binary operation between two vectors with the default
// Prometheus/LogQL one-to-one matching on identical label sets, timestamp by
// timestamp. Arithmetic and comparisons keep the left-hand labels.
func binaryOp(op string, isBool bool, l, r []*mseries) []*mseries {
	rIdx := make(map[string]map[int64]float64, len(r))
	for _, sr := range r {
		m := make(map[int64]float64, len(sr.pts))
		for _, p := range sr.pts {
			m[p.t] = p.v
		}
		rIdx[sr.key] = m
	}
	var out []*mseries
	switch op {
	case "and", "unless":
		for _, sr := range l {
			m := rIdx[sr.key]
			res := &mseries{labels: sr.labels, key: sr.key}
			for _, p := range sr.pts {
				_, ok := m[p.t]
				if ok == (op == "and") {
					res.pts = append(res.pts, p)
				}
			}
			out = append(out, res)
		}
	case "or":
		present := map[string]map[int64]bool{}
		for _, sr := range l {
			m := map[int64]bool{}
			for _, p := range sr.pts {
				m[p.t] = true
			}
			present[sr.key] = m
			out = append(out, sr)
		}
		// right-hand samples are added where no left-hand series has the same labels at that time
		for _, sr := range r {
			res := &mseries{labels: sr.labels, key: sr.key}
			for _, p := range sr.pts {
				if m, ok := present[sr.key]; ok && m[p.t] {
					continue
				}
				res.pts = append(res.pts, p)
			}
			out = append(out, res)
		}
		out = mergeSameKey(out)
	default:
		for _, sr := range l {
			m, ok := rIdx[sr.key]
			if !ok {
				continue
			}
			res := &mseries{labels: sr.labels, key: sr.key}
			for _, p := range sr.pts {
				rv, ok := m[p.t]
				if !ok {
					continue
				}
				v, keep := translate.ApplyScalar(op, p.v, rv)
				switch op {
				case "==", "!=", ">", ">=", "<", "<=":
					if isBool {
						res.pts = append(res.pts, point{p.t, v})
					} else if keep {
						res.pts = append(res.pts, p)
					}
				default:
					res.pts = append(res.pts, point{p.t, v})
				}
			}
			out = append(out, res)
		}
	}
	res := out[:0]
	for _, sr := range out {
		if len(sr.pts) > 0 {
			res = append(res, sr)
		}
	}
	return res
}

// mergeSameKey merges series with identical label sets (sorted points).
func mergeSameKey(in []*mseries) []*mseries {
	idx := map[string]*mseries{}
	var out []*mseries
	for _, sr := range in {
		if cur, ok := idx[sr.key]; ok {
			cur.pts = append(cur.pts, sr.pts...)
			sort.Slice(cur.pts, func(a, b int) bool { return cur.pts[a].t < cur.pts[b].t })
			continue
		}
		cp := &mseries{labels: sr.labels, key: sr.key, pts: append([]point(nil), sr.pts...)}
		idx[sr.key] = cp
		out = append(out, cp)
	}
	return out
}

func firstValue(sr *mseries) float64 {
	if len(sr.pts) == 0 {
		return math.NaN()
	}
	return sr.pts[0].v
}

// topK keeps, for every timestamp (and group), the k largest (or smallest) samples.
func topK(series []*mseries, op translate.PostOp) []*mseries {
	type cand struct {
		s int
		p int
	}
	groups := map[string]map[int64][]cand{}
	for si, sr := range series {
		g := groupKey(sr, op.By)
		m := groups[g]
		if m == nil {
			m = map[int64][]cand{}
			groups[g] = m
		}
		for pi, p := range sr.pts {
			m[p.t] = append(m[p.t], cand{si, pi})
		}
	}
	keep := make([][]bool, len(series))
	for i, sr := range series {
		keep[i] = make([]bool, len(sr.pts))
	}
	for _, m := range groups {
		for _, cs := range m {
			sort.Slice(cs, func(a, b int) bool {
				va, vb := series[cs[a].s].pts[cs[a].p].v, series[cs[b].s].pts[cs[b].p].v
				if op.Bottom {
					return va < vb
				}
				return va > vb
			})
			for i := 0; i < len(cs) && i < op.K; i++ {
				keep[cs[i].s][cs[i].p] = true
			}
		}
	}
	for i, sr := range series {
		pts := sr.pts[:0]
		for j, p := range sr.pts {
			if keep[i][j] {
				pts = append(pts, p)
			}
		}
		sr.pts = pts
	}
	return series
}

func groupKey(sr *mseries, by []string) string {
	if len(by) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, b := range by {
		name := lokijson.SanitizeLabelName(b)
		for _, l := range sr.labels {
			if l.name == name || l.name == b {
				sb.WriteString(l.value)
				break
			}
		}
		sb.WriteByte(0)
	}
	return sb.String()
}

func appendLabels(dst []byte, lbls []label) []byte {
	dst = append(dst, '{')
	for i, l := range lbls {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = lokijson.AppendString(dst, l.name)
		dst = append(dst, ':')
		dst = lokijson.AppendString(dst, l.value)
	}
	return append(dst, '}')
}

func appendSample(dst []byte, p point) []byte {
	dst = append(dst, '[')
	dst = lokijson.AppendUnixSeconds(dst, p.t)
	dst = append(dst, ',', '"')
	dst = lokijson.AppendFloatValue(dst, p.v)
	return append(dst, '"', ']')
}

// appendStats writes Loki's statistics block. VictoriaLogs does not report
// scan statistics, so only the execution time and returned entries are set;
// the other documented counters are present and zero.
func appendStats(dst []byte, exec time.Duration, entries int) []byte {
	dst = append(dst, `"stats":`...)
	return appendStatsObject(dst, exec, entries)
}

func appendStatsObject(dst []byte, exec time.Duration, entries int) []byte {
	dst = append(dst, `{"summary":{"bytesProcessedPerSecond":0,"linesProcessedPerSecond":0,"totalBytesProcessed":0,"totalLinesProcessed":0,"execTime":`...)
	dst = strconv.AppendFloat(dst, exec.Seconds(), 'f', -1, 64)
	dst = append(dst, `,"queueTime":0,"subqueries":0,"totalEntriesReturned":`...)
	dst = strconv.AppendInt(dst, int64(entries), 10)
	dst = append(dst, `,"splits":0,"shards":0,"totalPostFilterLines":0,"totalStructuredMetadataBytesProcessed":0},`+
		`"querier":{"store":{"totalChunksRef":0,"totalChunksDownloaded":0,"chunksDownloadTime":0,"queryReferencedStructuredMetadata":false,"chunk":{"headChunkBytes":0,"headChunkLines":0,"decompressedBytes":0,"decompressedLines":0,"compressedBytes":0,"totalDuplicates":0,"postFilterLines":0,"headChunkStructuredMetadataBytes":0,"decompressedStructuredMetadataBytes":0}}},`+
		`"ingester":{"totalReached":0,"totalChunksMatched":0,"totalBatches":0,"totalLinesSent":0,"store":{"totalChunksRef":0,"totalChunksDownloaded":0,"chunksDownloadTime":0,"queryReferencedStructuredMetadata":false,"chunk":{"headChunkBytes":0,"headChunkLines":0,"decompressedBytes":0,"decompressedLines":0,"compressedBytes":0,"totalDuplicates":0,"postFilterLines":0,"headChunkStructuredMetadataBytes":0,"decompressedStructuredMetadataBytes":0}}}}`...)
	return dst
}

func appendScalar(dst []byte, ts int64, v float64, exec time.Duration) []byte {
	dst = append(dst, `{"status":"success","data":{"resultType":"scalar","result":`...)
	dst = appendSample(dst, point{ts, v})
	dst = append(dst, ',')
	dst = appendStats(dst, exec, 1)
	return append(dst, '}', '}')
}

func appendMatrix(dst []byte, series []*mseries, exec time.Duration) []byte {
	dst = append(dst, `{"status":"success","data":{"resultType":"matrix","result":[`...)
	for i, sr := range series {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, `{"metric":`...)
		dst = appendLabels(dst, sr.labels)
		dst = append(dst, `,"values":[`...)
		for j, p := range sr.pts {
			if j > 0 {
				dst = append(dst, ',')
			}
			dst = appendSample(dst, p)
		}
		dst = append(dst, ']', '}')
	}
	dst = append(dst, `],`...)
	dst = appendStats(dst, exec, len(series))
	return append(dst, '}', '}')
}

func appendVector(dst []byte, series []*mseries, exec time.Duration) []byte {
	dst = append(dst, `{"status":"success","data":{"resultType":"vector","result":[`...)
	n := 0
	for _, sr := range series {
		if len(sr.pts) == 0 {
			continue
		}
		if n > 0 {
			dst = append(dst, ',')
		}
		n++
		dst = append(dst, `{"metric":`...)
		dst = appendLabels(dst, sr.labels)
		dst = append(dst, `,"value":`...)
		dst = appendSample(dst, sr.pts[len(sr.pts)-1])
		dst = append(dst, '}')
	}
	dst = append(dst, `],`...)
	dst = appendStats(dst, exec, n)
	return append(dst, '}', '}')
}
