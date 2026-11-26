package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Justereseau/loki-vl-proxy/internal/lokijson"
	"github.com/Justereseau/loki-vl-proxy/internal/translate"
)

const flushThreshold = 32 << 10

var detectedLevelKey = []byte(translate.DetectedLevel)

// logQuery describes a log (non-metric) query.
type logQuery struct {
	logsql     string
	start, end time.Time
	limit      int
	forward    bool
	categorize bool
	// interval keeps one entry per interval and stream (Loki `interval`).
	interval time.Duration
	// fromFields: the pipeline changed the label set (drop/keep/label_format).
	fromFields bool
}

// streamLogs runs a log query on VictoriaLogs and converts the JSON-lines
// response into a Loki "streams" response while it is being read. Memory use
// is bounded by the longest log line, independent of the result size.
//
// Consecutive entries of the same stream are merged into one stream object;
// Grafana accepts the same stream appearing several times in a response.
func (s *Server) streamLogs(w http.ResponseWriter, r *http.Request, tenant tenantID, q *logQuery) error {
	began := time.Now()
	ctx, cancel := s.ctx(r)
	defer cancel()

	form := url.Values{
		"start": {vlTime(q.start)},
		"end":   {vlTime(q.end)},
	}
	if q.forward {
		// oldest first: an explicit sort+limit works on every VictoriaLogs version
		form.Set("query", q.logsql+" | sort by (_time) limit "+strconv.Itoa(q.limit))
	} else {
		// `limit` returns the most recent matching entries
		form.Set("query", q.logsql)
		form.Set("limit", strconv.Itoa(q.limit))
	}
	resp, err := s.do(ctx, r, tenant, "/select/logsql/query", form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bp := getBuf()
	defer putBuf(bp)
	out := *bp

	setJSONHeaders(w)
	out = append(out, `{"status":"success","data":{"resultType":"streams",`...)
	if q.categorize {
		out = append(out, `"encodingFlags":["categorize-labels"],`...)
	}
	out = append(out, `"result":[`...)

	enc := newStreamEncoder(s.cfg.LevelFields, q.categorize)
	enc.normalize = s.cfg.NormalizeLevels
	enc.fromFields = q.fromFields
	if q.interval > 0 {
		enc.interval = int64(q.interval)
		enc.forward = q.forward
		enc.startNs, enc.endNs = q.start.UnixNano(), q.end.UnixNano()
		enc.next = map[string]int64{}
	}
	br := bufio.NewReaderSize(resp.Body, 64<<10)
	var long []byte
	wroteHeader := false
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			long = append(long[:0], line...)
			for errors.Is(err, bufio.ErrBufferFull) {
				line, err = br.ReadSlice('\n')
				long = append(long, line...)
			}
			line = long
		}
		if len(bytes.TrimSpace(line)) > 0 {
			out = enc.appendEntry(out, line)
		}
		if len(out) >= flushThreshold {
			if _, werr := w.Write(out); werr != nil { //nolint:gosec // G705: streamed JSON with an explicit content type and nosniff, never rendered as HTML
				*bp = out[:0]
				return errClientGone
			}
			wroteHeader = true
			out = out[:0]
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			if ctx.Err() != nil && !wroteHeader {
				*bp = out[:0]
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					return httpError(http.StatusGatewayTimeout, "upstream query timed out")
				}
				return errClientGone
			}
			// mid-stream failure: terminate the JSON document cleanly
			s.log.Warn("upstream stream interrupted", "err", err)
			break
		}
	}
	out = enc.finish(out)
	out = append(out, `],`...)
	out = appendStats(out, time.Since(began), enc.count)
	out = append(out, '}', '}')
	_, _ = w.Write(out) //nolint:gosec // G705: streamed JSON with an explicit content type and nosniff, never rendered as HTML
	*bp = out[:0]
	return nil
}

// streamEncoder converts VictoriaLogs JSON lines into Loki stream entries.
type streamEncoder struct {
	levelFields [][]byte
	categorize  bool
	normalize   bool
	fromFields  bool

	// interval sampling (Loki `interval` parameter)
	interval       int64
	forward        bool
	startNs, endNs int64
	next           map[string]int64

	count      int    // entries written
	openLabels []byte // labels of the open stream (categorized mode)
	fieldLbls  []byte

	fields []lokijson.Field
	open   bool // a stream object is open

	// current stream
	streamRaw   []byte   // raw _stream value of the open stream
	streamNames [][]byte // VictoriaLogs names of the stream labels (unescaped)
	labelsJSON  []byte   // {"a":"b"} of the open stream

	scratch  []byte
	valBuf   []byte
	keyBuf   []byte
	entryKey []byte // non-categorized mode: full label set of the open stream
	nextKey  []byte
}

func newStreamEncoder(levelFields []string, categorize bool) *streamEncoder {
	e := &streamEncoder{categorize: categorize}
	for _, f := range levelFields {
		e.levelFields = append(e.levelFields, []byte(f))
	}
	return e
}

func (e *streamEncoder) isStreamLabel(rawKey []byte) bool {
	for _, n := range e.streamNames {
		if bytes.Equal(n, rawKey) {
			return true
		}
	}
	return false
}

func (e *streamEncoder) setStream(raw []byte) {
	e.streamRaw = append(e.streamRaw[:0], raw...)
	e.streamNames = e.streamNames[:0]
	e.labelsJSON = append(e.labelsJSON[:0], '{')
	unesc := lokijson.Unescape(e.scratch[:0], raw)
	e.scratch = unesc
	n := 0
	lokijson.ParseStreamLabels(unesc, func(name, value []byte) {
		if len(value) == 0 {
			return
		}
		if n > 0 {
			e.labelsJSON = append(e.labelsJSON, ',')
		}
		n++
		e.streamNames = append(e.streamNames, append([]byte(nil), name...))
		e.labelsJSON = lokijson.AppendSanitizedName(e.labelsJSON, name)
		e.labelsJSON = append(e.labelsJSON, ':')
		e.labelsJSON = lokijson.AppendBytesString(e.labelsJSON, value)
	})
	e.labelsJSON = append(e.labelsJSON, '}')
}

func appendValue(dst []byte, f *lokijson.Field) []byte {
	if f.Quoted {
		return lokijson.AppendRaw(dst, f.Value)
	}
	return lokijson.AppendBytesString(dst, f.Value)
}

func isInternalField(k []byte) bool {
	return len(k) > 0 && k[0] == '_' && (string(k) == "_msg" || string(k) == "_time" || string(k) == "_stream" || string(k) == "_stream_id")
}

func (e *streamEncoder) appendEntry(out, line []byte) []byte {
	var err error
	e.fields, err = lokijson.ScanObject(line, e.fields)
	if err != nil {
		return out
	}
	var msg, ts, stream *lokijson.Field
	var level *lokijson.Field
	levelRank := len(e.levelFields)
	hasDetected := false
	for i := range e.fields {
		f := &e.fields[i]
		switch string(f.Key) {
		case "_msg":
			msg = f
		case "_time":
			ts = f
		case "_stream":
			stream = f
		case translate.DetectedLevel:
			hasDetected = true
		}
		if len(f.Value) > 0 {
			for j := 0; j < levelRank; j++ {
				if bytes.Equal(f.Key, e.levelFields[j]) {
					level, levelRank = f, j
					break
				}
			}
		}
	}
	var tsNs int64
	if ts != nil {
		tsNs, _ = lokijson.ParseTime(ts.Value)
	}
	var streamVal []byte
	if stream != nil {
		streamVal = stream.Value
	}

	// metadata (all non-stream fields)
	meta := e.valBuf[:0]
	nmeta := 0
	addMeta := func(key []byte, f *lokijson.Field, sanitize bool) {
		if nmeta > 0 {
			meta = append(meta, ',')
		}
		nmeta++
		if sanitize {
			meta = lokijson.AppendSanitizedName(meta, key)
		} else {
			meta = lokijson.AppendRaw(meta, key)
		}
		meta = append(meta, ':')
		meta = appendValue(meta, f)
	}
	streamChanged := !e.open || !bytes.Equal(streamVal, e.streamRaw)
	if streamChanged {
		e.setStream(streamVal)
	}
	if e.interval > 0 && !e.sample(streamVal, tsNs) {
		return out
	}
	labels := e.labelsJSON
	if e.fromFields {
		// the pipeline may have dropped, kept or renamed stream labels: use
		// the stream label fields that are still present in the entry
		e.fieldLbls = append(e.fieldLbls[:0], '{')
		n := 0
		for _, name := range e.streamNames {
			for i := range e.fields {
				f := &e.fields[i]
				if len(f.Value) > 0 && bytes.Equal(f.Key, name) {
					if n > 0 {
						e.fieldLbls = append(e.fieldLbls, ',')
					}
					n++
					e.fieldLbls = lokijson.AppendSanitizedName(e.fieldLbls, name)
					e.fieldLbls = append(e.fieldLbls, ':')
					e.fieldLbls = appendValue(e.fieldLbls, f)
					break
				}
			}
		}
		e.fieldLbls = append(e.fieldLbls, '}')
		labels = e.fieldLbls
	}
	for i := range e.fields {
		f := &e.fields[i]
		if len(f.Value) == 0 || isInternalField(f.Key) || e.isStreamLabel(f.Key) {
			continue
		}
		addMeta(f.Key, f, true)
	}
	if level != nil && !hasDetected {
		if e.normalize {
			e.keyBuf = lokijson.Unescape(e.keyBuf[:0], level.Value)
			norm := translate.NormalizeLevelBytes(e.keyBuf)
			if nmeta > 0 {
				meta = append(meta, ',')
			}
			nmeta++
			meta = append(meta, `"detected_level":"`...)
			meta = append(meta, norm...)
			meta = append(meta, '"')
		} else {
			addMeta(detectedLevelKey, level, false)
		}
	}
	e.valBuf = meta

	e.count++
	if e.categorize {
		if !e.open || !bytes.Equal(labels, e.openLabels) {
			e.openLabels = append(e.openLabels[:0], labels...)
			out = e.openStream(out, labels)
		} else {
			out = append(out, ',')
		}
	} else {
		// all labels on the stream: merge stream labels and metadata
		e.nextKey = append(e.nextKey[:0], labels[:len(labels)-1]...)
		if nmeta > 0 {
			if len(e.nextKey) > 1 {
				e.nextKey = append(e.nextKey, ',')
			}
			e.nextKey = append(e.nextKey, meta...)
		}
		e.nextKey = append(e.nextKey, '}')
		key := e.nextKey
		if !e.open || !bytes.Equal(key, e.entryKey) {
			e.entryKey = append(e.entryKey[:0], key...)
			out = e.openStream(out, key)
		} else {
			out = append(out, ',')
		}
	}

	out = append(out, '[', '"')
	out = strconv.AppendInt(out, tsNs, 10)
	out = append(out, '"', ',')
	if msg != nil {
		out = appendValue(out, msg)
	} else {
		out = append(out, '"', '"')
	}
	if e.categorize {
		// Grafana expects the third element on every entry in categorized mode
		if nmeta > 0 {
			out = append(out, `,{"structuredMetadata":{`...)
			out = append(out, meta...)
			out = append(out, '}', '}')
		} else {
			out = append(out, `,{}`...)
		}
	}
	out = append(out, ']')
	return out
}

// sample implements Loki's `interval`: per stream, an entry is returned at
// start, then the next entry at or after start+interval, and so on
// (mirrored from end for backward queries).
func (e *streamEncoder) sample(stream []byte, ts int64) bool {
	next, ok := e.next[string(stream)]
	if e.forward {
		if ok && ts < next {
			return false
		}
		e.next[string(stream)] = e.startNs + ((ts-e.startNs)/e.interval+1)*e.interval
		return true
	}
	if ok && ts > next {
		return false
	}
	e.next[string(stream)] = e.endNs - ((e.endNs-ts)/e.interval+1)*e.interval
	return true
}

func (e *streamEncoder) openStream(out, labels []byte) []byte {
	if e.open {
		out = append(out, ']', '}', ',')
	}
	e.open = true
	out = append(out, `{"stream":`...)
	out = append(out, labels...)
	out = append(out, `,"values":[`...)
	return out
}

func (e *streamEncoder) finish(out []byte) []byte {
	if e.open {
		out = append(out, ']', '}')
	}
	return out
}
