package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Justereseau/loki-vl-proxy/internal/lokijson"
)

const maxDistinctPerField = 1000

type fieldStat struct {
	vlName   string
	distinct map[string]struct{}
	overflow bool
	// type candidates, cleared as soon as a value does not match
	isInt, isFloat, isDuration, isBytes, isBool bool
	native                                      bool
	json                                        bool // seen on a line that looks like JSON
}

// handleDetectedFields serves /detected_fields like Loki does: it samples the
// most recent `line_limit` lines matching the query (including its parsers)
// and reports every field with its cardinality, type and parser. Fields stored
// natively in VictoriaLogs are reported as structured metadata (parsers: null).
func (s *Server) handleDetectedFields(w http.ResponseWriter, r *http.Request) error {
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
	began := time.Now()
	// documented defaults: line_limit=100, limit (alias field_limit)=1000
	lineLimit := 100
	if v := r.Form.Get("line_limit"); v != "" {
		if lineLimit, err = strconv.Atoi(v); err != nil || lineLimit <= 0 {
			return httpError(http.StatusBadRequest, "invalid line_limit %q", v)
		}
	}
	lineLimit = min(lineLimit, s.cfg.MaxLimit)
	limit, err := fieldLimit(r)
	if err != nil {
		return err
	}
	lines := 0

	ctx, cancel := s.ctx(r)
	defer cancel()
	form := timeForm(start, end)
	form.Set("query", q)
	form.Set("limit", strconv.Itoa(lineLimit))
	resp, err := s.do(ctx, r, tenant, "/select/logsql/query", form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	stats := map[string]*fieldStat{}
	var (
		fields      []lokijson.Field
		streamRaw   []byte
		streamNames []string
		valBuf      []byte
		long        []byte
	)
	br := bufio.NewReaderSize(resp.Body, 64<<10)
	for {
		line, rerr := br.ReadSlice('\n')
		if errors.Is(rerr, bufio.ErrBufferFull) {
			long = append(long[:0], line...)
			for errors.Is(rerr, bufio.ErrBufferFull) {
				line, rerr = br.ReadSlice('\n')
				long = append(long, line...)
			}
			line = long
		}
		if fields, err = lokijson.ScanObject(line, fields); err == nil {
			lines++
			isJSON := false
			for _, f := range fields {
				switch string(f.Key) {
				case "_stream":
					if !bytes.Equal(f.Value, streamRaw) {
						streamRaw = append(streamRaw[:0], f.Value...)
						streamNames = streamNames[:0]
						lokijson.ParseStreamLabels(lokijson.Unescape(nil, f.Value), func(n, _ []byte) {
							streamNames = append(streamNames, string(n))
						})
					}
				case "_msg":
					v := bytes.TrimLeft(f.Value, " \t")
					isJSON = len(v) > 0 && v[0] == '{'
				}
			}
			for _, f := range fields {
				if len(f.Value) == 0 || isInternalField(f.Key) {
					continue
				}
				key := string(lokijson.Unescape(nil, f.Key))
				if containsString(streamNames, key) {
					continue
				}
				st := stats[key]
				if st == nil {
					st = &fieldStat{vlName: key, distinct: map[string]struct{}{},
						isInt: true, isFloat: true, isDuration: true, isBytes: true, isBool: true}
					stats[key] = st
				}
				st.json = st.json || isJSON
				valBuf = lokijson.Unescape(valBuf[:0], f.Value)
				if !st.overflow {
					if _, ok := st.distinct[string(valBuf)]; !ok {
						if len(st.distinct) >= maxDistinctPerField {
							st.overflow = true
						} else {
							st.distinct[string(valBuf)] = struct{}{}
						}
					}
				}
				v := string(valBuf)
				st.isInt = st.isInt && reInt.MatchString(v)
				st.isFloat = st.isFloat && reFloat.MatchString(v)
				st.isDuration = st.isDuration && reDuration.MatchString(v)
				st.isBytes = st.isBytes && reBytes.MatchString(v)
				st.isBool = st.isBool && (v == "true" || v == "false")
			}
		}
		if rerr != nil {
			if rerr != io.EOF && ctx.Err() != nil {
				return errClientGone
			}
			break
		}
	}

	type field struct {
		Label       string   `json:"label"`
		Type        string   `json:"type"`
		Cardinality int      `json:"cardinality"`
		Parsers     []string `json:"parsers"`
		JSONPath    []string `json:"jsonPath,omitempty"`
	}
	out := struct {
		Fields []field         `json:"fields"`
		Limit  int             `json:"limit"`
		Stats  json.RawMessage `json:"stats"`
	}{Fields: []field{}, Limit: limit}
	names := make([]string, 0, len(stats))
	for n := range stats {
		names = append(names, n)
	}
	sort.Strings(names)
	s.names.learn(tenant, names...)
	for _, n := range names {
		st := stats[n]
		f := field{Label: lokijson.SanitizeLabelName(n), Cardinality: len(st.distinct)}
		if st.overflow {
			f.Cardinality = maxDistinctPerField + 1
		}
		switch {
		case st.isInt:
			f.Type = "int"
		case st.isFloat:
			f.Type = "float"
		case st.isDuration:
			f.Type = "duration"
		case st.isBytes:
			f.Type = "bytes"
		case st.isBool:
			f.Type = "boolean"
		default:
			f.Type = "string"
		}
		if !s.names.isNative(ctx, tenant, n) {
			if st.json {
				f.Parsers = []string{"json"}
				f.JSONPath = strings.Split(n, ".")
			} else {
				f.Parsers = []string{"logfmt"}
			}
		}
		out.Fields = append(out.Fields, f)
		if len(out.Fields) >= limit {
			break
		}
	}
	out.Stats = appendStatsObject(nil, time.Since(began), lines)
	return writeJSONValue(w, out)
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
