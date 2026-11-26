package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Justereseau/loki-vl-proxy/internal/translate"
)

// fakeVL is an in-memory VictoriaLogs stand-in recording upstream requests.
type fakeVL struct {
	mu        sync.Mutex
	responses map[string]string // path -> body
	requests  []*http.Request
	forms     []url.Values
}

func (f *fakeVL) RoundTrip(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	f.mu.Lock()
	f.requests = append(f.requests, r)
	f.forms = append(f.forms, form)
	resp, ok := f.responses[r.URL.Path]
	f.mu.Unlock()
	code := 200
	if !ok {
		code, resp = 400, "unexpected path "+r.URL.Path
	}
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(resp)), Header: http.Header{}, Request: r}, nil
}

func (f *fakeVL) last() (*http.Request, url.Values) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[len(f.requests)-1], f.forms[len(f.forms)-1]
}

func newTestServer(t *testing.T, responses map[string]string) (*Server, *fakeVL) {
	t.Helper()
	if _, ok := responses["/vl/select/logsql/field_names"]; !ok {
		responses["/vl/select/logsql/field_names"] = `{"values":[{"value":"service.name","hits":1},{"value":"level","hits":1},{"value":"pod","hits":1}]}`
	}
	f := &fakeVL{responses: responses}
	u, _ := url.Parse("http://vl:9428/vl")
	s := New(Config{
		Upstream:        u,
		Transport:       f,
		LevelFields:     []string{"level"},
		NormalizeLevels: true,
		TenantMap:       map[string]string{"team-a": "7:3"},
		Patterns:        true,
	})
	return s, f
}

func get(t *testing.T, s *Server, path string, hdr map[string]string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

const vlLines = `{"_msg":"GET /a 200","_stream":"{service.name=\"api\",pod=\"p1\"}","_stream_id":"x","_time":"2024-01-01T00:00:02.5Z","level":"ERR","pod":"p1","service.name":"api","trace.id":"t1"}
{"_msg":"GET /b 200","_stream":"{service.name=\"api\",pod=\"p1\"}","_stream_id":"x","_time":"2024-01-01T00:00:01Z","level":"info","pod":"p1","service.name":"api"}
{"_msg":"line \"quoted\" é","_stream":"{service.name=\"web\"}","_stream_id":"y","_time":"2024-01-01T00:00:00Z","service.name":"web"}
`

func TestLogQueryCategorized(t *testing.T) {
	s, f := newTestServer(t, map[string]string{"/vl/select/logsql/query": vlLines})
	code, body := get(t, s, `/loki/api/v1/query_range?query=`+url.QueryEscape(`{service_name=~"api|web"} |= "GET"`)+`&start=1704067200000000000&end=1704067260000000000&limit=10`,
		map[string]string{"X-Loki-Response-Encoding-Flags": "categorize-labels", "X-Scope-OrgID": "team-a"})
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	want := `{"status":"success","data":{"resultType":"streams","encodingFlags":["categorize-labels"],"result":[` +
		`{"stream":{"service_name":"api","pod":"p1"},"values":[` +
		`["1704067202500000000","GET /a 200",{"structuredMetadata":{"level":"ERR","trace_id":"t1","detected_level":"error"}}],` +
		`["1704067201000000000","GET /b 200",{"structuredMetadata":{"level":"info","detected_level":"info"}}]]},` +
		`{"stream":{"service_name":"web"},"values":[["1704067200000000000","line \"quoted\" é",{}]]}],"stats":{}}}`
	if noStats(body) != noStats(want) {
		t.Fatalf("got\n%s\nwant\n%s", body, want)
	}
	if !json.Valid([]byte(body)) {
		t.Fatal("invalid JSON")
	}
	req, form := f.last()
	if req.Header.Get("AccountID") != "7" || req.Header.Get("ProjectID") != "3" {
		t.Errorf("tenant headers: %v", req.Header)
	}
	if got := form.Get("query"); got != `{service.name=~"api|web"} *"GET"*` {
		t.Errorf("upstream query: %s", got)
	}
	if form.Get("limit") != "10" {
		t.Errorf("limit: %s", form.Get("limit"))
	}
}

func TestLogQueryForwardAndPlainLabels(t *testing.T) {
	s, f := newTestServer(t, map[string]string{"/vl/select/logsql/query": vlLines})
	code, body := get(t, s, `/loki/api/v1/query_range?direction=forward&limit=5&query=`+url.QueryEscape(`{pod="p1"}`), nil)
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	_, form := f.last()
	if got := form.Get("query"); got != `{pod="p1"} | sort by (_time) limit 5` {
		t.Errorf("upstream query: %s", got)
	}
	// without categorize-labels all fields are stream labels
	if !strings.Contains(body, `{"stream":{"service_name":"api","pod":"p1","level":"ERR","trace_id":"t1","detected_level":"error"},"values":[["1704067202500000000","GET /a 200"]]}`) {
		t.Errorf("unexpected body: %s", body)
	}
	if !json.Valid([]byte(body)) {
		t.Fatal("invalid JSON")
	}
}

func TestMetricRange(t *testing.T) {
	vl := `{"status":"success","data":{"resultType":"matrix","result":[
	 {"metric":{"__name__":"v","level":"ERR"},"values":[[1704067200,"6"],[1704067260,"12"]]},
	 {"metric":{"__name__":"v","level":"error"},"values":[[1704067260,"6"]]},
	 {"metric":{"__name__":"v","level":"info"},"values":[[1704067140,"60"]]}]}}`
	s, f := newTestServer(t, map[string]string{"/vl/select/logsql/stats_query_range": vl})
	q := `sum by (detected_level) (rate({service_name="api"}[1m]))`
	code, body := get(t, s, `/loki/api/v1/query_range?step=60&start=1704067200&end=1704067320&query=`+url.QueryEscape(q), nil)
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	// buckets shift by one step, ERR and error merge, rate divides by 60s
	want := `{"status":"success","data":{"resultType":"matrix","result":[` +
		`{"metric":{"detected_level":"error"},"values":[[1704067260,"0.1"],[1704067320,"0.3"]]},` +
		`{"metric":{"detected_level":"info"},"values":[[1704067200,"1"]]}],"stats":{}}}`
	if noStats(body) != noStats(want) {
		t.Fatalf("got\n%s\nwant\n%s", body, want)
	}
	_, form := f.last()
	if form.Get("query") != `{service.name="api"} | stats by (level) count() as v` || form.Get("step") != "60000ms" {
		t.Errorf("upstream form: %v", form)
	}
	if form.Get("start") != "2024-01-01T00:59:00Z" && form.Get("start") != "2023-12-31T23:59:00Z" {
		t.Errorf("start: %s", form.Get("start"))
	}
}

func TestMetricInstantStreamExpansionAndTopK(t *testing.T) {
	vl := `{"status":"success","data":{"resultType":"vector","result":[
	 {"metric":{"__name__":"v","_stream":"{service.name=\"a\",pod=\"1\"}"},"value":[1704067200,"5"]},
	 {"metric":{"__name__":"v","_stream":"{service.name=\"b\",pod=\"2\"}"},"value":[1704067200,"9"]},
	 {"metric":{"__name__":"v","_stream":"{service.name=\"c\",pod=\"3\"}"},"value":[1704067200,"1"]}]}}`
	s, _ := newTestServer(t, map[string]string{"/vl/select/logsql/stats_query": vl})
	code, body := get(t, s, `/loki/api/v1/query?time=1704067200&query=`+url.QueryEscape(`topk(2, count_over_time({pod=~".+"}[5m]))`), nil)
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	want := `{"status":"success","data":{"resultType":"vector","result":[` +
		`{"metric":{"pod":"1","service_name":"a"},"value":[1704067200,"5"]},` +
		`{"metric":{"pod":"2","service_name":"b"},"value":[1704067200,"9"]}],"stats":{}}}`
	if noStats(body) != noStats(want) {
		t.Fatalf("got\n%s\nwant\n%s", body, want)
	}
}

func TestHealthCheckQuery(t *testing.T) {
	s, _ := newTestServer(t, map[string]string{})
	code, body := get(t, s, `/loki/api/v1/query?time=1704067200&query=`+url.QueryEscape(`vector(1)+vector(1)`), nil)
	if code != 200 || noStats(body) != noStats(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1704067200,"2"]}],"stats":{}}}`) {
		t.Fatalf("%d %s", code, body)
	}
}

func TestLabelsAndValues(t *testing.T) {
	s, f := newTestServer(t, map[string]string{
		"/vl/select/logsql/stream_field_names":  `{"values":[{"value":"service.name","hits":3},{"value":"pod","hits":2}]}`,
		"/vl/select/logsql/stream_field_values": `{"values":[]}`,
		"/vl/select/logsql/field_values":        `{"values":[{"value":"ERR","hits":1},{"value":"error","hits":1},{"value":"Info","hits":1}]}`,
	})
	_, body := get(t, s, `/loki/api/v1/labels`, nil)
	if body != `{"status":"success","data":["pod","service_name"]}` {
		t.Errorf("labels: %s", body)
	}
	_, body = get(t, s, `/loki/api/v1/label/detected_level/values`, nil)
	if body != `{"status":"success","data":["error","info"]}` {
		t.Errorf("level values: %s", body)
	}
	_, form := f.last()
	if form.Get("field") != "level" {
		t.Errorf("field: %v", form)
	}
}

func TestVolume(t *testing.T) {
	vl := `{"status":"success","data":{"resultType":"vector","result":[
	 {"metric":{"__name__":"v","service.name":"small"},"value":[1704067200,"5"]},
	 {"metric":{"__name__":"v","service.name":"big"},"value":[1704067200,"50"]}]}}`
	s, f := newTestServer(t, map[string]string{"/vl/select/logsql/stats_query": vl})
	_, body := get(t, s, `/loki/api/v1/index/volume?limit=1&query=`+url.QueryEscape(`{service_name=~".+"}`), nil)
	if !strings.Contains(body, `"result":[{"metric":{"service_name":"big"}`) || strings.Contains(body, "small") {
		t.Errorf("volume: %s", body)
	}
	_, form := f.last()
	if form.Get("query") != `{service.name=~".+"} | stats by (service.name) count() as v` {
		t.Errorf("query: %s", form.Get("query"))
	}
}

func TestTenantErrors(t *testing.T) {
	s, _ := newTestServer(t, map[string]string{})
	for _, org := range []string{"unknown-tenant", "1|2", "1:x"} {
		code, _ := get(t, s, `/loki/api/v1/labels`, map[string]string{"X-Scope-OrgID": org})
		if code != http.StatusBadRequest {
			t.Errorf("%s: status %d", org, code)
		}
	}
}

func TestUpstreamErrorAndBadQuery(t *testing.T) {
	s, _ := newTestServer(t, map[string]string{})
	code, body := get(t, s, `/loki/api/v1/query_range?query=`+url.QueryEscape(`{a="b"`), nil)
	if code != 400 || !strings.Contains(body, "parse error") {
		t.Errorf("bad query: %d %s", code, body)
	}
	code, body = get(t, s, `/loki/api/v1/query_range?query=`+url.QueryEscape(`{a="b"}`), nil)
	if code != 400 || !strings.Contains(body, "victorialogs") {
		t.Errorf("upstream error: %d %s", code, body)
	}
}

// noStats drops the timing-dependent "stats" block of a Loki response.
func noStats(body string) string {
	if i := strings.Index(body, `,"stats":`); i >= 0 {
		return body[:i] + "}}"
	}
	return body
}

func TestLokiParameterValidation(t *testing.T) {
	s, _ := newTestServer(t, map[string]string{"/vl/select/logsql/query": vlLines})
	cases := []struct {
		path string
		code int
		msg  string
	}{
		{`/loki/api/v1/query?query=` + url.QueryEscape(`{a="b"}`), 400, "log queries are not supported as an instant query type"},
		{`/loki/api/v1/query_range?limit=0&query=` + url.QueryEscape(`{a="b"}`), 400, "limit must be a positive value"},
		{`/loki/api/v1/query_range?limit=6000&query=` + url.QueryEscape(`{a="b"}`), 400, "max entries limit per query exceeded"},
		{`/loki/api/v1/query_range?direction=sideways&query=` + url.QueryEscape(`{a="b"}`), 400, "invalid direction"},
		{`/loki/api/v1/query_range?step=0&query=` + url.QueryEscape(`count_over_time({a="b"}[1m])`), 400, "zero or negative query resolution step"},
		{`/loki/api/v1/query_range?query=` + url.QueryEscape(`{a="b"`), 400, "parse error at line 1, col 7"},
		{`/loki/api/v1/series`, 400, "at least one match[] argument must be provided"},
		{`/loki/api/v1/query_range?query=` + url.QueryEscape(`count_over_time({a="b"}[1m]) by (x)`), 400, "grouping not allowed for count_over_time aggregation"},
		{`/api/prom/query?query=x`, 404, ""},
	}
	for _, c := range cases {
		code, body := get(t, s, c.path, nil)
		if code != c.code || !strings.Contains(body, c.msg) {
			t.Errorf("%s: %d %s", c.path, code, body)
		}
	}
}

func TestIntervalAndLabelsFromFields(t *testing.T) {
	lines := `{"_msg":"a","_stream":"{app=\"x\",pod=\"p\"}","_time":"2024-01-01T00:00:00Z","app":"x","pod":"p"}
{"_msg":"b","_stream":"{app=\"x\",pod=\"p\"}","_time":"2024-01-01T00:00:10Z","app":"x","pod":"p"}
{"_msg":"c","_stream":"{app=\"x\",pod=\"p\"}","_time":"2024-01-01T00:01:05Z","app":"x"}
`
	s, f := newTestServer(t, map[string]string{"/vl/select/logsql/query": lines})
	_, body := get(t, s, `/loki/api/v1/query_range?direction=forward&interval=1m&start=1704067200&end=1704067500&query=`+url.QueryEscape(`{app="x"} | drop pod`),
		map[string]string{"X-Loki-Response-Encoding-Flags": "categorize-labels"})
	want := `{"status":"success","data":{"resultType":"streams","encodingFlags":["categorize-labels"],"result":[` +
		`{"stream":{"app":"x","pod":"p"},"values":[["1704067200000000000","a",{}]]},` +
		`{"stream":{"app":"x"},"values":[["1704067265000000000","c",{}]]}]}}`
	if noStats(body) != want {
		t.Errorf("got\n%s\nwant\n%s", body, want)
	}
	if _, form := f.last(); form.Get("query") != `{app="x"} | delete pod | sort by (_time) limit 100` {
		t.Errorf("query: %s", form.Get("query"))
	}
}

func TestBinaryOperationsAndAbsent(t *testing.T) {
	vl := `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"v"},"value":[1704067200,"6"]}]}}`
	s, _ := newTestServer(t, map[string]string{"/vl/select/logsql/stats_query": vl})
	for q, want := range map[string]string{
		`sum(count_over_time({a="b"}[1m])) / sum(count_over_time({a="c"}[1m]))`: `[{"metric":{},"value":[1704067200,"1"]}]`,
		`sum(count_over_time({a="b"}[1m])) or vector(0)`:                        `[{"metric":{},"value":[1704067200,"6"]}]`,
		`sum(count_over_time({a="b"}[1m])) > bool vector(10)`:                   `[{"metric":{},"value":[1704067200,"0"]}]`,
		`absent_over_time({a="b"}[1m])`:                                         `[]`,
	} {
		_, body := get(t, s, `/loki/api/v1/query?time=1704067200&query=`+url.QueryEscape(q), nil)
		if !strings.Contains(body, `"result":`+want) {
			t.Errorf("%s: %s", q, body)
		}
	}
	empty := `{"status":"success","data":{"resultType":"vector","result":[]}}`
	s2, _ := newTestServer(t, map[string]string{"/vl/select/logsql/stats_query": empty})
	_, body := get(t, s2, `/loki/api/v1/query?time=1704067200&query=`+url.QueryEscape(`absent_over_time({a="b", c!="d"}[1m])`), nil)
	if !strings.Contains(body, `"result":[{"metric":{"a":"b"},"value":[1704067200,"1"]}]`) {
		t.Errorf("absent: %s", body)
	}
	_, body = get(t, s2, `/loki/api/v1/query?time=1704067200&query=1%2B1`, nil)
	if !strings.Contains(body, `"resultType":"scalar","result":[1704067200,"2"]`) {
		t.Errorf("scalar: %s", body)
	}
}

func TestPatternsUseLokiPlaceholders(t *testing.T) {
	top := `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"v","_msg":"GET /u/<N> took <N>ms"},"value":[1704067200,"3"]},{"metric":{"__name__":"v","_msg":"GET /u/<UUID> took <N>ms"},"value":[1704067200,"2"]}]}}`
	rng := `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"v","_msg":"GET /u/<N> took <N>ms"},"values":[[1704067200,"3"]]},{"metric":{"__name__":"v","_msg":"GET /u/<UUID> took <N>ms"},"values":[[1704067200,"2"]]}]}}`
	s, _ := newTestServer(t, map[string]string{"/vl/select/logsql/stats_query": top, "/vl/select/logsql/stats_query_range": rng})
	_, body := get(t, s, `/loki/api/v1/patterns?step=60s&start=1704067200&end=1704067260&query=`+url.QueryEscape(`{a="b"}`), nil)
	if body != `{"status":"success","data":[{"pattern":"GET /u/<_> took <_>ms","samples":[[1704067260,5]]}]}` {
		t.Errorf("patterns: %s", body)
	}
}

func TestVolumeAggregateByLabels(t *testing.T) {
	vl := `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"l0"},"value":[1704067200,"7"]},{"metric":{"__name__":"l1"},"value":[1704067200,"3"]}]}}`
	s, f := newTestServer(t, map[string]string{"/vl/select/logsql/stats_query": vl})
	_, body := get(t, s, `/loki/api/v1/index/volume?aggregateBy=labels&query=`+url.QueryEscape(`{service_name=~".+", pod=~".+"}`), nil)
	if !strings.Contains(body, `"result":[{"metric":{"service_name":""},"value":[`) || !strings.Contains(body, `{"metric":{"pod":""}`) {
		t.Errorf("volume: %s", body)
	}
	if _, form := f.last(); form.Get("query") != `{service.name=~".+",pod=~".+"} | stats count() if (service.name:*) as l0, count() if (pod:*) as l1` {
		t.Errorf("query: %s", form.Get("query"))
	}
}

func TestSlideWindow(t *testing.T) {
	pts := []point{{60, 1}, {120, 2}, {300, 4}}
	got := slideWindow(pts, translate.SlideSum, 60, 180)
	want := []point{{60, 1}, {120, 3}, {180, 3}, {240, 2}, {300, 4}, {360, 4}, {420, 4}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestParseLokiTime(t *testing.T) {
	for in, want := range map[string]int64{
		"1704067200":           1704067200e9,
		"1704067200.5":         1704067200.5e9,
		"1704067200000000000":  1704067200e9,
		"2024-01-01T00:00:00Z": 1704067200e9,
	} {
		got, err := parseLokiTime(in, timeZero)
		if err != nil || got.UnixNano() != want {
			t.Errorf("%s: %v %v", in, got.UnixNano(), err)
		}
	}
}

// BenchmarkStreamEncoder measures the per-line cost of converting a
// VictoriaLogs JSON line into a Loki stream entry.
func BenchmarkStreamEncoder(b *testing.B) {
	line := []byte(`{"_msg":"GET /api/v1/users 200 12ms","_stream":"{service.name=\"api\",pod=\"p1\"}","_stream_id":"0000000000000000a67ab97eb264323c","_time":"2026-11-25T22:41:40.123456789Z","level":"info","service.name":"api","pod":"p1","trace.id":"4bf92f3577b34da6a3ce929d0e0e4736"}`)
	enc := newStreamEncoder([]string{"level", "severity_text"}, true)
	enc.normalize = true
	out := make([]byte, 0, 64<<10)
	b.ReportAllocs()
	b.SetBytes(int64(len(line)))
	for i := 0; i < b.N; i++ {
		out = enc.appendEntry(out[:0], line)
	}
}
