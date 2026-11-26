package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestE2E runs the main Grafana / Logs Drilldown requests against a real
// VictoriaLogs instance. It is skipped unless LOKI_VL_PROXY_E2E_URL is set:
//
//	LOKI_VL_PROXY_E2E_URL=http://localhost:9428 go test -run E2E -v ./internal/proxy/
//
// LOKI_VL_PROXY_E2E_CA optionally points to a PEM bundle for HTTPS upstreams.
// LOKI_VL_PROXY_E2E_SELECTOR sets the stream selector used for log queries.
func TestE2E(t *testing.T) {
	raw := os.Getenv("LOKI_VL_PROXY_E2E_URL")
	if raw == "" {
		t.Skip("LOKI_VL_PROXY_E2E_URL not set")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Upstream: u, Patterns: true, LevelFields: []string{"level", "severity_text"}, NormalizeLevels: true, QueryTimeout: time.Minute}
	if ca := os.Getenv("LOKI_VL_PROXY_E2E_CA"); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
		cfg.Transport = tr
	}
	s := New(&cfg)
	end := time.Now()
	start := end.Add(-30 * time.Minute)
	se := "&start=" + strconv.FormatInt(start.UnixNano(), 10) + "&end=" + strconv.FormatInt(end.UnixNano(), 10)
	sel := os.Getenv("LOKI_VL_PROXY_E2E_SELECTOR")
	if sel == "" {
		sel = `{service_name=~".+"}`
	}
	q := url.QueryEscape

	call := func(t *testing.T, path string, hdr map[string]string) []byte {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		body, _ := io.ReadAll(rec.Body)
		if rec.Code != 200 {
			t.Fatalf("%s: status %d: %s", path, rec.Code, body)
		}
		if !json.Valid(body) {
			t.Fatalf("%s: invalid JSON: %.500s", path, body)
		}
		if testing.Verbose() {
			t.Logf("%s\n%.700s", path, body)
		}
		return body
	}

	steps := []struct {
		name, path string
		hdr        map[string]string
	}{
		{"buildinfo", "/loki/api/v1/status/buildinfo", nil},
		{"health check", "/loki/api/v1/query?query=" + q("vector(1)+vector(1)"), nil},
		{"labels", "/loki/api/v1/labels?" + se[1:], nil},
		{"label values", "/loki/api/v1/label/service_name/values?" + se[1:], nil},
		{"detected_level values", "/loki/api/v1/label/detected_level/values?" + se[1:], nil},
		{"series", "/loki/api/v1/series?match[]=" + q(sel) + se, nil},
		{"index stats", "/loki/api/v1/index/stats?query=" + q(sel) + se, nil},
		{"volume", "/loki/api/v1/index/volume?limit=5000&query=" + q(sel) + se, nil},
		{"volume range", "/loki/api/v1/index/volume_range?step=60s&query=" + q(sel) + se, nil},
		{"detected labels", "/loki/api/v1/detected_labels?query=" + se, nil},
		{"detected fields", "/loki/api/v1/detected_fields?query=" + q(sel+` | json | logfmt | drop __error__, __error_details__`) + se, nil},
		{"detected field values", "/loki/api/v1/detected_field/detected_level/values?query=" + q(sel) + se, nil},
		{"logs categorized", "/loki/api/v1/query_range?limit=20&direction=backward&query=" + q(sel+` | json | logfmt | drop __error__, __error_details__`) + se,
			map[string]string{"X-Loki-Response-Encoding-Flags": "categorize-labels"}},
		{"logs forward", "/loki/api/v1/query_range?limit=5&direction=forward&query=" + q(sel) + se, nil},
		{"service volume by level", "/loki/api/v1/query_range?step=60s&query=" + q(`sum by (detected_level) (count_over_time(`+sel+` [1m]))`) + se, nil},
		{"rate sliding", "/loki/api/v1/query_range?step=60s&query=" + q(`sum by (service_name) (rate(`+sel+` [5m]))`) + se, nil},
		{"topk", "/loki/api/v1/query_range?step=300s&query=" + q(`topk(3, sum by (service_name) (count_over_time(`+sel+` [5m])))`) + se, nil},
		{"instant", "/loki/api/v1/query?query=" + q(`sum by (service_name) (count_over_time(`+sel+` [30m]))`) + "&time=" + strconv.FormatInt(end.Unix(), 10), nil},
		{"patterns", "/loki/api/v1/patterns?step=60s&query=" + q(sel) + se, nil},
		{"drilldown limits", "/loki/api/v1/drilldown-limits", nil},
		{"binary op", "/loki/api/v1/query_range?step=60s&query=" + q(`sum(count_over_time(`+sel+` [1m])) / sum(count_over_time(`+sel+` [1m])) or vector(0)`) + se, nil},
		{"absent", "/loki/api/v1/query?query=" + q(`absent_over_time({service_name="does-not-exist"}[5m])`), nil},
		{"volume by labels", "/loki/api/v1/index/volume?aggregateBy=labels&query=" + q(sel) + se, nil},
		{"interval", "/loki/api/v1/query_range?limit=50&interval=30s&query=" + q(sel) + se, nil},
		{"detected field values", "/loki/api/v1/detected_field/detected_level/values?query=" + q(sel) + se, nil},
	}
	t.Run("step_grid_alignment", func(t *testing.T) {
		// start deliberately not aligned to the step: Loki evaluates at start + k*step
		st := start.Truncate(time.Minute).Add(17 * time.Second)
		// end is extended so that a grid point follows the most recent logs
		// (CI ingests all its sample data just before the test runs)
		body := call(t, "/loki/api/v1/query_range?step=60s&start="+strconv.FormatInt(st.UnixNano(), 10)+"&end="+strconv.FormatInt(end.Add(2*time.Minute).UnixNano(), 10)+
			"&query="+q(`sum(count_over_time(`+sel+` [1m]))`), nil)
		var resp struct {
			Data struct {
				Result []struct {
					Values [][2]any `json:"values"`
				} `json:"result"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, r := range resp.Data.Result {
			for _, v := range r.Values {
				ts := int64(math.Round(v[0].(float64) * 1000))
				if (ts-st.UnixMilli())%60000 != 0 {
					t.Fatalf("timestamp %d is not on the start+k*step grid (start %d)", ts, st.Unix())
				}
				n++
			}
		}
		if n == 0 {
			t.Fatal("no samples")
		}
	})
	for _, st := range steps {
		t.Run(strings.ReplaceAll(st.name, " ", "_"), func(t *testing.T) {
			call(t, st.path, st.hdr)
		})
	}
}
