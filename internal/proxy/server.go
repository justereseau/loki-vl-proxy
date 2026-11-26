// Package proxy implements the Loki-compatible HTTP API on top of VictoriaLogs.
package proxy

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
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

// Config is the proxy configuration.
type Config struct {
	Upstream *url.URL
	// QueryTimeout bounds every upstream request (0 = no limit).
	QueryTimeout time.Duration
	// LevelFields are mapped to Loki's detected_level.
	LevelFields []string
	// IgnoreParsers drops | json / | logfmt stages (fields are already stored).
	IgnoreParsers bool
	// NormalizeLevels maps raw level values to Loki's detected_level values.
	NormalizeLevels bool
	// DefaultTenant is used when X-Scope-OrgID is missing ("" = VictoriaLogs default 0:0).
	DefaultTenant string
	// TenantMap maps non-numeric Loki tenant names to "accountID:projectID".
	TenantMap map[string]string
	// ForwardAuthorization forwards the client Authorization header upstream.
	ForwardAuthorization bool
	// UpstreamAuthorization is a static Authorization header for upstream (basic or bearer).
	UpstreamAuthorization string
	// MaxLimit caps the number of log lines per query.
	MaxLimit int
	// Patterns enables the best-effort /patterns implementation.
	Patterns bool
	// IndexStatsBytes computes `bytes` in /index/stats (reads every log message).
	IndexStatsBytes bool
	// LokiVersion is reported by /status/buildinfo; Grafana enables features based on it.
	LokiVersion string
	// Version of this proxy.
	Version string
	// NameCacheTTL controls how often field names are refreshed to map
	// sanitized Loki label names (service_name) back to VictoriaLogs names (service.name).
	NameCacheTTL time.Duration
	Logger       *slog.Logger
	// Transport overrides the upstream transport (tests).
	Transport http.RoundTripper
}

// Server serves the Loki API.
type Server struct {
	cfg    Config
	client *http.Client
	names  *nameCache
	mux    *http.ServeMux
	log    *slog.Logger
}

// New creates a Server.
func New(cfg Config) *Server {
	if cfg.MaxLimit <= 0 {
		cfg.MaxLimit = 5000
	}
	if cfg.LokiVersion == "" {
		cfg.LokiVersion = "3.5.0"
	}
	if cfg.NameCacheTTL <= 0 {
		cfg.NameCacheTTL = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	tr := cfg.Transport
	if tr == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.MaxIdleConns = 256
		t.MaxIdleConnsPerHost = 256
		t.IdleConnTimeout = 90 * time.Second
		// The proxy usually runs next to VictoriaLogs: skip gzip to save CPU.
		t.DisableCompression = true
		tr = t
	}
	s := &Server{
		cfg:    cfg,
		client: &http.Client{Transport: tr},
		log:    cfg.Logger,
		mux:    http.NewServeMux(),
	}
	s.names = newNameCache(cfg.NameCacheTTL, s.fetchNames)
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) routes() {
	h := func(pattern string, fn func(w http.ResponseWriter, r *http.Request) error) {
		s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			err := fn(w, r)
			if err != nil {
				s.writeError(w, r, err)
			}
			s.log.Debug("request", "path", r.URL.Path, "duration", time.Since(start), "err", err)
		})
	}
	// Query endpoints of https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-endpoints
	h("/loki/api/v1/query_range", s.handleQueryRange)
	h("/loki/api/v1/query", s.handleQuery)
	h("/loki/api/v1/labels", s.handleLabels)
	h("/loki/api/v1/label", s.handleLabels) // undocumented alias still served by Loki
	h("/loki/api/v1/label/{name}/values", s.handleLabelValues)
	h("/loki/api/v1/series", s.handleSeries)
	h("/loki/api/v1/index/stats", s.handleIndexStats)
	h("/loki/api/v1/index/volume", s.handleVolume)
	h("/loki/api/v1/index/volume_range", s.handleVolumeRange)
	h("/loki/api/v1/detected_fields", s.handleDetectedFields)
	h("/loki/api/v1/detected_field/{name}/values", s.handleDetectedFieldValues)
	h("/loki/api/v1/detected_labels", s.handleDetectedLabels)
	h("/loki/api/v1/patterns", s.handlePatterns)
	h("/loki/api/v1/drilldown-limits", s.handleDrilldownLimits)
	h("/loki/api/v1/status/buildinfo", s.handleBuildInfo)
	h("/loki/api/v1/format_query", s.handleFormatQuery)
	h("/loki/api/v1/tail", s.handleTail)
	s.mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ready\n")
	})
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "404 page not found: "+r.URL.Path+" is not implemented by loki-vl-proxy", http.StatusNotFound)
	})
}

// statusError carries an HTTP status code.
type statusError struct {
	code int
	msg  string
}

func (e *statusError) Error() string { return e.msg }

func httpError(code int, format string, args ...any) error {
	return &statusError{code: code, msg: fmt.Sprintf(format, args...)}
}

func badRequest(err error) error {
	return &statusError{code: http.StatusBadRequest, msg: err.Error()}
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	code := http.StatusInternalServerError
	var se *statusError
	if errors.As(err, &se) {
		code = se.code
	} else if errors.Is(err, errClientGone) || r.Context().Err() != nil {
		return
	}
	if code >= 500 {
		s.log.Warn("request failed", "path", r.URL.Path, "status", code, "err", err)
	}
	// Loki returns plain-text errors; Grafana displays the body.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = io.WriteString(w, err.Error())
}

var errClientGone = errors.New("client went away")

// translateOptions returns translation options bound to the request tenant.
func (s *Server) translateOptions(r *http.Request, tenant tenantID) *translate.Options {
	return &translate.Options{
		LevelFields:     s.cfg.LevelFields,
		IgnoreParsers:   s.cfg.IgnoreParsers,
		NormalizeLevels: s.cfg.NormalizeLevels,
		ResolveName: func(n string) string {
			return s.names.resolve(r.Context(), tenant, n)
		},
		IsNative: func(f string) bool {
			return s.names.isNative(r.Context(), tenant, f)
		},
	}
}

// --- request parameter helpers (Loki semantics) ---

const defaultLookback = time.Hour

// parseLokiTime implements Loki's timestamp parsing: fractional Unix seconds,
// integer Unix seconds (<= 10 digits) or nanoseconds, or RFC3339(Nano).
func parseLokiTime(v string, def time.Time) (time.Time, error) {
	if v == "" {
		return def, nil
	}
	if strings.Contains(v, ".") {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			sec, frac := math.Modf(f)
			return time.Unix(int64(sec), int64(frac*1e9)), nil
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return time.Time{}, fmt.Errorf("cannot parse %q as a timestamp", v)
		}
		return t, nil
	}
	if len(v) <= 10 {
		return time.Unix(n, 0), nil
	}
	return time.Unix(0, n), nil
}

// parseLokiDuration accepts "15s", "1m" or a plain number of seconds.
func parseLokiDuration(v string) (time.Duration, error) {
	return logql.ParseDuration(v)
}

// Default lookbacks documented in the Loki HTTP API reference.
const (
	labelsLookback = 6 * time.Hour // /labels, /label/<name>/values
)

func timeRange(r *http.Request) (start, end time.Time, err error) {
	return timeRangeDefault(r, defaultLookback)
}

// timeRangeDefault implements Loki's start/end/since parameters: `since` is
// relative to `end`, or to now when `end` is in the future; `start` wins.
func timeRangeDefault(r *http.Request, lookback time.Duration) (start, end time.Time, err error) {
	now := time.Now()
	if end, err = parseLokiTime(r.Form.Get("end"), now); err != nil {
		return
	}
	ref := end
	if ref.After(now) {
		ref = now
	}
	def := ref.Add(-lookback)
	if since := r.Form.Get("since"); since != "" {
		d, derr := parseLokiDuration(since)
		if derr != nil {
			return start, end, derr
		}
		def = ref.Add(-d)
	}
	if start, err = parseLokiTime(r.Form.Get("start"), def); err != nil {
		return
	}
	if end.Before(start) {
		err = fmt.Errorf("end timestamp must not be before start time")
	}
	return
}

func vlTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func vlDuration(d time.Duration) string {
	if d%time.Millisecond == 0 {
		return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
	}
	return strconv.FormatInt(d.Nanoseconds(), 10) + "ns"
}

func parseForm(r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return badRequest(err)
	}
	return nil
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 0, 64<<10); return &b }}

func getBuf() *[]byte { return bufPool.Get().(*[]byte) }
func putBuf(b *[]byte) {
	if cap(*b) > 4<<20 { // do not keep huge buffers around
		return
	}
	*b = (*b)[:0]
	bufPool.Put(b)
}

func writeJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(body)
}
