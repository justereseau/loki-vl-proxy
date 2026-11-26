// Command loki-vl-proxy exposes a Loki-compatible HTTP API on top of VictoriaLogs.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Justereseau/loki-vl-proxy/internal/proxy"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const envPrefix = "LOKI_VL_PROXY_"

func main() {
	fs := flag.NewFlagSet("loki-vl-proxy", flag.ExitOnError)
	var (
		listen          = fs.String("listen", ":3100", "address to listen on")
		upstream        = fs.String("upstream", "http://localhost:9428", "VictoriaLogs base URL (may include a path prefix and user:password)")
		queryTimeout    = fs.Duration("query-timeout", 2*time.Minute, "timeout for upstream queries (0 = none)")
		idleTimeout     = fs.Duration("idle-timeout", 2*time.Minute, "keep-alive timeout for client connections")
		levelFields     = fs.String("level-fields", "level,severity_text,severity", "comma-separated VictoriaLogs fields exposed as detected_level (first non-empty wins; empty disables)")
		normalizeLvls   = fs.Bool("normalize-levels", true, "normalize detected_level values like Loki (ERR -> error, Warning -> warn, unknown values -> unknown)")
		ignoreParsers   = fs.Bool("ignore-parsers", false, "drop | json, | logfmt and | unpack stages: use when fields are stored natively in VictoriaLogs (faster)")
		defaultTenant   = fs.String("default-tenant", "", "tenant (accountID[:projectID]) used when X-Scope-OrgID is missing")
		tenantMap       = fs.String("tenant-map", "", "comma-separated name=accountID:projectID mappings for non-numeric X-Scope-OrgID values")
		forwardAuth     = fs.Bool("forward-authorization", false, "forward the client Authorization header to VictoriaLogs")
		upstreamAuth    = fs.String("upstream-authorization", "", "static Authorization header value sent to VictoriaLogs (e.g. 'Bearer xyz')")
		maxLimit        = fs.Int("max-limit", 5000, "maximum number of log lines returned per query")
		indexStatsBytes = fs.Bool("index-stats-bytes", false, "compute bytes in /index/stats (reads every matching log message; Loki reads it from its index)")
		patterns        = fs.Bool("patterns", true, "enable the best-effort /patterns endpoint (scans log messages)")
		lokiVersion     = fs.String("loki-version", "3.5.0", "Loki version reported by /status/buildinfo")
		nameCacheTTL    = fs.Duration("name-cache-ttl", 5*time.Minute, "refresh interval of the field-name cache used to map service_name back to service.name")
		logLevel        = fs.String("log-level", "info", "log level: debug, info, warn, error")
		showVersion     = fs.Bool("version", false, "print version and exit")
	)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage of loki-vl-proxy:\n\nEvery flag can also be set with an environment variable, e.g. -query-timeout as %sQUERY_TIMEOUT.\n\n", envPrefix)
		fs.PrintDefaults()
	}
	// environment variables first, command-line flags override them
	fs.VisitAll(func(f *flag.Flag) {
		env := envPrefix + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := os.LookupEnv(env); ok {
			if err := f.Value.Set(v); err != nil {
				fmt.Fprintf(os.Stderr, "invalid %s: %v\n", env, err)
				os.Exit(2)
			}
		}
	})
	_ = fs.Parse(os.Args[1:])
	if *showVersion {
		fmt.Println(version)
		return
	}

	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(*logLevel)); err != nil {
		fmt.Fprintf(os.Stderr, "invalid -log-level: %v\n", err)
		os.Exit(2)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	u, err := url.Parse(*upstream)
	if err != nil || u.Scheme == "" || u.Host == "" {
		logger.Error("invalid -upstream", "value", *upstream)
		os.Exit(2)
	}
	tm, err := parseTenantMap(*tenantMap)
	if err != nil {
		logger.Error("invalid -tenant-map", "err", err)
		os.Exit(2)
	}

	srv := proxy.New(proxy.Config{
		Upstream:              u,
		QueryTimeout:          *queryTimeout,
		LevelFields:           splitList(*levelFields),
		IgnoreParsers:         *ignoreParsers,
		NormalizeLevels:       *normalizeLvls,
		DefaultTenant:         *defaultTenant,
		TenantMap:             tm,
		ForwardAuthorization:  *forwardAuth,
		UpstreamAuthorization: *upstreamAuth,
		MaxLimit:              *maxLimit,
		Patterns:              *patterns,
		IndexStatsBytes:       *indexStatsBytes,
		LokiVersion:           *lokiVersion,
		Version:               version,
		NameCacheTTL:          *nameCacheTTL,
		Logger:                logger,
	})

	hs := &http.Server{
		Addr:              *listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       *idleTimeout,
		MaxHeaderBytes:    1 << 20,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	logger.Info("starting loki-vl-proxy", "version", version, "listen", *listen, "upstream", u.Redacted())
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server failed", "err", err)
		os.Exit(1)
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseTenantMap(s string) (map[string]string, error) {
	m := map[string]string{}
	for _, kv := range splitList(s) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("expected name=accountID:projectID, got %q", kv)
		}
		m[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return m, nil
}
