package proxy

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Justereseau/loki-vl-proxy/internal/lokijson"
)

// nameCache maps sanitized Loki label names (service_name) back to the
// VictoriaLogs field names they came from (service.name), per tenant.
//
// Loki label names must match [a-zA-Z_][a-zA-Z0-9_]*, while VictoriaLogs
// fields commonly use OpenTelemetry dotted names. Responses expose sanitized
// names; queries are translated back using this cache. Exact names always win
// over sanitized aliases, so a real `service_name` field is never shadowed.
type nameCache struct {
	ttl   time.Duration
	fetch func(ctx context.Context, t tenantID) ([]string, error)

	mu      sync.Mutex
	tenants map[string]*tenantNames
}

type tenantNames struct {
	mu       sync.RWMutex
	m        map[string]string
	native   map[string]bool // fields stored natively (seen without pipes)
	loaded   time.Time
	inflight chan struct{} // closed when the running refresh completes
}

func newNameCache(ttl time.Duration, fetch func(context.Context, tenantID) ([]string, error)) *nameCache {
	return &nameCache{ttl: ttl, fetch: fetch, tenants: map[string]*tenantNames{}}
}

func (c *nameCache) get(t tenantID) *tenantNames {
	c.mu.Lock()
	defer c.mu.Unlock()
	tn := c.tenants[t.key()]
	if tn == nil {
		tn = &tenantNames{m: map[string]string{}, native: map[string]bool{}}
		c.tenants[t.key()] = tn
	}
	return tn
}

// mayBeSanitized reports whether name could be the sanitized form of another name.
func mayBeSanitized(name string) bool { return strings.IndexByte(name, '_') >= 0 }

func (c *nameCache) resolve(ctx context.Context, t tenantID, name string) string {
	if !mayBeSanitized(name) {
		return name
	}
	tn := c.get(t)
	tn.mu.RLock()
	v, ok := tn.m[name]
	loaded := tn.loaded
	tn.mu.RUnlock()
	if ok {
		if time.Since(loaded) > c.ttl {
			go c.refresh(t, tn) //nolint:gosec // G118: background refresh must outlive the request that noticed the stale cache
		}
		return v
	}
	if time.Since(loaded) > c.ttl/10 {
		// unknown name: refresh synchronously (rate limited) and retry
		c.refreshCtx(ctx, t, tn, true)
		tn.mu.RLock()
		v, ok = tn.m[name]
		tn.mu.RUnlock()
		if ok {
			return v
		}
	}
	return name
}

func (c *nameCache) refresh(t tenantID, tn *tenantNames) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c.refreshCtx(ctx, t, tn, false)
}

// refreshCtx reloads the field names of a tenant. Concurrent callers share a
// single upstream request; with wait they block until it completes.
func (c *nameCache) refreshCtx(ctx context.Context, t tenantID, tn *tenantNames, wait bool) {
	tn.mu.Lock()
	if ch := tn.inflight; ch != nil {
		tn.mu.Unlock()
		if wait {
			select {
			case <-ch:
			case <-ctx.Done():
			}
		}
		return
	}
	if time.Since(tn.loaded) <= c.ttl/10 {
		tn.mu.Unlock()
		return
	}
	ch := make(chan struct{})
	tn.inflight = ch
	tn.mu.Unlock()
	defer func() {
		tn.mu.Lock()
		tn.inflight = nil
		tn.mu.Unlock()
		close(ch)
	}()

	names, err := c.fetch(ctx, t)
	tn.mu.Lock()
	tn.loaded = time.Now() // also on error, to rate-limit retries
	tn.mu.Unlock()
	if err == nil {
		c.learn(t, names...)
		c.learnNative(t, names...)
	}
}

// learnNative records fields that exist natively in VictoriaLogs.
func (c *nameCache) learnNative(t tenantID, names ...string) {
	tn := c.get(t)
	tn.mu.Lock()
	for _, n := range names {
		tn.native[n] = true
	}
	tn.mu.Unlock()
}

// isNative reports whether a field is stored natively. Unknown state (no
// successful fetch yet) is treated as native, which keeps the fast path.
func (c *nameCache) isNative(ctx context.Context, t tenantID, field string) bool {
	tn := c.get(t)
	tn.mu.RLock()
	loaded, n, ok := tn.loaded, len(tn.native), tn.native[field]
	tn.mu.RUnlock()
	if loaded.IsZero() {
		c.refreshCtx(ctx, t, tn, true)
		tn.mu.RLock()
		n, ok = len(tn.native), tn.native[field]
		tn.mu.RUnlock()
	} else if time.Since(loaded) > c.ttl {
		go c.refresh(t, tn) //nolint:gosec // G118: background refresh must outlive the request that noticed the stale cache
	}
	return ok || n == 0
}

// learn records VictoriaLogs field names seen in responses.
func (c *nameCache) learn(t tenantID, names ...string) {
	if len(names) == 0 {
		return
	}
	tn := c.get(t)
	tn.mu.Lock()
	defer tn.mu.Unlock()
	for _, n := range names {
		if lokijson.LabelNameOK(n) {
			if mayBeSanitized(n) {
				tn.m[n] = n
			}
			continue
		}
		s := lokijson.SanitizeLabelName(n)
		if cur, ok := tn.m[s]; !ok || cur != s {
			tn.m[s] = n
		}
	}
}

// fetchNames loads field names seen recently for a tenant.
func (s *Server) fetchNames(ctx context.Context, t tenantID) ([]string, error) {
	form := url.Values{
		"query": {"*"},
		"start": {vlTime(time.Now().Add(-time.Hour))},
		"end":   {vlTime(time.Now())},
	}
	var resp valuesResponse
	if err := s.getJSON(ctx, nil, t, "/select/logsql/field_names", form, &resp); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(resp.Values))
	for _, v := range resp.Values {
		out = append(out, v.Value)
	}
	return out, nil
}
