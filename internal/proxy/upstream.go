package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// tenantID is a VictoriaLogs tenant ("accountID:projectID"); empty = default tenant.
type tenantID struct {
	account, project string
}

func (t tenantID) key() string { return t.account + ":" + t.project }

// tenant maps the Loki X-Scope-OrgID header to a VictoriaLogs tenant.
// Accepted forms: "12", "12:34" or a name listed in the tenant map.
func (s *Server) tenant(r *http.Request) (tenantID, error) {
	org := strings.TrimSpace(r.Header.Get("X-Scope-OrgID"))
	if org == "" {
		org = s.cfg.DefaultTenant
	}
	if org == "" {
		return tenantID{}, nil
	}
	if strings.Contains(org, "|") {
		return tenantID{}, httpError(http.StatusBadRequest, "multi-tenant queries (%q) are not supported", org)
	}
	if mapped, ok := s.cfg.TenantMap[org]; ok {
		org = mapped
	}
	acc, proj, _ := strings.Cut(org, ":")
	if proj == "" {
		proj = "0"
	}
	if _, err := strconv.ParseUint(acc, 10, 32); err != nil {
		return tenantID{}, httpError(http.StatusBadRequest, "tenant %q is not numeric and not listed in -tenant-map", org)
	}
	if _, err := strconv.ParseUint(proj, 10, 32); err != nil {
		return tenantID{}, httpError(http.StatusBadRequest, "invalid projectID in tenant %q", org)
	}
	return tenantID{account: acc, project: proj}, nil
}

// do sends a form-encoded POST to VictoriaLogs and returns the response with a
// 2xx status. Long LogsQL queries never hit URL length limits this way.
func (s *Server) do(ctx context.Context, in *http.Request, tenant tenantID, path string, form url.Values) (*http.Response, error) {
	u := *s.cfg.Upstream
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	if s.cfg.QueryTimeout > 0 && path != "/select/logsql/tail" {
		// documented `timeout` arg: VictoriaLogs stops the query on its side too
		form.Set("timeout", vlDuration(s.cfg.QueryTimeout))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if tenant.account != "" {
		req.Header.Set("AccountID", tenant.account)
		req.Header.Set("ProjectID", tenant.project)
	}
	switch {
	case s.cfg.UpstreamAuthorization != "":
		req.Header.Set("Authorization", s.cfg.UpstreamAuthorization)
	case s.cfg.ForwardAuthorization && in != nil && in.Header.Get("Authorization") != "":
		req.Header.Set("Authorization", in.Header.Get("Authorization"))
	}
	if s.cfg.Upstream.User != nil && req.Header.Get("Authorization") == "" {
		pw, _ := s.cfg.Upstream.User.Password()
		req.SetBasicAuth(s.cfg.Upstream.User.Username(), pw)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, httpError(http.StatusGatewayTimeout, "upstream query timed out")
			}
			return nil, errClientGone
		}
		return nil, httpError(http.StatusBadGateway, "upstream request failed: %v", err)
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		msg := strings.TrimSpace(string(b))
		code := http.StatusBadGateway
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnprocessableEntity {
			code = http.StatusBadRequest
		}
		return nil, &statusError{code: code, msg: fmt.Sprintf("victorialogs %s: %s", path, msg)}
	}
	return resp, nil
}

// getJSON performs an upstream call and decodes a JSON response.
func (s *Server) getJSON(ctx context.Context, in *http.Request, tenant tenantID, path string, form url.Values, dst any) error {
	resp, err := s.do(ctx, in, tenant, path, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		if ctx.Err() != nil {
			return errClientGone
		}
		return httpError(http.StatusBadGateway, "cannot decode %s response: %v", path, err)
	}
	return nil
}

// ctx returns the request context bounded by the query timeout.
func (s *Server) ctx(r *http.Request) (context.Context, context.CancelFunc) {
	if s.cfg.QueryTimeout > 0 {
		return context.WithTimeout(r.Context(), s.cfg.QueryTimeout)
	}
	return context.WithCancel(r.Context())
}

// valuesResponse is the {"values":[{"value":..,"hits":..}]} shape shared by
// field_names, field_values, stream_field_names, stream_field_values and streams.
type valuesResponse struct {
	Values []struct {
		Value string `json:"value"`
		Hits  uint64 `json:"hits"`
	} `json:"values"`
}
