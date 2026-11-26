# loki-vl-proxy

A small, fast proxy that exposes a **Loki-compatible HTTP API on top of
[VictoriaLogs](https://docs.victoriametrics.com/victorialogs/)**, so that Grafana's
**Logs Drilldown** app, Explore and the regular Loki data source work against
VictoriaLogs without any Grafana plugin.

```
Grafana (Loki data source, Logs Drilldown) ──Loki API──▶ loki-vl-proxy ──LogsQL──▶ VictoriaLogs
```

- Translates LogQL to LogsQL (stream selectors, line filters, parsers, label
  filters, `drop`/`keep`, formatting, and metric queries such as
  `count_over_time`, `rate`, `sum by`, `topk`, `quantile_over_time`).
- Implements every endpoint Logs Drilldown calls: services list, log volumes,
  logs, labels, fields, levels and patterns.
- Streams log responses: memory stays constant whatever the result size.
- Single static binary with no dependencies beyond the Go standard library;
  `FROM scratch` image (binary, CA certificates and a non-root user only).

## Why Go

The proxy is I/O-bound glue between two HTTP APIs. Go gives a streaming HTTP
client and server in the standard library, cheap goroutines for concurrent
upstream calls, and a tiny static binary. It is also the language of both
VictoriaLogs and Loki, so their semantics are easy to cross-check (the CI
validates every generated LogsQL query with the real VictoriaLogs parser).
Rust could shave a few MB of RSS, but the hot path here is already
allocation-free:

| benchmark (Apple M-series, 1 core) | time / line | allocs |
|---|---|---|
| scan a VictoriaLogs JSON line | 186 ns | 0 |
| convert a line into a Loki stream entry | 340 ns (~780 MB/s) | 0 |

The container image is 7.5 MB (`scratch`, binary and CA certificates only), and the proxy idles at ~2.5 MiB RSS.

Efficiency choices:

- Log lines are scanned in place and written straight to the response.
  Already-escaped JSON strings are copied, never decoded and re-encoded.
  Buffers are pooled and flushed every 32 KB.
- `limit`, sorting and aggregation are pushed down to VictoriaLogs (`limit=`,
  `sort … limit`, `stats`). Additive aggregations are collapsed into a single
  `stats` pipe. Regexps like `a|b`, `.+` and `prefix.*` become `in()`, `*` and
  exact-prefix filters.
- Filters on native VictoriaLogs fields are placed before any `unpack_*` pipe,
  so they use the VictoriaLogs indexes even when the query contains `| json`.
- `detected_fields` samples the most recent lines like Loki does, instead of
  scanning the whole range.
- Upstream gzip is disabled by default (the proxy usually runs next to
  VictoriaLogs). Client cancellation aborts the upstream query.

## Quick start

```bash
docker compose -f deploy/compose/docker-compose.yml up -d --build
```

Then open Logs Drilldown at <http://localhost:3000/a/grafana-lokiexplore-app/explore>.
The stack runs VictoriaLogs, a log generator (structured, JSON, logfmt and
plain-text logs from four services), the proxy, and Grafana with the
provisioned data source.

To use an existing VictoriaLogs instead:

```bash
VL_URL=https://victorialogs.example.com docker compose -f deploy/compose/docker-compose.yml up -d --build loki-vl-proxy grafana
```

Standalone, with the multi-arch image (linux/amd64, linux/arm64):

```bash
docker run -p 3100:3100 ghcr.io/justereseau/loki-vl-proxy:latest -upstream http://victorialogs:9428
```

Or with a static binary from the [releases](https://github.com/justereseau/loki-vl-proxy/releases)
(Linux amd64 and arm64):

```bash
tar xzf loki-vl-proxy_<version>_linux_amd64.tar.gz
./loki-vl-proxy_<version>_linux_amd64/loki-vl-proxy -upstream http://localhost:9428
```

In Grafana, add a **Loki** data source with URL `http://loki-vl-proxy:3100`.

## Configuration

Every flag can also be set with an environment variable named
`LOKI_VL_PROXY_<FLAG>`, for example `-query-timeout` becomes
`LOKI_VL_PROXY_QUERY_TIMEOUT`.

| flag | default | description |
|---|---|---|
| `-listen` | `:3100` | listen address |
| `-upstream` | `http://localhost:9428` | VictoriaLogs URL; may include a path prefix (`https://host/vl`) and `user:password@` |
| `-query-timeout` | `2m` | upstream query timeout (0 = none) |
| `-level-fields` | `level,severity_text,severity` | fields exposed as `detected_level`; the first non-empty one wins |
| `-normalize-levels` | `true` | normalize levels like Loki (`ERR`→`error`, `Warning`→`warn`, unrecognized values→`unknown`) |
| `-ignore-parsers` | `false` | drop `\| json` / `\| logfmt` / `\| unpack` stages; faster when every field is stored natively |
| `-default-tenant` | | tenant used when `X-Scope-OrgID` is missing |
| `-tenant-map` | | `name=accountID:projectID,...` for non-numeric `X-Scope-OrgID` values |
| `-forward-authorization` | `false` | forward the client `Authorization` header upstream |
| `-upstream-authorization` | | static `Authorization` header for VictoriaLogs |
| `-max-limit` | `5000` | maximum log lines per query |
| `-patterns` | `true` | enable the best-effort `/patterns` endpoint |
| `-index-stats-bytes` | `false` | compute `bytes` in `/index/stats` (reads every matching message; Loki reads it from its index) |
| `-loki-version` | `3.5.0` | version reported to Grafana (it gates features) |
| `-name-cache-ttl` | `5m` | refresh interval of the field-name cache (see below) |
| `-log-level` | `info` | `debug`, `info`, `warn`, `error` |

### Multi-tenancy

`X-Scope-OrgID` is mapped to the VictoriaLogs `AccountID` / `ProjectID` headers:
`12` → `12:0`, `12:34` → `12:34`, and names go through `-tenant-map`. Multi-tenant
queries (`a|b`) are rejected.

### Field names

Loki label names must match `[a-zA-Z_][a-zA-Z0-9_]*`, while VictoriaLogs often
stores OpenTelemetry names such as `service.name`. The proxy exposes sanitized
names (`service_name`) and maps them back using a per-tenant cache of the
VictoriaLogs field names. Exact names always win, so a real `service_name`
field is never shadowed. Grafana's `service_name` primary label therefore works
with OTLP data out of the box.

## Compatibility matrix

The proxy follows the [Loki HTTP API reference](https://grafana.com/docs/loki/latest/reference/loki-http-api/) and the
[LogQL documentation](https://grafana.com/docs/loki/latest/query/) for requests and responses. Upstream, it only uses
the documented [VictoriaLogs querying API](https://docs.victoriametrics.com/victorialogs/querying/) and [LogsQL](https://docs.victoriametrics.com/victorialogs/logsql/). Every
place where the behaviour differs from Loki is listed under
[Differences from Loki](#differences-from-loki).

### HTTP endpoints

| Loki endpoint (reference section) | Status | VictoriaLogs API used |
|---|---|---|
| `GET/POST /loki/api/v1/query_range` ([Query logs within a range of time](https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-logs-within-a-range-of-time)) | ✅ `query`, `start`, `end`, `since`, `limit`, `direction`, `step`, `interval`; streamed `streams`, or `matrix` | [`/select/logsql/query`](https://docs.victoriametrics.com/victorialogs/querying/#querying-logs) with `limit` (backward) or `sort … limit` (forward); [`/select/logsql/stats_query_range`](https://docs.victoriametrics.com/victorialogs/querying/#querying-log-range-stats) with `step` and `offset` |
| `GET/POST /loki/api/v1/query` ([Query logs at a single point in time](https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-logs-at-a-single-point-in-time)) | ✅ `vector`, or `scalar` for scalar expressions; log queries are rejected with 400 as documented | [`/select/logsql/stats_query`](https://docs.victoriametrics.com/victorialogs/querying/#querying-log-stats) with `time`, `start`, `end` |
| `/loki/api/v1/labels` ([Query labels](https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-labels)) | ✅ `start` defaults to 6h ago, `query` optional | [`/select/logsql/stream_field_names`](https://docs.victoriametrics.com/victorialogs/querying/#querying-stream-field-names) with `ignore_pipes=1` |
| `/loki/api/v1/label/<name>/values` ([Query label values](https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-label-values)) | ✅ 6h default, `query` optional | [`stream_field_values`](https://docs.victoriametrics.com/victorialogs/querying/#querying-stream-field-values), falling back to [`field_values`](https://docs.victoriametrics.com/victorialogs/querying/#querying-field-values) |
| `/loki/api/v1/series` ([Query streams](https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-streams)) | ✅ at least one `match[]` required | [`/select/logsql/streams`](https://docs.victoriametrics.com/victorialogs/querying/#querying-streams) |
| `/loki/api/v1/index/stats` ([Query log statistics](https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-log-statistics)) | ✅ `streams`, `chunks` (= streams), `entries`; `bytes` only with `-index-stats-bytes` | `stats_query` with `count()`, `count_uniq(_stream_id)`, `sum_len(_msg)` |
| `/loki/api/v1/index/volume`, `/index/volume_range` ([Query log volume](https://grafana.com/docs/loki/latest/reference/loki-http-api/#query-log-volume)) | ✅ `targetLabels`, `aggregateBy=series\|labels`, `limit` (default 100), `step` | `stats_query` / `stats_query_range` |
| `/loki/api/v1/patterns` ([Patterns detection](https://grafana.com/docs/loki/latest/reference/loki-http-api/#patterns-detection)) | ⚠️ best effort, `<_>` placeholders | [`collapse_nums prettify`](https://docs.victoriametrics.com/victorialogs/logsql/#collapse_nums-pipe) + `stats_query[_range]` |
| `/loki/api/v1/detected_fields` ([Detected fields](https://grafana.com/docs/loki/latest/reference/loki-http-api/#detected-fields)) | ✅ `line_limit` (default 100), `limit`/`field_limit` (default 1000), `stats` | `/select/logsql/query` sample of the newest lines |
| `/loki/api/v1/detected_field/<name>/values` ([Detected field values](https://grafana.com/docs/loki/latest/reference/loki-http-api/#detected-field-values)) | ✅ `limit`/`field_limit`, `stats` | [`field_values`](https://docs.victoriametrics.com/victorialogs/querying/#querying-field-values) |
| `/loki/api/v1/detected_labels` | ✅ (not in the reference; used by Logs Drilldown) | `/select/logsql/streams` |
| `/loki/api/v1/tail` ([Stream logs](https://grafana.com/docs/loki/latest/reference/loki-http-api/#stream-logs)) | ✅ WebSocket; `query`, `delay_for` (≤ 5), `limit`, `start` | [`/select/logsql/tail`](https://docs.victoriametrics.com/victorialogs/querying/#live-tailing) with `start_offset`, `offset` |
| `/loki/api/v1/format_query` ([Format a LogQL query](https://grafana.com/docs/loki/latest/reference/loki-http-api/#format-a-logql-query)) | ⚠️ validates the query and returns it unchanged | |
| `/loki/api/v1/status/buildinfo` ([Show build information](https://grafana.com/docs/loki/latest/reference/loki-http-api/#show-build-information)) | ✅ `version` is `-loki-version` | |
| `/ready` ([Readiness probe](https://grafana.com/docs/loki/latest/reference/loki-http-api/#readiness-probe)) | ✅ | |
| `/loki/api/v1/drilldown-limits` | ✅ (Logs Drilldown configuration) | |
| `/loki/api/v1/push`, `/otlp/v1/logs` | ❌ ingest straight into VictoriaLogs (its `/insert/loki/api/v1/push` and OTLP endpoints) | |
| deprecated `/api/prom/*`, rules, deletes, ring, flush and config endpoints | ❌ 404 | |

Response conventions from the [Format](https://grafana.com/docs/loki/latest/reference/loki-http-api/#format) section:

- `{"status":"success","data":{"resultType":…,"result":…,"stats":…}}`.
- Log timestamps are nanosecond strings. Sample timestamps are Unix seconds,
  and sample values are strings.
- Stream values are sorted newest first for `backward` and oldest first for
  `forward`.
- The [`stats`](https://grafana.com/docs/loki/latest/reference/loki-http-api/#statistics) block has the documented layout. Only
  `summary.execTime` and `summary.totalEntriesReturned` are filled; the scan
  counters stay 0.
- `X-Loki-Response-Encoding-Flags: categorize-labels` is honoured: stream
  fields become stream labels, and other fields become
  `structuredMetadata`.
- Request timestamps accept nanosecond epochs, float seconds and RFC3339.
  Like Loki's parser, integers of 10 digits or fewer are read as seconds.
- Errors are plain-text bodies with Loki's status codes and messages, for
  example `parse error at line 1, col 7: …`, or `limit must be a positive value`.
- Multi-tenancy: `X-Scope-OrgID` maps to the VictoriaLogs `AccountID` / `ProjectID`
  [headers](https://docs.victoriametrics.com/victorialogs/querying/#querying-logs).

### LogQL ([log queries](https://grafana.com/docs/loki/latest/query/log_queries/), [metric queries](https://grafana.com/docs/loki/latest/query/metric_queries/))

| LogQL | LogsQL | Notes |
|---|---|---|
| `{a="b", c!="d", e=~"x.*", f!~"y"}` | `{a="b",c!="d",e=~"x.*",f!~"y"}` | [stream filter](https://docs.victoriametrics.com/victorialogs/logsql/#stream-filter); both anchor regexps |
| `\|= "x"` / `!= "x"` | `*"x"*` / `!*"x"*` | [substring filter](https://docs.victoriametrics.com/victorialogs/logsql/#substring-filter): exact Loki semantics |
| `\|~ "re"` / `!~ "re"` | `~"(?s)re"` / `!~"(?s)re"` | [regexp filter](https://docs.victoriametrics.com/victorialogs/logsql/#regexp-filter); `(?s)` because `.` matches newlines in LogQL line filters |
| `\|= "a" or "b"` | `(*"a"* or *"b"*)` | |
| `\|> "p"` / `!> "p"` | `pattern_match_full("p")` or anchored regexp | [pattern match filter](https://docs.victoriametrics.com/victorialogs/logsql/#pattern-match-filter) for `<N>`, `<UUID>`…; `<_>` uses a regexp |
| `\| json`, `\| logfmt` | `unpack_json` / `unpack_logfmt keep_original_fields` | [unpack_json](https://docs.victoriametrics.com/victorialogs/logsql/#unpack_json-pipe), [unpack_logfmt](https://docs.victoriametrics.com/victorialogs/logsql/#unpack_logfmt-pipe) |
| `\| json a="b.c"`, `\| logfmt a="k"` | `unpack_* fields (b.c) \| rename b.c as a` | |
| `\| unpack` | `unpack_json`, then `_entry` becomes the line | |
| `\| regexp "…"` | `extract_regexp` | [extract_regexp](https://docs.victoriametrics.com/victorialogs/logsql/#extract_regexp-pipe) |
| `\| pattern "…"` | `extract if (_msg:="prefix"*) …` | [extract](https://docs.victoriametrics.com/victorialogs/logsql/#extract-pipe), anchored at line start like Loki |
| `\| a="b"`, `!=`, `=~`, `!~` | `a:="b"`, `!a:="b"`, `in()`, `*`, exact prefix, or anchored regexp | [exact](https://docs.victoriametrics.com/victorialogs/logsql/#exact-filter), [multi-exact](https://docs.victoriametrics.com/victorialogs/logsql/#multi-exact-filter), [exact prefix](https://docs.victoriametrics.com/victorialogs/logsql/#exact-prefix-filter) |
| `\| d > 10s`, `\| size >= 1.5KiB`, `==`, `!=` | `d:>10s`, `size:>=1536`, `range[…]` | [range comparison](https://docs.victoriametrics.com/victorialogs/logsql/#range-comparison-filter); byte units become numbers |
| `\| a="x" or b="y"`, `and`, `,`, space | `(a:="x" or b:="y")`, implicit AND | `and` binds tighter than `or`, as in LogQL |
| `\| addr=ip("10.0.0.0/8")` | `addr:ipv4_range("10.0.0.0/8")` | [IPv4 range](https://docs.victoriametrics.com/victorialogs/logsql/#ipv4-range-filter) |
| `\| drop a, b="v"` / `\| keep a, b="v"` | `delete` / `fields` plus conditional `format` | output label sets are rebuilt from the returned fields |
| `\| line_format "{{.a}} {{__line__}}"` | `format "<a> <_msg>" as _msg` | [format](https://docs.victoriametrics.com/victorialogs/logsql/#format-pipe) |
| `\| label_format a=b`, `a="{{.x}}"` | `rename b as a`, `format` | |
| `\| decolorize` | `decolorize` | |
| `count_over_time`, `rate`, `bytes_over_time`, `bytes_rate` | `count()`, `sum_len(_msg)` | per stream: `stats by (_stream)`, expanded to labels |
| `sum/avg/min/max/stddev/stdvar/quantile_over_time(… \| unwrap [duration\|bytes](x))`, `rate(unwrap)` | `sum/avg/min/max/stddev/quantile(x)` | [stats functions](https://docs.victoriametrics.com/victorialogs/logsql/#stats-pipe-functions) |
| `absent_over_time` | `count()` + proxy | labels taken from the selector's `=` matchers |
| `sum/avg/min/max/count/stddev/stdvar by (…)` | `stats by (…)` | additive cases collapse into one `stats` pipe |
| `topk`, `bottomk`, `sort`, `sort_desc` | proxy | `sort` only orders instant queries, as documented |
| vector ⊕ scalar, vector ⊕ vector (`+ - * / % ^`, comparisons, `bool`, `and`, `or`, `unless`) | proxy, one-to-one matching | `… or vector(0)` works |
| `vector(s)`, scalar expressions | proxy | |
| `offset` | ✅ | |

### Differences from Loki

These are the known differences. Anything not listed here is meant to behave
like Loki; please open an issue if it doesn't.

**Data model**

1. **Labels vs fields.** Loki labels are VictoriaLogs
   [stream fields](https://docs.victoriametrics.com/victorialogs/querying/#querying-stream-field-names). Every other VictoriaLogs
   field is reported as structured metadata.
2. **Label names.** Field names that aren't valid Loki label names
   (`service.name`) are exposed sanitized (`service_name`) and mapped back in
   queries (see [Field names](#field-names)).
3. **Levels.** `detected_level` comes from stored fields (`-level-fields`) and
   is normalized like Loki. Loki also detects levels inside unparsed JSON or
   logfmt lines; the proxy doesn't.
4. **Parsed field names.** Parsers follow VictoriaLogs naming: nested JSON keys
   are joined with `.`, which is then exposed as `_`, so `a.b.c` shows as `a_b_c`
   like Loki. Differences from Loki's parsers:
   - JSON arrays are kept as JSON strings instead of being skipped.
   - When an extracted key clashes with an existing label, Loki keeps both and
     names the new one `<key>_extracted`; here the original value is kept.
   - `--strict` and `--keep-empty` are accepted but ignored.
   - JSON path parameters with array indexes (`servers[0]`) aren't supported.
5. **`__error__`.** VictoriaLogs parsers never fail, so `__error__` and
   `__error_details__` are never set: `__error__=""` is always true. Numeric
   comparisons skip values that aren't numbers, where Loki keeps the line and
   sets `__error__`.

**Metric queries**

6. **Windows.** A `stats_query_range` bucket `[t-step, t)` is reported at `t`
   (the [documented](https://docs.victoriametrics.com/victorialogs/querying/#querying-log-range-stats) one-step shift), on Loki's
   `start + k·step` grid. When `range` is a multiple of `step`, count, sum,
   bytes, rate, min and max are combined into exact sliding windows. Other
   functions use `step`-wide windows. Loki's windows are `(t-range, t]`.
7. **Unwrapped per-stream series.** Without grouping, unwrapped and log range
   aggregations produce one series per stream. Loki's series also carry
   labels extracted by parsers.
8. **Not supported:**
   - `first_over_time`, `last_over_time`, `rate_counter`
   - `without (…)` with labels
   - `on()`/`ignoring()`/`group_left`/`group_right`, `label_replace`
   - `approx_count_distinct`, `approx_topk`
   - aggregations over vector⊕vector expressions (except `topk`, `bottomk`, `sort`)
   - `line_format`/`label_format` template functions

**Endpoints**

9. **Statistics.** VictoriaLogs doesn't expose per-query scan statistics. The
   `stats` block, the `X-Loki-Query-Bytes-Processed` header (omitted) and
   `/index/stats` `bytes` (0 unless `-index-stats-bytes`) reflect that.
   `chunks` equals `streams`.
10. **Volumes** are counted in log entries, not bytes.
11. **`/patterns`** is computed on the fly with `collapse_nums prettify` over the
    requested range (top 50 shapes, numbers, UUIDs, IPs and times only), not
    by a pattern ingester. It doesn't report a per-pattern `level`.
12. **`detected_fields`** scans the newest `line_limit` lines once, not per
    shard. Its `cardinality` is exact over that sample (Loki uses a sketch),
    and `sketch` isn't returned.
13. **`interval`** is applied per stream after VictoriaLogs returns the newest
    `limit` lines, so it can return fewer than `limit` entries.
14. **`/tail`:**
    - VictoriaLogs waits at least 1 s before returning new lines (`offset`).
    - `limit` only bounds the initial historical batch.
    - `dropped_entries` is always `null`.
15. **`/format_query`** doesn't reformat the query.
16. **Multi-tenant queries** (`X-Scope-OrgID: a|b`) are rejected. Non-numeric
    tenants need `-tenant-map`.
17. **Parquet responses** (`Accept: application/vnd.apache.parquet`) aren't
    supported; responses are always JSON.

## Development

```bash
make test     # unit tests
make bench    # benchmarks
make lint     # gofmt + go vet
make e2e      # request set used by Grafana/Drilldown, against LOKI_VL_PROXY_E2E_URL
make dist     # static binaries: dist/linux_amd64, dist/linux_arm64
make docker   # multi-arch image from dist/ (needs a buildx builder with multi-platform support)
```

The release image ([Dockerfile](Dockerfile)) contains no compiler step: it
packages the `dist/linux_<arch>/loki-vl-proxy` binaries built by the pipeline.
The compose stack builds from source with
[deploy/compose/Dockerfile](deploy/compose/Dockerfile).

`TRANSLATE_DUMP=queries.tsv go test ./internal/translate/` dumps every
generated LogsQL query. CI parses them with the VictoriaLogs parser built from
`tools/vlcheck`.

## Releases

Releases are fully automated with
[release-please](https://github.com/googleapis/release-please) and follow
[Conventional Commits](https://www.conventionalcommits.org/):

- `fix:` makes a patch release, and `feat:` a minor one.
- A breaking change (`!` or `BREAKING CHANGE:`) bumps the minor version while
  below 1.0.
- `chore:`, `ci:`, `docs:` and similar types don't release.

1. Every push to `main` updates a release PR with the next version and the
   `CHANGELOG.md` entry.
2. Merging that PR creates a draft GitHub release and its `vX.Y.Z` tag.
3. The [release workflow](.github/workflows/release.yml) then:
   1. runs the tests at the tag;
   2. builds the static Linux binaries (amd64, arm64);
   3. pushes the multi-arch image `ghcr.io/justereseau/loki-vl-proxy`, tagged
      `X.Y.Z`, `X.Y`, `X` (from 1.0) and `latest`, built from those same
      binaries;
   4. attaches `loki-vl-proxy_<version>_linux_<arch>.tar.gz` and
      `loki-vl-proxy_<version>_checksums.txt`;
   5. publishes the release.
4. The repository has [immutable releases](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/immutable-releases)
   enabled, so a published release (its tag and assets) can't be changed.

Every push to `main` also publishes `ghcr.io/justereseau/loki-vl-proxy:main`
and `:sha-<commit>` from the CI binaries.

`main` requires the CI checks (`test`, `logsql-syntax`, `e2e`, `build (amd64)`,
`build (arm64)`, `image`), so pull requests, release PRs included, can use
GitHub's **auto-merge**. Release PRs are opened with the built-in token, which
doesn't trigger `pull_request` workflows, so the release workflow dispatches CI
on them.

## License

Apache License 2.0.
