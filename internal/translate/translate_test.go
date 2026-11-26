package translate

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/Justereseau/loki-vl-proxy/internal/logql"
)

func opts() *Options {
	return &Options{
		LevelFields: []string{"level"},
		ResolveName: func(n string) string {
			if n == "service_name" {
				return "service.name"
			}
			return n
		},
	}
}

// dump writes "<mode>\t<logsql>" lines to $TRANSLATE_DUMP so that generated
// queries can be validated with the real VictoriaLogs parser (see Makefile).
func dump(t *testing.T, mode, q string) {
	if p := os.Getenv("TRANSLATE_DUMP"); p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		fmt.Fprintf(f, "%s\t%s\n", mode, q)
	}
}

func TestLogQueries(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{app="nginx"}`, `{app="nginx"}`},
		{`{app="nginx", env!="dev", pod=~"web-.*", ns!~"kube-.*"}`, `{app="nginx",env!="dev",pod=~"web-.*",ns!~"kube-.*"}`},
		{`{service_name="api"}`, `{service.name="api"}`},
		{`{}`, `*`},
		{`{app=~".*"}`, `*`},
		{`{app="a", __stream_shard__="3"}`, `{app="a"}`},
		// line filters
		{`{app="a"} |= "error"`, `{app="a"} *"error"*`},
		{`{app="a"} != "debug"`, `{app="a"} !*"debug"*`},
		{`{app="a"} |~ "(?i)timeout"`, `{app="a"} ~"(?i)timeout"`},
		{`{app="a"} !~ "health.*check"`, `{app="a"} !~"(?s)health.*check"`},
		{`{app="a"} |~ "err\\d+"`, `{app="a"} ~"err\\d+"`},
		{`{app="a"} |= "foo" or "bar"`, `{app="a"} (*"foo"* or *"bar"*)`},
		{`{app="a"} |= ""`, `{app="a"}`},
		{"{app=\"a\"} |= `C:\\path`", `{app="a"} *"C:\\path"*`},
		{`{app="a"} |> "user <N> logged in from <IP4>"`, `{app="a"} pattern_match_full("user <N> logged in from <IP4>")`},
		{`{app="a"} |> "<_> level=info <_>"`, `{app="a"} ~"(?s)^.*? level=info .*?$"`},
		{`{app="a"} !> "GET <_> 200"`, `{app="a"} !~"(?s)^GET .*? 200$"`},
		// label filters, before and after parsers
		{`{app="a"} | detected_level="error"`, `{app="a"} level:in("error")`},
		{`{app="a"} | level="info" or level="error"`, `{app="a"} (level:="info" or level:="error")`},
		{`{app="a"} | level=~"info|error"`, `{app="a"} level:in("info", "error")`},
		{`{app="a"} | level=~"in.+"`, `{app="a"} level:~"^(?:in.+)$"`},
		{`{app="a"} | level=~"inf.*"`, `{app="a"} level:="inf"*`},
		{`{app="a"} | level!~"info"`, `{app="a"} !level:="info"`},
		{`{app="a"} | pod=~".+"`, `{app="a"} pod:*`},
		{`{app="a"} | pod!=""`, `{app="a"} pod:*`},
		{`{app="a"} | duration > 10s, duration <= 20s`, `{app="a"} duration:>10s duration:<=20s`},
		{`{app="a"} | status >= 500`, `{app="a"} status:>=500`},
		{`{app="a"} | status == 200`, `{app="a"} status:range[200, 200]`},
		{`{app="a"} | size > 1KB`, `{app="a"} size:>1000`},
		{`{app="a"} | size >= 1.5KiB`, `{app="a"} size:>=1536`},
		{`{app="a"} | size < 2PB`, `{app="a"} size:<2000000000000000`},
		{`{app="a"} | took > 1h30m`, `{app="a"} took:>1h30m`},
		{`{app="a"} | keep level, method="GET"`, `{app="a"} | format if (!(method:="GET")) "" as method | fields _time, _stream, _stream_id, _msg, level, method`},
		{`{app="a"} | unpack`, `{app="a"} | unpack_json keep_original_fields | format if (_entry:*) "<_entry>" as _msg | delete _entry`},
		{`{app="a"} | pattern "<_> msg=\"<m>\""`, `{app="a"} | extract "<_> msg=\"<m>\"" keep_original_fields`},
		{`{app="a"} | line_format "{{ __line__ }} ({{.level}})"`, `{app="a"} | format "<_msg> (<level>)" as _msg`},
		{`{app="a"} | addr = ip("10.0.0.0/8")`, `{app="a"} addr:ipv4_range("10.0.0.0/8")`},
		{`{app="a"} | (a="1" or b="2") c="3"`, `{app="a"} (a:="1" or b:="2") c:="3"`},
		// parsers
		{`{app="a"} | json | logfmt | drop __error__, __error_details__`,
			`{app="a"} | unpack_json keep_original_fields | unpack_logfmt keep_original_fields`},
		{`{app="a"} | json | status="500"`, `{app="a"} | unpack_json keep_original_fields | filter status:="500"`},
		{`{app="a"} | json |= "x"`, `{app="a"} *"x"* | unpack_json keep_original_fields`},
		{`{app="a"} | json code="resp.status", ua="headers[\"ua\"]"`,
			`{app="a"} | unpack_json fields (resp.status, headers.ua) keep_original_fields | rename resp.status as code | rename headers.ua as ua`},
		{`{app="a"} | logfmt --strict`, `{app="a"} | unpack_logfmt keep_original_fields`},
		{`{app="a"} | regexp "(?P<method>\\w+) (?P<path>\\S+)"`, `{app="a"} | extract_regexp "(?P<method>\\w+) (?P<path>\\S+)" keep_original_fields`},
		{`{app="a"} | pattern "<ip> - <_> \"<method> <path>"`, `{app="a"} | extract "<ip> - <_> \"<method> <path>" keep_original_fields`},
		{`{app="a"} | pattern "GET <path> <_>"`, `{app="a"} | extract if (_msg:="GET "*) "GET <path> <_>" keep_original_fields`},
		// formatting, drop, keep
		{`{app="a"} | line_format "{{.msg}} ({{ .level }})"`, `{app="a"} | format "<msg> (<level>)" as _msg`},
		{`{app="a"} | line_format "{{.msg}}" |= "x"`, `{app="a"} | format "<msg>" as _msg | filter *"x"*`},
		{`{app="a"} | label_format svc=app, x="{{.a}}-{{.b}}"`, `{app="a"} | rename app as svc | format "<a>-<b>" as x`},
		{`{app="a"} | drop pod, node`, `{app="a"} | delete pod, node`},
		{`{app="a"} | drop level="debug"`, `{app="a"} | format if (level:="debug") "" as level`},
		{`{app="a"} | keep level`, `{app="a"} | fields _time, _stream, _stream_id, _msg, level`},
		{`{app="a"} | decolorize`, `{app="a"} | decolorize`},
		// error label filters
		{`{app="a"} | json | __error__=""`, `{app="a"} | unpack_json keep_original_fields`},
		// the full Drilldown log panel query
		{`{service_name="tempo"} | detected_level="error" | user!="03428" |~ "(?i)Error" | json | logfmt | drop __error__, __error_details__ | msg!="Failed"`,
			`{service.name="tempo"} level:in("error") !user:="03428" ~"(?i)Error" | unpack_json keep_original_fields | unpack_logfmt keep_original_fields | filter !msg:="Failed"`},
	}
	for _, c := range cases {
		e, err := logql.ParseLog(c.in)
		if err != nil {
			t.Errorf("parse %s: %v", c.in, err)
			continue
		}
		got, err := Log(e, opts())
		if err != nil {
			t.Errorf("translate %s: %v", c.in, err)
			continue
		}
		dump(t, "L", got)
		if got != c.want {
			t.Errorf("\n in:   %s\n got:  %s\n want: %s", c.in, got, c.want)
		}
	}
}

func TestMultiLevelFields(t *testing.T) {
	o := opts()
	o.LevelFields = []string{"level", "severity_text"}
	e, _ := logql.ParseLog(`{app="a"} | detected_level="error" | detected_level!=""`)
	got, err := Log(e, o)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{app="a"} (level:in("error") or severity_text:in("error")) (level:* or severity_text:*)`; got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	dump(t, "L", got)
	e2, _ := logql.Parse(`sum by (detected_level) (count_over_time({app="a"} | detected_level!="debug" [1m]))`)
	m, err := Metric(e2, o)
	if err != nil {
		t.Fatal(err)
	}
	want := `{app="a"} !(level:in("debug") or severity_text:in("debug")) | coalesce (level, severity_text) as detected_level | stats by (detected_level) count() as v`
	if m.LogsQL != want {
		t.Fatalf("got  %s\nwant %s", m.LogsQL, want)
	}
	dump(t, "R", m.LogsQL)
}

func TestLevelNormalization(t *testing.T) {
	o := opts()
	o.NormalizeLevels = true
	o.LevelFields = []string{"level", "severity_text"}
	cases := []struct{ in, want string }{
		{`{a="b"} | detected_level="warn"`, `{a="b"} (level:in("warn", "WARN", "Warn", "warning", "WARNING", "Warning", "wrn", "WRN", "Wrn") or severity_text:in("warn", "WARN", "Warn", "warning", "WARNING", "Warning", "wrn", "WRN", "Wrn"))`},
		{`{a="b"} | detected_level=~"debug|trace"`, `{a="b"} (level:in("debug", "DEBUG", "Debug", "dbg", "DBG", "Dbg", "trace", "TRACE", "Trace", "trc", "TRC", "Trc") or severity_text:in("debug", "DEBUG", "Debug", "dbg", "DBG", "Dbg", "trace", "TRACE", "Trace", "trc", "TRC", "Trc"))`},
		{`{a="b"} | detected_level!="Unspecified"`, `{a="b"} !(level:in("Unspecified") or severity_text:in("Unspecified"))`},
	}
	for _, c := range cases {
		e, err := logql.ParseLog(c.in)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Log(e, o)
		if err != nil {
			t.Fatal(err)
		}
		dump(t, "L", got)
		if got != c.want {
			t.Errorf("\n in:   %s\n got:  %s\n want: %s", c.in, got, c.want)
		}
	}
	e, _ := logql.ParseLog(`{a="b"} | detected_level="unknown"`)
	got, _ := Log(e, o)
	dump(t, "L", got)
	if !strings.HasPrefix(got, `{a="b"} !(level:in("trace"`) {
		t.Errorf("unknown: %s", got)
	}
	for in, want := range map[string]string{"ERR": "error", "Warning": "warn", "notice": "info", "Unspecified": "unknown", "FATAL": "critical"} {
		if got := NormalizeLevel(in); got != want {
			t.Errorf("NormalizeLevel(%s)=%s want %s", in, got, want)
		}
	}
}

func TestNonNativeFiltersRunAfterParsers(t *testing.T) {
	o := opts()
	o.IsNative = func(f string) bool { return f == "level" || f == "pod" }
	e, _ := logql.ParseLog(`{app="a"} | level="info" | msg="started" | pod="p1" |= "x" | json | logfmt | drop __error__, __error_details__ | status="200"`)
	got, err := Log(e, o)
	if err != nil {
		t.Fatal(err)
	}
	want := `{app="a"} level:="info" pod:="p1" *"x"* | unpack_json keep_original_fields | unpack_logfmt keep_original_fields | filter msg:="started" | filter status:="200"`
	if got != want {
		t.Fatalf("\ngot  %s\nwant %s", got, want)
	}
	dump(t, "L", got)
}

func TestIgnoreParsers(t *testing.T) {
	o := opts()
	o.IgnoreParsers = true
	e, err := logql.ParseLog(`{app="a"} | json | logfmt | drop __error__, __error_details__ | status="500"`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Log(e, o)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{app="a"} status:="500"`; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestMetricQueries(t *testing.T) {
	cases := []struct {
		in, want string
		stream   bool
		slide    SlideKind
		post     string
	}{
		{in: `count_over_time({app="a"}[5m])`, want: `{app="a"} | stats by (_stream) count() as v`, stream: true, slide: SlideSum},
		{in: `sum(count_over_time({app="a"}[5m]))`, want: `{app="a"} | stats count() as v`, slide: SlideSum},
		{in: `sum by (detected_level) (count_over_time({service_name="api"} | detected_level != "" [1m]))`,
			want: `{service.name="api"} level:* | stats by (level) count() as v`, slide: SlideSum},
		{in: `sum(count_over_time({app="a"} | json | logfmt | drop __error__, __error_details__ [1m])) by (status)`,
			want: `{app="a"} | unpack_json keep_original_fields | unpack_logfmt keep_original_fields | stats by (status) count() as v`, slide: SlideSum},
		{in: `sum by (pod) (rate({app="a"} |= "err" [5m]))`, want: `{app="a"} *"err"* | stats by (pod) count() as v`, slide: SlideSum, post: "window"},
		{in: `bytes_over_time({app="a"}[1m])`, want: `{app="a"} | stats by (_stream) sum_len(_msg) as v`, stream: true, slide: SlideSum},
		{in: `sum(bytes_rate({app="a"}[1m]))`, want: `{app="a"} | stats sum_len(_msg) as v`, slide: SlideSum, post: "window"},
		{in: `avg_over_time({app="a"} | unwrap latency | __error__="" [1m]) by ()`, want: `{app="a"} | stats avg(latency) as v`},
		{in: `avg_over_time({app="a"} | logfmt | unwrap duration(took) | __error__="" [1m]) by ()`,
			want: `{app="a"} | unpack_logfmt keep_original_fields | stats avg(took) as v`, post: "scale"},
		{in: `quantile_over_time(0.99, {app="a"} | unwrap bytes(size) [5m]) by (host)`, want: `{app="a"} | stats by (host) quantile(0.99, size) as v`},
		{in: `max by (host) (max_over_time({app="a"} | unwrap x [5m]))`, want: `{app="a"} | stats by (host) max(x) as v`, slide: SlideMax},
		{in: `avg by (host) (count_over_time({app="a"}[5m]))`,
			want: `{app="a"} | stats by (_stream, host) count() as v | stats by (host) avg(v) as v`},
		{in: `count by (host) (count_over_time({app="a"}[5m]))`,
			want: `{app="a"} | stats by (_stream, host) count() as v | stats by (host) count() as v`},
		{in: `topk(5, sum by (path) (count_over_time({app="a"}[5m])))`, want: `{app="a"} | stats by (path) count() as v`, slide: SlideSum, post: "topk"},
		{in: `sum by (status) (count_over_time({app="a"} | keep status [1h]))`,
			want: `{app="a"} | fields _time, _stream, _stream_id, _msg, status | stats by (status) count() as v`, slide: SlideSum},
		{in: `sum(count_over_time({app="a"}[1m])) / 60`, want: `{app="a"} | stats count() as v`, post: "scalar"},
		{in: `sum(rate({app="a"}[1m])) > 2`, want: `{app="a"} | stats count() as v`, post: "window,compare"},
		{in: `stdvar_over_time({app="a"} | unwrap x [1m]) by (h)`, want: `{app="a"} | stats by (h) stddev(x) as v`, post: "square"},
	}
	for _, c := range cases {
		e, err := logql.Parse(c.in)
		if err != nil {
			t.Errorf("parse %s: %v", c.in, err)
			continue
		}
		m, err := Metric(e, opts())
		if err != nil {
			t.Errorf("translate %s: %v", c.in, err)
			continue
		}
		dump(t, "R", m.LogsQL)
		if m.LogsQL != c.want {
			t.Errorf("\n in:   %s\n got:  %s\n want: %s", c.in, m.LogsQL, c.want)
		}
		if m.ExpandStream != c.stream {
			t.Errorf("%s: ExpandStream=%v", c.in, m.ExpandStream)
		}
		if m.Slide != c.slide {
			t.Errorf("%s: Slide=%v want %v", c.in, m.Slide, c.slide)
		}
		if got := postString(m.Post); got != c.post {
			t.Errorf("%s: post=%q want %q", c.in, got, c.post)
		}
	}
}

func postString(ps []PostOp) string {
	names := map[PostKind]string{PostScale: "scale", PostScaleWindow: "window", PostSquare: "square",
		PostScalarOp: "scalar", PostCompare: "compare", PostTopK: "topk", PostSort: "sort"}
	var out []string
	for _, p := range ps {
		out = append(out, names[p.Kind])
	}
	return strings.Join(out, ",")
}

func TestRenames(t *testing.T) {
	e, _ := logql.Parse(`sum by (detected_level, service_name) (count_over_time({app="a"}[1m]))`)
	m, err := Metric(e, opts())
	if err != nil {
		t.Fatal(err)
	}
	if m.Renames["level"] != "detected_level" || m.Renames["service.name"] != "service_name" {
		t.Fatalf("renames: %v", m.Renames)
	}
}

func TestConst(t *testing.T) {
	e, err := logql.Parse(`vector(1)+vector(1)`)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Metric(e, opts())
	if err != nil {
		t.Fatal(err)
	}
	if m.Const == nil || *m.Const != 2 {
		t.Fatalf("const: %+v", m)
	}
}

func TestPlan(t *testing.T) {
	cases := map[string]string{
		`sum(count_over_time({a="b"}[1m])) / sum(count_over_time({a="c"}[1m]))`:                               "bin(/,leaf,leaf)",
		`sum(count_over_time({a="b"}[1m])) or vector(0)`:                                                      "bin(or,leaf,vector)",
		`(sum(rate({a="b"}[1m])) / sum(rate({a="c"}[1m]))) * 100`:                                             "bin(/,leaf,leaf)+post",
		`topk(3, sum by (x) (count_over_time({a="b"}[1m])) > bool sum by (x) (count_over_time({a="c"}[1m])))`: "bin(>,leaf,leaf)+post",
		`sum(count_over_time({a="b"}[1m])) * 2`:                                                               "leaf",
		`vector(1)+vector(1)`:                                                                                 "vector",
		`1+1`:                                                                                                 "scalar",
	}
	var show func(p *MetricPlan) string
	show = func(p *MetricPlan) string {
		s := ""
		switch {
		case p.Query != nil:
			s = "leaf"
		case p.Vector != nil:
			s = "vector"
		case p.Scalar != nil:
			s = "scalar"
		default:
			s = "bin(" + p.Op + "," + show(p.L) + "," + show(p.R) + ")"
		}
		if len(p.Post) > 0 {
			s += "+post"
		}
		return s
	}
	for q, want := range cases {
		e, err := logql.Parse(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		p, err := Plan(e, opts())
		if err != nil {
			t.Errorf("%s: %v", q, err)
			continue
		}
		if got := show(p); got != want {
			t.Errorf("%s: got %s want %s", q, got, want)
		}
	}
}

func TestAbsentAndGroupingRules(t *testing.T) {
	e, _ := logql.Parse(`absent_over_time({app="a", env!="dev"}[5m])`)
	m, err := Metric(e, opts())
	if err != nil {
		t.Fatal(err)
	}
	if m.LogsQL != `{app="a",env!="dev"} | stats count() as v` || len(m.Post) != 1 || m.Post[0].Kind != PostAbsent || m.Post[0].Labels["app"] != "a" || len(m.Post[0].Labels) != 1 {
		t.Fatalf("%+v", m)
	}
	dump(t, "R", m.LogsQL)
	for _, q := range []string{`count_over_time({a="b"}[1m]) by (x)`, `sum_over_time({a="b"} | unwrap v [1m]) by (x)`, `rate({a="b"} | unwrap v [1m]) by (x)`} {
		e, _ := logql.Parse(q)
		if _, err := Metric(e, opts()); err == nil || !strings.Contains(err.Error(), "grouping not allowed") {
			t.Errorf("%s: %v", q, err)
		}
	}
}

func TestUnsupported(t *testing.T) {
	for _, q := range []string{
		`sum(sum(count_over_time({a="b"}[1m])) / sum(count_over_time({a="c"}[1m])))`,
		`sum without (pod) (count_over_time({a="b"}[1m]))`,
		`first_over_time({a="b"} | unwrap x [1m])`,
		`sum_over_time({a="b"}[1m])`,
		`{a="b"} | line_format "{{ .a | upper }}"`,
	} {
		e, err := logql.Parse(q)
		if err != nil {
			continue
		}
		var terr error
		if le, ok := e.(*logql.LogExpr); ok {
			_, terr = Log(le, opts())
		} else {
			_, terr = Metric(e, opts())
		}
		if terr == nil {
			t.Errorf("expected error for %s", q)
		}
	}
}
