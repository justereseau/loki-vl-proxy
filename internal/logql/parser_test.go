package logql

import (
	"testing"
	"time"
)

func TestParseShapes(t *testing.T) {
	ok := []string{
		`{a="b"}`,
		`{a="b", c!="d", e=~"f.*", g!~"h"} |= "x" != "y" |~ "z" !~ "w"`,
		"{a=`raw\\string`}",
		`{a="b"} | json | logfmt --strict --keep-empty | drop __error__, __error_details__`,
		`{a="b"} | json foo="bar.baz", qux | line_format "{{.foo}}"`,
		`{a="b"} | level="info" or level="error" | duration >= 20ms, size < 1KB`,
		`{a="b"} | addr = ip("10.0.0.0/8")`,
		`{a="b"} |> "<_> foo <_>" !> "bar"`,
		`sum by (level) (count_over_time({a="b"} [5m]))`,
		`sum(count_over_time({a="b"} | json [5m])) by (level)`,
		`count_over_time({a="b"}[5m] | json)`,
		`avg_over_time({a="b"} | unwrap duration(took) | __error__="" [1m]) by ()`,
		`quantile_over_time(0.99, {a="b"} | unwrap bytes(size) [5m]) by (host)`,
		`topk(10, sum by (x) (rate({a="b"}[1m])))`,
		`sum(rate({a="b"}[1m] offset 5m)) * 60 > 1`,
		`vector(1) + vector(1)`,
		`-sum(rate({a="b"}[1m]))`,
	}
	for _, q := range ok {
		if _, err := Parse(q); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
	bad := []string{`{a="b"`, `{a="b"} | `, `count_over_time({a="b"})`, `{a=b}`, `foo({a="b"})`, `{a="b"} |= ip("1.2.3.4")`}
	for _, q := range bad {
		if _, err := Parse(q); err == nil {
			t.Errorf("%s: expected error", q)
		}
	}
}

func TestParseRangeAgg(t *testing.T) {
	e, err := Parse(`avg_over_time({a="b"} | json | unwrap duration(took) | __error__="" [5m] offset 1m) by (host)`)
	if err != nil {
		t.Fatal(err)
	}
	r := e.(*RangeAgg)
	if r.Range != 5*time.Minute || r.Offset != time.Minute || r.Unwrap.Conv != "duration" || r.Unwrap.Label != "took" ||
		len(r.Log.Stages) != 1 || len(r.Post) != 1 || r.Grouping.Labels[0] != "host" {
		t.Fatalf("%+v", r)
	}
}

func TestBinaryPrecedence(t *testing.T) {
	e, err := Parse(`vector(1) + vector(2) * vector(3)`)
	if err != nil {
		t.Fatal(err)
	}
	b := e.(*BinOp)
	if b.Op != "+" || b.R.(*BinOp).Op != "*" {
		t.Fatalf("%+v", b)
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"5m": 5 * time.Minute, "1h30m": 90 * time.Minute, "15": 15 * time.Second, "1d": 24 * time.Hour, "250ms": 250 * time.Millisecond} {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
}
