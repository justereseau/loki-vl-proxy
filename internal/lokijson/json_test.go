package lokijson

import (
	"encoding/json"
	"testing"
	"time"
)

func TestScanObject(t *testing.T) {
	line := []byte(`{"_msg":"a \"b\" \\ c","n":12,"obj":{"x":[1,2]},"e":""}`)
	fs, err := ScanObject(line, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 4 || string(fs[0].Value) != `a \"b\" \\ c` || !fs[0].Quoted || string(fs[1].Value) != "12" || fs[1].Quoted || string(fs[2].Value) != `{"x":[1,2]}` {
		t.Fatalf("%+v", fs)
	}
	if got := string(Unescape(nil, fs[0].Value)); got != `a "b" \ c` {
		t.Fatalf("unescape: %q", got)
	}
	for raw, want := range map[string]string{`caf\u00e9`: "café", `\ud83d\ude00!`: "😀!", `bad \uZZZZ`: "bad uZZZZ", `\u003c13>`: "<13>"} {
		if got := string(Unescape(nil, []byte(raw))); got != want {
			t.Errorf("unescape %s: %q want %q", raw, got, want)
		}
	}
	if _, err := ScanObject([]byte(`{"a":"b`), nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestAppendString(t *testing.T) {
	for _, s := range []string{"plain", "q\"uote", "back\\slash", "new\nline", "ctl\x01", "ünïcode ✓"} {
		b := AppendString(nil, s)
		var back string
		if err := json.Unmarshal(b, &back); err != nil || back != s {
			t.Errorf("%q -> %s -> %q (%v)", s, b, back, err)
		}
	}
}

func TestParseTime(t *testing.T) {
	for _, s := range []string{"2024-01-02T03:04:05Z", "2024-01-02T03:04:05.123Z", "2024-01-02T03:04:05.123456789Z", "1969-12-31T23:59:59Z", "2024-01-02T03:04:05+02:00"} {
		want, _ := time.Parse(time.RFC3339Nano, s)
		got, ok := ParseTime([]byte(s))
		if !ok || got != want.UnixNano() {
			t.Errorf("%s: got %d want %d", s, got, want.UnixNano())
		}
	}
}

func TestParseStreamLabels(t *testing.T) {
	var got []string
	ok := ParseStreamLabels([]byte(`{service.name="api",msg="a \"q\"",empty=""}`), func(n, v []byte) {
		got = append(got, string(n)+"="+string(v))
	})
	if !ok || len(got) != 3 || got[0] != "service.name=api" || got[1] != `msg=a "q"` {
		t.Fatalf("%v", got)
	}
}

func TestSanitize(t *testing.T) {
	for in, want := range map[string]string{"service.name": "service_name", "ok_name": "ok_name", "1abc": "_1abc", "a-b/c": "a_b_c"} {
		if got := SanitizeLabelName(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
		if got := string(AppendSanitizedName(nil, []byte(in))); got != `"`+want+`"` {
			t.Errorf("append %s: %s", in, got)
		}
	}
}

func BenchmarkScanObject(b *testing.B) {
	line := []byte(`{"_msg":"GET /api/v1/users 200 12ms","_stream":"{service.name=\"api\",pod=\"p1\"}","_stream_id":"0000000000000000a67ab97eb264323c","_time":"2026-11-25T22:41:40.123456789Z","level":"info","service.name":"api","pod":"p1","trace.id":"4bf92f3577b34da6a3ce929d0e0e4736"}`)
	var fs []Field
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fs, _ = ScanObject(line, fs)
	}
}
