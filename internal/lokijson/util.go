package lokijson

import (
	"strconv"
	"time"
	"unsafe"
)

func unsafeString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(&b[0], len(b))
}

// ParseTime parses the RFC3339 timestamps emitted by VictoriaLogs
// ("2024-01-02T03:04:05.123456789Z") into Unix nanoseconds. The UTC fast path
// avoids time.Parse allocations.
func ParseTime(b []byte) (int64, bool) {
	if len(b) >= 20 && b[len(b)-1] == 'Z' && b[4] == '-' && b[7] == '-' && b[10] == 'T' && b[13] == ':' && b[16] == ':' {
		year, ok1 := atoi(b[0:4])
		month, ok2 := atoi(b[5:7])
		day, ok3 := atoi(b[8:10])
		hour, ok4 := atoi(b[11:13])
		minute, ok5 := atoi(b[14:16])
		sec, ok6 := atoi(b[17:19])
		if ok1 && ok2 && ok3 && ok4 && ok5 && ok6 {
			var nanos int64
			if b[19] == '.' {
				frac := b[20 : len(b)-1]
				if len(frac) > 9 {
					frac = frac[:9]
				}
				n, ok := atoi(frac)
				if !ok {
					goto slow
				}
				for i := len(frac); i < 9; i++ {
					n *= 10
				}
				nanos = int64(n)
			} else if len(b) != 20 {
				goto slow
			}
			days := daysFromCivil(year, month, day)
			return (days*86400+int64(hour*3600+minute*60+sec))*1e9 + nanos, true
		}
	}
slow:
	t, err := time.Parse(time.RFC3339Nano, unsafeString(b))
	if err != nil {
		return 0, false
	}
	return t.UnixNano(), true
}

func atoi(b []byte) (int, bool) {
	if len(b) == 0 {
		return 0, false
	}
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// daysFromCivil returns the number of days since 1970-01-01 (Howard Hinnant's algorithm).
func daysFromCivil(y, m, d int) int64 {
	if m <= 2 {
		y--
	}
	era := y / 400
	if y < 0 && y%400 != 0 {
		era--
	}
	yoe := y - era*400
	mp := (m + 9) % 12
	doy := (153*mp+2)/5 + d - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return int64(era)*146097 + int64(doe) - 719468
}

// ParseStreamLabels parses a VictoriaLogs `_stream` value such as
// {app="nginx",host="h1"} and calls fn for every label. Values are unquoted.
func ParseStreamLabels(s []byte, fn func(name, value []byte)) bool {
	i := skipWS(s, 0)
	if i >= len(s) || s[i] != '{' {
		return false
	}
	i++
	var tmp []byte
	for {
		i = skipWS(s, i)
		if i >= len(s) {
			return false
		}
		if s[i] == '}' {
			return true
		}
		if s[i] == ',' {
			i++
			continue
		}
		// label name, possibly quoted
		var name []byte
		if s[i] == '"' {
			e := stringEnd(s, i+1)
			if e < 0 {
				return false
			}
			name = s[i+1 : e]
			i = e + 1
		} else {
			st := i
			for i < len(s) && s[i] != '=' && s[i] != ' ' {
				i++
			}
			name = s[st:i]
		}
		i = skipWS(s, i)
		if i >= len(s) || s[i] != '=' {
			return false
		}
		i = skipWS(s, i+1)
		if i >= len(s) || s[i] != '"' {
			return false
		}
		e := stringEnd(s, i+1)
		if e < 0 {
			return false
		}
		val := s[i+1 : e]
		if HasEscape(val) {
			if u, err := strconv.Unquote(unsafeString(s[i : e+1])); err == nil {
				tmp = append(tmp[:0], u...)
				val = tmp
			}
		}
		fn(name, val)
		i = e + 1
	}
}

// AppendFloatValue formats a sample value the way Prometheus/Loki do.
func AppendFloatValue(dst []byte, v float64) []byte {
	switch {
	case v != v:
		return append(dst, "NaN"...)
	case v > 1.7976931348623157e308:
		return append(dst, "+Inf"...)
	case v < -1.7976931348623157e308:
		return append(dst, "-Inf"...)
	}
	return strconv.AppendFloat(dst, v, 'f', -1, 64)
}

// AppendUnixSeconds appends a millisecond timestamp as fractional Unix seconds.
func AppendUnixSeconds(dst []byte, ms int64) []byte {
	dst = strconv.AppendInt(dst, ms/1000, 10)
	if r := ms % 1000; r != 0 {
		if r < 0 {
			r = -r
		}
		dst = append(dst, '.')
		dst = append(dst, byte('0'+r/100), byte('0'+(r/10)%10), byte('0'+r%10))
		for dst[len(dst)-1] == '0' {
			dst = dst[:len(dst)-1]
		}
	}
	return dst
}
