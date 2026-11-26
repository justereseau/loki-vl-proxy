package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // G505: SHA-1 is mandated by the WebSocket handshake (RFC 6455), not used for security
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Justereseau/loki-vl-proxy/internal/logql"
	"github.com/Justereseau/loki-vl-proxy/internal/translate"
)

// handleTail serves the /loki/api/v1/tail WebSocket
// (https://grafana.com/docs/loki/latest/reference/loki-http-api/#stream-logs)
// on top of VictoriaLogs live tailing
// (https://docs.victoriametrics.com/victorialogs/querying/#live-tailing).
//
// Parameters: query, delay_for (seconds, max 5), limit (default 100), start
// (default one hour ago). Every WebSocket text message is
// {"streams":[...],"dropped_entries":null}.
func (s *Server) handleTail(w http.ResponseWriter, r *http.Request) error {
	if err := parseForm(r); err != nil {
		return err
	}
	tenant, err := s.tenant(r)
	if err != nil {
		return err
	}
	expr, err := s.parseQuery(r)
	if err != nil {
		return err
	}
	le, ok := expr.(*logql.LogExpr)
	if !ok {
		return httpError(http.StatusBadRequest, "tail requires a log query")
	}
	logsql, meta, err := translate.LogWithMeta(le, s.translateOptions(r, tenant))
	if err != nil {
		return badRequest(err)
	}
	delay := 0
	if v := r.Form.Get("delay_for"); v != "" {
		if delay, err = strconv.Atoi(v); err != nil || delay < 0 {
			return httpError(http.StatusBadRequest, "invalid delay_for %q", v)
		}
		if delay > 5 {
			return httpError(http.StatusBadRequest, "delay_for can't be greater than 5")
		}
	}
	limit, err := s.parseLimit(r.Form.Get("limit"))
	if err != nil {
		return err
	}
	now := time.Now()
	start, err := parseLokiTime(r.Form.Get("start"), now.Add(-time.Hour))
	if err != nil {
		return badRequest(err)
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return httpError(http.StatusBadRequest, "tail is a WebSocket endpoint")
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	form := url.Values{"query": {logsql}}
	if d := now.Sub(start); d > 0 {
		form.Set("start_offset", vlDuration(d.Truncate(time.Millisecond)))
	}
	// VictoriaLogs delays new logs by 5s by default; Loki's delay_for defaults to 0.
	form.Set("offset", strconv.Itoa(max(delay, 1))+"s")
	resp, err := s.do(ctx, r, tenant, "/select/logsql/tail", form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	conn, brw, err := wsAccept(w, r)
	if err != nil {
		return nil // response already written or connection unusable
	}
	defer conn.Close()
	ws := &wsConn{conn: conn, bw: brw.Writer}

	// reader: answer pings, stop on close or error
	go func() {
		defer cancel()
		ws.readLoop(brw.Reader)
	}()

	enc := newStreamEncoder(s.cfg.LevelFields, false)
	enc.normalize = s.cfg.NormalizeLevels
	enc.fromFields = meta.LabelsFromFields
	br := bufio.NewReaderSize(resp.Body, 64<<10)
	msg := make([]byte, 0, 16<<10)
	sent := 0
	var long []byte
	for {
		msg = append(msg[:0], `{"streams":[`...)
		enc.reset()
		n := 0
		for {
			line, err := br.ReadSlice('\n')
			if errors.Is(err, bufio.ErrBufferFull) {
				long = append(long[:0], line...)
				for errors.Is(err, bufio.ErrBufferFull) {
					line, err = br.ReadSlice('\n')
					long = append(long, line...)
				}
				line = long
			}
			if err != nil {
				if n > 0 {
					break
				}
				if err != io.EOF && ctx.Err() == nil {
					s.log.Warn("tail stream interrupted", "err", err)
				}
				ws.close(1000)
				return nil
			}
			if len(bytes.TrimSpace(line)) > 0 && (sent+n < limit || time.Since(now) > 2*time.Second) {
				// `limit` bounds the initial batch of historical entries
				msg = enc.appendEntry(msg, line)
				n++
			}
			if br.Buffered() == 0 || len(msg) > 256<<10 {
				break
			}
		}
		if n == 0 {
			continue
		}
		sent += n
		msg = enc.finish(msg)
		msg = append(msg, `],"dropped_entries":null}`...)
		if err := ws.writeText(msg); err != nil {
			return nil
		}
	}
}

func (e *streamEncoder) reset() {
	e.open = false
	e.streamRaw = e.streamRaw[:0]
	e.entryKey = e.entryKey[:0]
	e.openLabels = e.openLabels[:0]
}

// --- minimal RFC 6455 server (text frames out, control frames in) ---

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func wsAccept(w http.ResponseWriter, r *http.Request) (net.Conn, *bufio.ReadWriter, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" || !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		http.Error(w, "missing WebSocket handshake headers", http.StatusBadRequest)
		return nil, nil, errors.New("bad handshake")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket not supported", http.StatusInternalServerError)
		return nil, nil, errors.New("hijack unsupported")
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	sum := sha1.Sum([]byte(key + wsGUID)) //nolint:gosec // G401: Sec-WebSocket-Accept is defined as base64(SHA-1(key + GUID)) by RFC 6455
	_, err = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n")
	if err == nil {
		err = brw.Flush()
	}
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return conn, brw, nil
}

type wsConn struct {
	conn net.Conn
	mu   sync.Mutex
	bw   *bufio.Writer
}

func (c *wsConn) writeFrame(op byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var hdr [10]byte
	hdr[0] = 0x80 | op
	n := 2
	switch l := len(payload); {
	case l < 126:
		hdr[1] = byte(l)
	case l <= 0xFFFF:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(l))
		n = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(l))
		n = 10
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.bw.Write(hdr[:n]); err != nil {
		return err
	}
	if _, err := c.bw.Write(payload); err != nil {
		return err
	}
	return c.bw.Flush()
}

func (c *wsConn) writeText(p []byte) error { return c.writeFrame(0x1, p) }

func (c *wsConn) close(code uint16) {
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], code)
	_ = c.writeFrame(0x8, p[:])
}

// readLoop consumes client frames: pings are answered, close or errors end it.
func (c *wsConn) readLoop(br *bufio.Reader) {
	var hdr [14]byte
	for {
		if _, err := io.ReadFull(br, hdr[:2]); err != nil {
			return
		}
		op := hdr[0] & 0x0F
		masked := hdr[1]&0x80 != 0
		l := uint64(hdr[1] & 0x7F)
		switch l {
		case 126:
			if _, err := io.ReadFull(br, hdr[2:4]); err != nil {
				return
			}
			l = uint64(binary.BigEndian.Uint16(hdr[2:4]))
		case 127:
			if _, err := io.ReadFull(br, hdr[2:10]); err != nil {
				return
			}
			l = binary.BigEndian.Uint64(hdr[2:10])
		}
		if l > 1<<20 {
			return
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(br, mask[:]); err != nil {
				return
			}
		}
		payload := make([]byte, l)
		if _, err := io.ReadFull(br, payload); err != nil {
			return
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
		switch op {
		case 0x8: // close
			c.close(1000)
			return
		case 0x9: // ping
			_ = c.writeFrame(0xA, payload)
		}
	}
}
