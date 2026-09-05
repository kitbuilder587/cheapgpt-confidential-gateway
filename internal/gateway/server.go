package gateway

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kitbuilder587/cheapgpt-confidential-gateway/attestation"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/policy"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/protocol"
	"github.com/tiktoken-go/tokenizer"
)

const maxSessions = 256
const requestTimeout = 3 * time.Minute

type session struct {
	key     hpke.PrivateKey
	expires time.Time
}

type Server struct {
	provider   attestation.Provider
	upstream   *http.Client
	auth       [32]byte
	mu         sync.Mutex
	sessions   map[string]session
	quotes     chan struct{}
	requests   chan struct{}
	ready      atomic.Bool
	accepted   atomic.Uint64
	failed     atomic.Uint64
	active     atomic.Int64
	stop       chan struct{}
	closeOnce  sync.Once
	tokenizers chan struct{}
}

func New(provider attestation.Provider, token string) (*Server, error) {
	if provider == nil || len(token) < 32 {
		return nil, errors.New("attestation provider and a token of at least 32 bytes are required")
	}
	s := &Server{provider: provider, upstream: upstreamClient(), auth: sha256.Sum256([]byte(token)), sessions: make(map[string]session), quotes: make(chan struct{}, 2), requests: make(chan struct{}, 32), stop: make(chan struct{}), tokenizers: make(chan struct{}, 2)}
	go s.expireSessions()
	return s, nil
}

func (s *Server) expireSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			s.mu.Lock()
			s.prune(now)
			s.mu.Unlock()
		case <-s.stop:
			return
		}
	}
}

func (s *Server) Probe(ctx context.Context) error {
	data := make([]byte, 64)
	if _, err := rand.Read(data); err != nil {
		return err
	}
	_, err := s.provider.Quote(ctx, data)
	s.ready.Store(err == nil)
	return err
}

func (s *Server) Close() {
	s.closeOnce.Do(func() { close(s.stop) })
	s.ready.Store(false)
	s.upstream.CloseIdleConnections()
	s.mu.Lock()
	clear(s.sessions)
	s.mu.Unlock()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !s.ready.Load() {
			fail(w, http.StatusServiceUnavailable, "not_ready")
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /v1/session", s.createSession)
	mux.HandleFunc("POST /v1/relay", s.relay)
	mux.HandleFunc("GET /metrics", s.metrics)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		defer func() {
			if recover() != nil {
				s.failed.Add(1)
				panic(http.ErrAbortHandler)
			}
		}()
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) authorized(r *http.Request) bool {
	v := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
	return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") && subtle.ConstantTimeCompare(v[:], s.auth[:]) == 1
}

func decode(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	defer r.Body.Close()
	if kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || kind != "application/json" {
		return errors.New("JSON required")
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

func fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func (s *Server) prune(now time.Time) {
	for id, entry := range s.sessions {
		if !now.Before(entry.expires) {
			delete(s.sessions, id)
		}
	}
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	if !s.ready.Load() {
		fail(w, 503, "not_ready")
		return
	}
	select {
	case s.quotes <- struct{}{}:
		defer func() { <-s.quotes }()
	default:
		fail(w, 429, "busy")
		return
	}
	var input struct {
		Challenge []byte `json:"challenge"`
	}
	if decode(w, r, 1024, &input) != nil || len(input.Challenge) != 32 {
		fail(w, 400, "invalid_challenge")
		return
	}
	key, err := protocol.Key()
	if err != nil {
		fail(w, 503, "unavailable")
		return
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		fail(w, 503, "unavailable")
		return
	}
	e := protocol.Evidence{ID: hex.EncodeToString(id), PublicKey: key.PublicKey().Bytes(), ExpiresAt: time.Now().Add(protocol.SessionTTL).Unix(), PolicyHash: policy.Hash()}
	s.mu.Lock()
	s.prune(time.Now())
	full := len(s.sessions) >= maxSessions
	if !full {
		s.sessions[e.ID] = session{key, time.Unix(e.ExpiresAt, 0)}
	}
	s.mu.Unlock()
	if full {
		fail(w, 429, "busy")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	quote, err := s.provider.Quote(ctx, protocol.ReportData(e, input.Challenge))
	if err != nil {
		s.mu.Lock()
		delete(s.sessions, e.ID)
		s.mu.Unlock()
		fail(w, 503, "attestation_unavailable")
		return
	}
	e.Quote, e.EventLog = quote.Bytes, quote.EventLog
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(e)
}

func (s *Server) relay(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		fail(w, 401, "unauthorized")
		return
	}
	select {
	case s.requests <- struct{}{}:
		defer func() { <-s.requests }()
	default:
		fail(w, 429, "busy")
		return
	}
	var input protocol.Request
	if decode(w, r, protocol.MaxWireBody, &input) != nil {
		fail(w, 400, "invalid_request")
		return
	}
	s.mu.Lock()
	s.prune(time.Now())
	entry, ok := s.sessions[input.SessionID]
	delete(s.sessions, input.SessionID)
	s.mu.Unlock()
	if !ok {
		fail(w, 400, "invalid_session")
		return
	}
	var payload protocol.Payload
	if protocol.Open(entry.key, input.SessionID, "payload", input.Payload, &payload) != nil {
		fail(w, 400, "invalid_envelope")
		return
	}
	defer clear(payload.Body)
	defer clear(payload.ResponseKey)
	out, err := newStream(w, payload.ResponseKey, input.SessionID, protocol.Digest(input.Payload))
	if err != nil {
		fail(w, 400, "invalid_envelope")
		return
	}
	s.accepted.Add(1)
	s.active.Add(1)
	defer s.active.Add(-1)
	failure := func(code string) { s.failed.Add(1); _ = out.send(protocol.Frame{Type: "error", Code: code}) }
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	if payload.Tokenize != nil {
		if payload.Host != "" || len(payload.Body) != 0 || len(payload.Tokenize.Text) > 64<<10 {
			failure("invalid_tokenization")
			return
		}
		s.tokenize(out, payload.Tokenize, failure)
		return
	}
	var route protocol.Route
	if protocol.Open(entry.key, input.SessionID, "route", input.Route, &route) != nil || route.PayloadHash != protocol.Digest(input.Payload) || payload.Host != route.Host {
		failure("invalid_route")
		return
	}
	defer clear(route.ReceiptKey)
	if len(route.ReceiptKey) != 0 {
		out.receiptCipher, err = protocol.NewResponseCipher(route.ReceiptKey, input.SessionID, "receipt:"+protocol.Digest(input.Payload))
		if err != nil {
			failure("invalid_route")
			return
		}
	}
	if len(payload.Body) == 0 || len(payload.Body) > protocol.MaxBody || !json.Valid(payload.Body) {
		failure("invalid_body")
		return
	}
	target, err := policy.URL(route.Host, route.Path)
	if err != nil {
		failure("destination_denied")
		return
	}
	headers, err := policy.Headers(route.Headers)
	if err != nil {
		failure("headers_denied")
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(payload.Body))
	if err != nil {
		failure("invalid_request")
		return
	}
	req.Header = headers
	resp, err := s.upstream.Do(req)
	if err != nil {
		failure("upstream_unavailable")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		failure("redirect_denied")
		return
	}
	contentType := safeContentType(resp.Header.Get("Content-Type"))
	usage := &usageReader{kind: contentType, countOnly: route.Host == "ai-gateway.vercel.sh"}
	defer usage.disable()
	if out.send(protocol.Frame{Type: "head", Status: resp.StatusCode, ContentType: contentType}) != nil {
		return
	}
	buffer := make([]byte, protocol.ChunkSize)
	defer clear(buffer)
	var total int64
	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			usage.write(buffer[:n])
			total += int64(n)
			if total > protocol.MaxResponse {
				failure("response_too_large")
				return
			}
			if out.send(protocol.Frame{Type: "data", Data: buffer[:n]}) != nil {
				return
			}
		}
		if err == io.EOF {
			receipt := usage.finish()
			receipt.Status, receipt.Bytes = resp.StatusCode, total
			out.receipt = &receipt
			_ = out.send(protocol.Frame{Type: "end", Bytes: total})
			return
		}
		if err != nil {
			failure("upstream_interrupted")
			return
		}
	}
}

func safeContentType(value string) string {
	kind, _, _ := mime.ParseMediaType(value)
	switch kind {
	case "application/json", "text/event-stream", "application/vnd.amazon.eventstream":
		return kind
	}
	return "application/octet-stream"
}

func (s *Server) tokenize(out *stream, input *protocol.Tokenize, failure func(string)) {
	select {
	case s.tokenizers <- struct{}{}:
		defer func() { <-s.tokenizers }()
	default:
		failure("busy")
		return
	}
	if input.Encoding != "cl100k_base" && input.Encoding != "o200k_base" {
		failure("unsupported_encoding")
		return
	}
	codec, err := tokenizer.Get(tokenizer.Encoding(input.Encoding))
	if err != nil {
		failure("tokenizer_unavailable")
		return
	}
	count, err := codec.Count(input.Text)
	if err != nil {
		failure("tokenization_failed")
		return
	}
	body, _ := json.Marshal(map[string]any{"tokens": count, "encoding": input.Encoding, "scope": "text_only"})
	if out.send(protocol.Frame{Type: "head", Status: 200, ContentType: "application/json"}) != nil {
		return
	}
	if out.send(protocol.Frame{Type: "data", Data: body}) != nil {
		return
	}
	_ = out.send(protocol.Frame{Type: "end", Bytes: int64(len(body))})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		fail(w, 401, "unauthorized")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(w, "# TYPE gateway_requests_total counter\ngateway_requests_total %d\n# TYPE gateway_failures_total counter\ngateway_failures_total %d\n# TYPE gateway_active_requests gauge\ngateway_active_requests %d\n", s.accepted.Load(), s.failed.Load(), s.active.Load())
}

type stream struct {
	writer        http.ResponseWriter
	encoder       *json.Encoder
	cipher        *protocol.ResponseCipher
	receiptCipher *protocol.ResponseCipher
	receipt       *protocol.Receipt
}

func newStream(w http.ResponseWriter, rawKey []byte, id, payloadHash string) (*stream, error) {
	cipher, err := protocol.NewResponseCipher(rawKey, id, payloadHash)
	if err != nil {
		return nil, err
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Accel-Buffering", "no")
	encoder := json.NewEncoder(w)
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(15 * time.Second))
	return &stream{writer: w, encoder: encoder, cipher: cipher}, nil
}

func (s *stream) send(frame protocol.Frame) error {
	body, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	defer clear(body)
	ciphertext, err := s.cipher.Seal(body)
	if err != nil {
		return err
	}
	controller := http.NewResponseController(s.writer)
	_ = controller.SetWriteDeadline(time.Now().Add(15 * time.Second))
	wire := protocol.WireFrame{Ciphertext: ciphertext}
	if frame.Type == "end" && s.receipt != nil && s.receiptCipher != nil {
		data, err := json.Marshal(s.receipt)
		if err != nil {
			return err
		}
		wire.Receipt, err = s.receiptCipher.Seal(data)
		if err != nil {
			return err
		}
	}
	if err := s.encoder.Encode(wire); err != nil {
		return err
	}
	return controller.Flush()
}
