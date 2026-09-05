package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kitbuilder587/cheapgpt-confidential-gateway/attestation"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/protocol"
)

const testToken = "test-only-token-0000000000000000000000"

type fakeProvider struct{ fail bool }

func (f fakeProvider) Quote(_ context.Context, data []byte) (attestation.Quote, error) {
	if f.fail {
		return attestation.Quote{}, errors.New("sensitive diagnostic")
	}
	return attestation.Quote{Bytes: append([]byte(nil), data...), EventLog: json.RawMessage(`[]`)}, nil
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(fakeProvider{}, testToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func call(s *Server, path string, input any, token string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(input)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func prepare(t *testing.T, s *Server, payload protocol.Payload, route protocol.Route) (protocol.Request, *protocol.ResponseCipher) {
	t.Helper()
	w := call(s, "/v1/session", map[string][]byte{"challenge": bytes.Repeat([]byte{7}, 32)}, "")
	if w.Code != 200 {
		t.Fatalf("session: %d", w.Code)
	}
	var e protocol.Evidence
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(e.Quote, protocol.ReportData(e, bytes.Repeat([]byte{7}, 32))) {
		t.Fatal("incorrect quote binding")
	}
	payload.ResponseKey = bytes.Repeat([]byte{9}, 32)
	sealed, err := protocol.Seal(e.PublicKey, e.ID, "payload", payload)
	if err != nil {
		t.Fatal(err)
	}
	route.PayloadHash = protocol.Digest(sealed)
	routed, err := protocol.Seal(e.PublicKey, e.ID, "route", route)
	if err != nil {
		t.Fatal(err)
	}
	cipher, _ := protocol.NewResponseCipher(payload.ResponseKey, e.ID, route.PayloadHash)
	return protocol.Request{SessionID: e.ID, Payload: sealed, Route: routed}, cipher
}

func frames(t *testing.T, wire []byte, cipher *protocol.ResponseCipher) []protocol.Frame {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(wire))
	var frames []protocol.Frame
	for {
		var w protocol.WireFrame
		if err := d.Decode(&w); err == io.EOF {
			return frames
		} else if err != nil {
			t.Fatal(err)
		}
		plain, err := cipher.Open(w.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		var frame protocol.Frame
		if err := json.Unmarshal(plain, &frame); err != nil {
			t.Fatal(err)
		}
		frames = append(frames, frame)
	}
}

func TestRelayEncryptionReceiptAndReplay(t *testing.T) {
	s := testServer(t)
	var calls atomic.Int64
	secret := "private-prompt-67b9"
	response := `{"content":"private-reply","usage":{"input_tokens":12,"output_tokens":4}}`
	s.upstream.Transport = roundTripper(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"input":"`+secret+`"}` || r.URL.String() != "https://chatgpt.com/backend-api/codex/responses" || r.Header.Get("Authorization") != "Bearer upstream-secret" {
			t.Fatal("request mismatch")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(response))}, nil
	})
	receiptKey := bytes.Repeat([]byte{8}, 32)
	input, cipher := prepare(t, s, protocol.Payload{Host: "chatgpt.com", Body: json.RawMessage(`{"input":"` + secret + `"}`)}, protocol.Route{Host: "chatgpt.com", Path: "/backend-api/codex/responses", Headers: map[string]string{"Authorization": "Bearer upstream-secret"}, ReceiptKey: receiptKey})
	w := call(s, "/v1/relay", input, testToken)
	if w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte(secret)) || bytes.Contains(w.Body.Bytes(), []byte("private-reply")) {
		t.Fatal("plaintext or failed relay")
	}
	got := frames(t, w.Body.Bytes(), cipher)
	if len(got) != 3 || got[0].Type != "head" || string(got[1].Data) != response || got[2].Type != "end" {
		t.Fatalf("unexpected frames: %d", len(got))
	}
	lines := bytes.Split(bytes.TrimSpace(w.Body.Bytes()), []byte{'\n'})
	var last protocol.WireFrame
	_ = json.Unmarshal(lines[len(lines)-1], &last)
	rc, _ := protocol.NewResponseCipher(receiptKey, input.SessionID, "receipt:"+protocol.Digest(input.Payload))
	plain, err := rc.Open(last.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	var receipt protocol.Receipt
	_ = json.Unmarshal(plain, &receipt)
	if !receipt.UsageAvailable || receipt.InputTokens != 12 || receipt.OutputTokens != 4 || receipt.Bytes != int64(len(response)) {
		t.Fatalf("bad receipt: %+v", receipt)
	}
	if w := call(s, "/v1/relay", input, testToken); w.Code != 400 {
		t.Fatal("replay accepted")
	}
	if calls.Load() != 1 {
		t.Fatal("replayed upstream request")
	}
}

func TestHostSubstitutionAndHeaderInjection(t *testing.T) {
	for _, route := range []protocol.Route{
		{Host: "openrouter.ai", Path: "/api/v1/responses"},
		{Host: "chatgpt.com", Path: "/backend-api/codex/responses", Headers: map[string]string{"Host": "evil.test"}},
		{Host: "chatgpt.com", Path: "//evil.test/path"},
	} {
		s := testServer(t)
		s.upstream.Transport = roundTripper(func(*http.Request) (*http.Response, error) {
			t.Fatal("denied request reached network")
			return nil, nil
		})
		input, cipher := prepare(t, s, protocol.Payload{Host: "chatgpt.com", Body: json.RawMessage(`{}`)}, route)
		got := frames(t, call(s, "/v1/relay", input, testToken).Body.Bytes(), cipher)
		if len(got) != 1 || got[0].Type != "error" {
			t.Fatal("expected encrypted error")
		}
	}
}

func TestRedirectAndTransportErrorsStayPrivate(t *testing.T) {
	for _, redirect := range []bool{false, true} {
		s := testServer(t)
		s.upstream.Transport = roundTripper(func(*http.Request) (*http.Response, error) {
			if !redirect {
				return nil, errors.New("private-path and secret-token")
			}
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://evil.test/"}}, Body: io.NopCloser(strings.NewReader("private-error"))}, nil
		})
		input, cipher := prepare(t, s, protocol.Payload{Host: "chatgpt.com", Body: json.RawMessage(`{}`)}, protocol.Route{Host: "chatgpt.com", Path: "/backend-api/codex/responses"})
		w := call(s, "/v1/relay", input, testToken)
		got := frames(t, w.Body.Bytes(), cipher)
		if len(got) != 1 || got[0].Type != "error" || strings.Contains(string(got[0].Data), "private") {
			t.Fatal("unsafe error")
		}
	}
}

func TestAuthLimitsExpiryAndTokenizer(t *testing.T) {
	s := testServer(t)
	if w := call(s, "/v1/relay", protocol.Request{}, "wrong"); w.Code != 401 {
		t.Fatal("unauthorized accepted")
	}
	input, cipher := prepare(t, s, protocol.Payload{Tokenize: &protocol.Tokenize{Encoding: "cl100k_base", Text: "hello world"}}, protocol.Route{})
	got := frames(t, call(s, "/v1/relay", input, testToken).Body.Bytes(), cipher)
	if len(got) != 3 || !bytes.Contains(got[1].Data, []byte(`"tokens":2`)) {
		t.Fatal("tokenization failed")
	}
	input, _ = prepare(t, s, protocol.Payload{Host: "chatgpt.com", Body: json.RawMessage(`{}`)}, protocol.Route{})
	entry := s.sessions[input.SessionID]
	entry.expires = time.Now().Add(-time.Second)
	s.sessions[input.SessionID] = entry
	if w := call(s, "/v1/relay", input, testToken); w.Code != 400 {
		t.Fatal("expired session accepted")
	}
	for i := 0; i < maxSessions; i++ {
		s.sessions[string(rune(i))] = session{expires: time.Now().Add(time.Hour)}
	}
	if w := call(s, "/v1/session", map[string][]byte{"challenge": make([]byte, 32)}, ""); w.Code != 429 {
		t.Fatal("session capacity exceeded")
	}
}

func TestAttestationFailureDoesNotCreateSession(t *testing.T) {
	s := testServer(t)
	s.provider = fakeProvider{fail: true}
	w := call(s, "/v1/session", map[string][]byte{"challenge": make([]byte, 32)}, "")
	if w.Code != 503 || len(s.sessions) != 0 || strings.Contains(w.Body.String(), "sensitive") {
		t.Fatal("unsafe attestation failure")
	}
}

func TestCancellationReachesUpstream(t *testing.T) {
	s := testServer(t)
	called := make(chan struct{})
	s.upstream.Transport = roundTripper(func(r *http.Request) (*http.Response, error) {
		close(called)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	input, _ := prepare(t, s, protocol.Payload{Host: "chatgpt.com", Body: json.RawMessage(`{}`)}, protocol.Route{Host: "chatgpt.com", Path: "/backend-api/codex/responses"})
	data, _ := json.Marshal(input)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("POST", "/v1/relay", bytes.NewReader(data)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+testToken)
	done := make(chan struct{})
	go func() { s.Handler().ServeHTTP(httptest.NewRecorder(), r); close(done) }()
	<-called
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("upstream not cancelled")
	}
}

func TestUsageDoesNotReadGeneratedContent(t *testing.T) {
	u := &usageReader{kind: "text/event-stream"}
	for _, part := range []string{"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":17}}}\n\n", "data: {\"delta\":{\"text\":\"{\\\"usage\\\":{\\\"input_tokens\\\":999}}\"}}\n\n", "data: {\"usage\":{\"output_tokens\":9}}\n\n"} {
		for _, b := range []byte(part) {
			u.write([]byte{b})
		}
	}
	r := u.finish()
	if r.InputTokens != 17 || r.OutputTokens != 9 || !r.UsageAvailable {
		t.Fatalf("bad usage: %+v", r)
	}
	u = &usageReader{kind: "application/json"}
	u.write(bytes.Repeat([]byte{'a'}, maxUsageBuffer+1))
	if u.finish().UsageAvailable || !u.disabled {
		t.Fatal("unbounded usage buffer")
	}
}
