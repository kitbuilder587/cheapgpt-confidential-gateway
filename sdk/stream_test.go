package sdk

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/kitbuilder587/cheapgpt-confidential-gateway/protocol"
)

func fixture(t *testing.T, frames []protocol.Frame) (*Prepared, []byte) {
	t.Helper()
	key := bytes.Repeat([]byte{1}, 32)
	sender, _ := protocol.NewResponseCipher(key, "session", "hash")
	receiver, _ := protocol.NewResponseCipher(key, "session", "hash")
	var wire bytes.Buffer
	for _, frame := range frames {
		plain, _ := json.Marshal(frame)
		encrypted, _ := sender.Seal(plain)
		_ = json.NewEncoder(&wire).Encode(protocol.WireFrame{Ciphertext: encrypted})
	}
	return &Prepared{cipher: receiver}, wire.Bytes()
}

func TestResponseStream(t *testing.T) {
	p, wire := fixture(t, []protocol.Frame{{Type: "head", Status: 200, ContentType: "text/event-stream"}, {Type: "data", Data: []byte("private")}, {Type: "end", Bytes: 7}})
	resp, err := p.OpenResponse(io.NopCloser(bytes.NewReader(wire)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "private" {
		t.Fatalf("bad response: %v", err)
	}
	if _, err := p.OpenResponse(io.NopCloser(bytes.NewReader(wire))); err == nil {
		t.Fatal("response reopened")
	}
}

func TestTruncatedAndInvalidStreams(t *testing.T) {
	for _, frames := range [][]protocol.Frame{
		{{Type: "head", Status: 200}, {Type: "data", Data: []byte("partial")}},
		{{Type: "head", Status: 200}, {Type: "data", Data: []byte("partial")}, {Type: "end", Bytes: 2}},
		{{Type: "head", Status: 200}, {Type: "error", Code: "upstream_interrupted"}},
		{{Type: "head", Status: 200}, {Type: "head", Status: 200}},
	} {
		p, wire := fixture(t, frames)
		resp, err := p.OpenResponse(io.NopCloser(bytes.NewReader(wire)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(resp.Body); err == nil {
			t.Fatal("invalid stream accepted")
		}
		resp.Body.Close()
	}
	p, wire := fixture(t, []protocol.Frame{{Type: "head", Status: 200}, {Type: "end"}})
	lines := bytes.Split(bytes.TrimSpace(wire), []byte{'\n'})
	wire = append(append(lines[1], '\n'), lines[0]...)
	if _, err := p.OpenResponse(io.NopCloser(bytes.NewReader(wire))); err == nil {
		t.Fatal("reordered stream accepted")
	}
}

func TestSessionIsSingleUse(t *testing.T) {
	key, _ := protocol.Key()
	s := &Session{evidence: protocol.Evidence{ID: "session", PublicKey: key.PublicKey().Bytes(), ExpiresAt: time.Now().Add(time.Minute).Unix()}}
	payload := protocol.Payload{Host: "api.anthropic.com", Body: json.RawMessage(`{"messages":[]}`)}
	p, err := s.Prepare(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prepare(payload); err == nil {
		t.Fatal("session reused")
	}
	var decoded protocol.Payload
	if err := protocol.Open(key, "session", "payload", p.Request.Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.ResponseKey) != 32 || decoded.Host != payload.Host {
		t.Fatal("payload mismatch")
	}
	if _, err := s.SealRoute(p.Request.Payload, protocol.Route{Host: "api.anthropic.com", Path: "/v1/messages?beta=true"}); err != nil {
		t.Fatal(err)
	}
}
