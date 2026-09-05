package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kitbuilder587/cheapgpt-confidential-gateway/attestation"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/internal/gateway"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/protocol"
)

type syntheticEvidence struct{}

func (syntheticEvidence) Quote(_ context.Context, data []byte) (attestation.Quote, error) {
	return attestation.Quote{Bytes: bytes.Clone(data), EventLog: json.RawMessage(`[]`)}, nil
}

func TestEncryptedTokenizationOverHTTP(t *testing.T) {
	const token = "test-service-token-00000000000000000"
	server, err := gateway.New(syntheticEvidence{}, token)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewTLSServer(server.Handler())
	defer httpServer.Close()
	client := &Client{base: httpServer.URL, http: httpServer.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	challenge := bytes.Repeat([]byte{3}, 32)
	data, _ := json.Marshal(map[string][]byte{"challenge": challenge})
	response, err := client.http.Post(client.base+"/v1/session", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var e protocol.Evidence
	if err := json.NewDecoder(response.Body).Decode(&e); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	// Synthetic evidence is injected only in this test; the public SDK rejects it.
	session := &Session{evidence: e, challenge: challenge}
	prepared, err := session.Prepare(protocol.Payload{Tokenize: &protocol.Tokenize{Encoding: "cl100k_base", Text: "hello world"}})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := client.Relay(ctx, prepared.Request, token)
	if err != nil {
		t.Fatal(err)
	}
	result, err := prepared.OpenResponse(wire)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Body.Close()
	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"tokens":2`)) {
		t.Fatalf("unexpected result: %s", body)
	}
	if _, err := client.Session(ctx); err == nil {
		t.Fatal("public SDK accepted synthetic evidence")
	}
}

func TestReceiptAuthentication(t *testing.T) {
	key, _ := protocol.Key()
	session := &Session{evidence: protocol.Evidence{ID: "session", PublicKey: key.PublicKey().Bytes(), ExpiresAt: time.Now().Add(time.Minute).Unix()}}
	payload := []byte("opaque-ciphertext")
	routing, err := session.PrepareRoute(payload, protocol.Route{Host: "api.anthropic.com", Path: "/v1/messages?beta=true"})
	if err != nil {
		t.Fatal(err)
	}
	var route protocol.Route
	if err := protocol.Open(key, "session", "route", routing.Envelope, &route); err != nil {
		t.Fatal(err)
	}
	cipher, _ := protocol.NewResponseCipher(route.ReceiptKey, "session", "receipt:"+protocol.Digest(payload))
	body, _ := json.Marshal(protocol.Receipt{Status: 200, Bytes: 1024, UsageAvailable: true, InputTokens: 12, OutputTokens: 8})
	encrypted, _ := cipher.Seal(body)
	bad := bytes.Clone(encrypted)
	bad[len(bad)-1] ^= 1
	if _, err := routing.OpenReceipt(protocol.WireFrame{Receipt: bad}); err == nil {
		t.Fatal("tampered receipt accepted")
	}
	receipt, err := routing.OpenReceipt(protocol.WireFrame{Receipt: encrypted})
	if err != nil || receipt.InputTokens != 12 {
		t.Fatal("valid receipt rejected")
	}
	if _, err := routing.OpenReceipt(protocol.WireFrame{Receipt: encrypted}); err == nil {
		t.Fatal("replayed receipt accepted")
	}
}
