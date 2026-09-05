package protocol

import (
	"bytes"
	"testing"
)

func TestEnvelopeBinding(t *testing.T) {
	k, err := Key()
	if err != nil {
		t.Fatal(err)
	}
	data, err := Seal(k.PublicKey().Bytes(), "session", "payload", map[string]string{"prompt": "private text"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("private text")) {
		t.Fatal("plaintext on wire")
	}
	var value map[string]string
	if err := Open(k, "session", "payload", data, &value); err != nil || value["prompt"] != "private text" {
		t.Fatalf("roundtrip: %v", err)
	}
	if Open(k, "other", "payload", data, &value) == nil {
		t.Fatal("session substitution accepted")
	}
	if Open(k, "session", "route", data, &value) == nil {
		t.Fatal("purpose substitution accepted")
	}
	data[len(data)-1] ^= 1
	if Open(k, "session", "payload", data, &value) == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestResponseOrderAndBinding(t *testing.T) {
	key := bytes.Repeat([]byte{5}, 32)
	sender, _ := NewResponseCipher(key, "session", "payload")
	a, _ := sender.Seal([]byte("first"))
	b, _ := sender.Seal([]byte("second"))
	receiver, _ := NewResponseCipher(key, "session", "payload")
	if _, err := receiver.Open(b); err == nil {
		t.Fatal("reordered frame accepted")
	}
	if p, err := receiver.Open(a); err != nil || string(p) != "first" {
		t.Fatal("valid first frame rejected")
	}
	if _, err := receiver.Open(a); err == nil {
		t.Fatal("replayed frame accepted")
	}
	if _, err := receiver.Open(b); err != nil {
		t.Fatal(err)
	}
	other, _ := NewResponseCipher(key, "session", "other-payload")
	if _, err := other.Open(a); err == nil {
		t.Fatal("cross-request frame accepted")
	}
}

func FuzzOpen(f *testing.F) {
	k, _ := Key()
	f.Add([]byte("invalid"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > MaxWireBody {
			t.Skip()
		}
		var out Payload
		_ = Open(k, "session", "payload", input, &out)
	})
}
