package attestation

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

func TestDstackUnixSocket(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "dstack.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	report := bytes.Repeat([]byte{3}, 64)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/GetQuote" || r.Method != "POST" {
			t.Error("wrong RPC")
		}
		var input map[string]string
		_ = json.NewDecoder(r.Body).Decode(&input)
		if input["report_data"] != hex.EncodeToString(report) {
			t.Error("wrong report data")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"quote": "010203", "event_log": "[]"})
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	q, err := NewDstack(socket).Quote(context.Background(), report)
	if err != nil || !bytes.Equal(q.Bytes, []byte{1, 2, 3}) {
		t.Fatalf("quote failed: %v", err)
	}
}
