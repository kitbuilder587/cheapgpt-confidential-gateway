package attestation

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

type Quote struct {
	Bytes    []byte
	EventLog json.RawMessage
}

type Provider interface {
	Quote(context.Context, []byte) (Quote, error)
}

type Dstack struct{ client *http.Client }

func NewDstack(socket string) *Dstack {
	return &Dstack{client: &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}},
	}}
}

func (d *Dstack) Quote(ctx context.Context, reportData []byte) (Quote, error) {
	if len(reportData) != 64 {
		return Quote{}, errors.New("invalid report data")
	}
	body, _ := json.Marshal(map[string]string{"report_data": hex.EncodeToString(reportData)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/GetQuote", bytes.NewReader(body))
	if err != nil {
		return Quote{}, errors.New("attestation unavailable")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return Quote{}, errors.New("attestation unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Quote{}, errors.New("attestation unavailable")
	}
	var wire struct {
		Quote    string `json:"quote"`
		EventLog string `json:"event_log"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&wire); err != nil {
		return Quote{}, errors.New("invalid attestation")
	}
	quote, err := hex.DecodeString(wire.Quote)
	if err != nil || len(quote) == 0 || !json.Valid([]byte(wire.EventLog)) {
		return Quote{}, errors.New("invalid attestation")
	}
	return Quote{Bytes: quote, EventLog: json.RawMessage(wire.EventLog)}, nil
}
