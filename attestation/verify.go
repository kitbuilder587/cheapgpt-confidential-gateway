package attestation

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/policy"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/protocol"
)

type Policy struct {
	MRTD        string `json:"mrtd"`
	RTMR0       string `json:"rtmr0"`
	RTMR1       string `json:"rtmr1"`
	RTMR2       string `json:"rtmr2"`
	ComposeHash string `json:"compose_hash"`
}

func (p Policy) Validate() error {
	for name, field := range map[string]string{"mrtd": p.MRTD, "rtmr0": p.RTMR0, "rtmr1": p.RTMR1, "rtmr2": p.RTMR2, "compose_hash": p.ComposeHash} {
		n := 48
		if name == "compose_hash" {
			n = 32
		}
		b, err := hex.DecodeString(field)
		if err != nil || len(b) != n || ((name == "mrtd" || name == "compose_hash") && bytes.Equal(b, make([]byte, n))) {
			return fmt.Errorf("missing approved %s", name)
		}
	}
	return nil
}

func Verify(ctx context.Context, e protocol.Evidence, challenge []byte, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if len(challenge) != 32 || len(e.PublicKey) != 32 || len(e.ID) != 64 || e.PolicyHash != policy.Hash() {
		return errors.New("invalid attested identity")
	}
	if _, err := hex.DecodeString(e.ID); err != nil {
		return errors.New("invalid session")
	}
	remaining := time.Until(time.Unix(e.ExpiresAt, 0))
	if remaining <= 0 || remaining > protocol.SessionTTL {
		return errors.New("expired or invalid session")
	}
	if len(e.Quote) > 64<<10 || len(e.EventLog) > 1<<20 {
		return errors.New("evidence too large")
	}
	quote, err := abi.QuoteToProto(e.Quote)
	if err != nil {
		return errors.New("invalid TDX quote")
	}
	opts := verify.DefaultOptions()
	opts.CheckRevocations, opts.GetCollateral = true, true
	opts.Getter = collateralGetter{ctx: ctx}
	if err := verify.TdxQuoteContext(ctx, quote, opts); err != nil {
		return fmt.Errorf("TDX verification failed: %w", err)
	}
	var body tdBody
	switch q := quote.(type) {
	case *pb.QuoteV4:
		body = q.GetTdQuoteBody()
	case *pb.QuoteV5:
		body = q.GetTdQuoteBodyDescriptor().GetTdQuoteBodyV5()
	default:
		return errors.New("unsupported TDX quote")
	}
	if err := checkBody(body, protocol.ReportData(e, challenge), p); err != nil {
		return err
	}
	return checkEvents(e.EventLog, body.GetRtmrs()[3], p.ComposeHash)
}

type tdBody interface {
	GetTdAttributes() []byte
	GetMrTd() []byte
	GetRtmrs() [][]byte
	GetReportData() []byte
}

func checkBody(body tdBody, report []byte, p Policy) error {
	attrs := body.GetTdAttributes()
	if len(attrs) != 8 || binary.LittleEndian.Uint64(attrs)&1 != 0 {
		return errors.New("debug TEE denied")
	}
	if !bytes.Equal(body.GetReportData(), report) {
		return errors.New("attestation key or challenge mismatch")
	}
	registers := body.GetRtmrs()
	if len(registers) != 4 {
		return errors.New("invalid measurements")
	}
	for _, r := range registers {
		if len(r) != 48 {
			return errors.New("invalid measurements")
		}
	}
	for _, measurement := range []struct {
		expected string
		actual   []byte
	}{{p.MRTD, body.GetMrTd()}, {p.RTMR0, registers[0]}, {p.RTMR1, registers[1]}, {p.RTMR2, registers[2]}} {
		if !strings.EqualFold(measurement.expected, hex.EncodeToString(measurement.actual)) {
			return errors.New("unapproved boot measurements")
		}
	}
	return nil
}

type event struct {
	IMR      uint32 `json:"imr"`
	Type     uint32 `json:"event_type"`
	Digest   string `json:"digest"`
	Name     string `json:"event"`
	Payload  string `json:"event_payload"`
	Version  int    `json:"version"`
	Preimage string `json:"preimage"`
}

func checkEvents(raw []byte, expected []byte, compose string) error {
	var events []event
	if err := json.Unmarshal(raw, &events); err != nil || len(events) == 0 || len(events) > 4096 {
		return errors.New("invalid event log")
	}
	register := make([]byte, 48)
	composeCount, bootCount := 0, 0
	for _, e := range events {
		if e.IMR != 3 {
			continue
		}
		if e.Type != 0x08000001 {
			return errors.New("unsupported runtime event")
		}
		payload, err := hex.DecodeString(e.Payload)
		if err != nil {
			return errors.New("invalid event payload")
		}
		var preimage []byte
		switch e.Version {
		case 0, 1:
			preimage = binary.LittleEndian.AppendUint32(nil, e.Type)
			preimage = append(preimage, []byte(":"+e.Name+":")...)
			preimage = append(preimage, payload...)
		case 2:
			preimage, err = hex.DecodeString(e.Preimage)
			if err != nil {
				return errors.New("invalid event preimage")
			}
			var content struct {
				Name    string `json:"name"`
				Payload string `json:"payload"`
				Type    uint32 `json:"type"`
			}
			if json.Unmarshal(preimage, &content) != nil || content.Name != e.Name || content.Payload != e.Payload || content.Type != e.Type {
				return errors.New("event preimage mismatch")
			}
		default:
			return errors.New("unsupported event version")
		}
		digest := sha512.Sum384(preimage)
		if !strings.EqualFold(hex.EncodeToString(digest[:]), e.Digest) {
			return errors.New("event digest mismatch")
		}
		h := sha512.New384()
		h.Write(register)
		h.Write(digest[:])
		register = h.Sum(nil)
		if e.Name == "compose-hash" {
			composeCount++
			if bootCount != 0 || !strings.EqualFold(hex.EncodeToString(payload), compose) {
				return errors.New("unapproved application")
			}
		}
		if e.Name == "boot-mr-done" {
			bootCount++
		}
	}
	if composeCount != 1 || bootCount != 1 || !bytes.Equal(register, expected) {
		return errors.New("runtime measurement mismatch")
	}
	return nil
}

type collateralGetter struct{ ctx context.Context }

func (g collateralGetter) Get(address string) (map[string][]string, []byte, error) {
	u, err := url.Parse(address)
	if err != nil || u.User != nil || u.Port() != "" {
		return nil, nil, errors.New("collateral URL denied")
	}
	switch u.Host {
	case "api.trustedservices.intel.com", "certificates.trustedservices.intel.com", "certs.trustedservices.intel.com":
	default:
		return nil, nil, errors.New("collateral host denied")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, nil, errors.New("collateral scheme denied")
	}
	u.Scheme = "https"
	req, err := http.NewRequestWithContext(g.ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, errors.New("collateral unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
	if len(body) > 4<<20 {
		return nil, nil, errors.New("collateral too large")
	}
	return resp.Header, body, err
}
