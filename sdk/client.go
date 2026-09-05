package sdk

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kitbuilder587/cheapgpt-confidential-gateway/attestation"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/policy"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/protocol"
)

type Client struct {
	base   string
	http   *http.Client
	policy attestation.Policy
}

func New(baseURL string, approved attestation.Policy) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("HTTPS gateway URL required")
	}
	if err := approved.Validate(); err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Client{base: strings.TrimRight(baseURL, "/"), policy: approved, http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

type Session struct {
	evidence  protocol.Evidence
	challenge []byte
	mu        sync.Mutex
	used      bool
}

func (c *Client) Session(ctx context.Context) (*Session, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	data, _ := json.Marshal(map[string][]byte{"challenge": challenge})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/session", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("session unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("session rejected")
	}
	var e protocol.Evidence
	if json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&e) != nil {
		return nil, errors.New("invalid evidence")
	}
	return VerifySession(ctx, e, challenge, c.policy)
}

type Proof struct {
	Evidence  protocol.Evidence `json:"evidence"`
	Challenge []byte            `json:"challenge"`
}

func VerifySession(ctx context.Context, e protocol.Evidence, challenge []byte, approved attestation.Policy) (*Session, error) {
	e.PublicKey = bytes.Clone(e.PublicKey)
	e.Quote = bytes.Clone(e.Quote)
	e.EventLog = bytes.Clone(e.EventLog)
	challenge = bytes.Clone(challenge)
	if err := attestation.Verify(ctx, e, challenge, approved); err != nil {
		return nil, err
	}
	return &Session{evidence: e, challenge: challenge}, nil
}

func (s *Session) Proof() Proof {
	e := s.evidence
	e.PublicKey = bytes.Clone(e.PublicKey)
	e.Quote = bytes.Clone(e.Quote)
	e.EventLog = bytes.Clone(e.EventLog)
	return Proof{Evidence: e, Challenge: bytes.Clone(s.challenge)}
}

type Prepared struct {
	Request protocol.Request
	cipher  *protocol.ResponseCipher
	mu      sync.Mutex
	opened  bool
}

func (s *Session) Prepare(payload protocol.Payload) (*Prepared, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used || time.Now().Unix() >= s.evidence.ExpiresAt {
		return nil, errors.New("session unavailable")
	}
	if payload.Tokenize == nil && !policy.HostAllowed(payload.Host) {
		return nil, errors.New("destination denied")
	}
	if len(payload.Body) > protocol.MaxBody {
		return nil, errors.New("body too large")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	defer clear(key)
	payload.ResponseKey = key
	encrypted, err := protocol.Seal(s.evidence.PublicKey, s.evidence.ID, "payload", payload)
	if err != nil {
		return nil, err
	}
	cipher, err := protocol.NewResponseCipher(key, s.evidence.ID, protocol.Digest(encrypted))
	if err != nil {
		return nil, err
	}
	s.used = true
	return &Prepared{Request: protocol.Request{SessionID: s.evidence.ID, Payload: encrypted}, cipher: cipher}, nil
}

func (s *Session) SealRoute(payload []byte, route protocol.Route) ([]byte, error) {
	if time.Now().Unix() >= s.evidence.ExpiresAt {
		return nil, errors.New("session expired")
	}
	if _, err := policy.URL(route.Host, route.Path); err != nil {
		return nil, err
	}
	if _, err := policy.Headers(route.Headers); err != nil {
		return nil, err
	}
	route.PayloadHash = protocol.Digest(payload)
	return protocol.Seal(s.evidence.PublicKey, s.evidence.ID, "route", route)
}

func (c *Client) Relay(ctx context.Context, input protocol.Request, gatewayToken string) (io.ReadCloser, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/relay", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+gatewayToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("relay unavailable")
	}
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/x-ndjson" {
		resp.Body.Close()
		return nil, errors.New("relay rejected")
	}
	return resp.Body, nil
}
