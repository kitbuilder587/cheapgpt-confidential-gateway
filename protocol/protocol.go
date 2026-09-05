package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const Version = "cgw/1"
const SessionTTL = 5 * time.Minute
const MaxBody = 2 << 20
const MaxWireBody = 4 << 20
const MaxResponse = 64 << 20
const ChunkSize = 32 << 10

type Evidence struct {
	ID         string          `json:"id"`
	PublicKey  []byte          `json:"public_key"`
	ExpiresAt  int64           `json:"expires_at"`
	PolicyHash string          `json:"policy_hash"`
	Quote      []byte          `json:"quote"`
	EventLog   json.RawMessage `json:"event_log"`
}

type Payload struct {
	Host        string          `json:"host"`
	Body        json.RawMessage `json:"body,omitempty"`
	ResponseKey []byte          `json:"response_key"`
	Tokenize    *Tokenize       `json:"tokenize,omitempty"`
}

type Tokenize struct {
	Encoding string `json:"encoding"`
	Text     string `json:"text"`
}

type Route struct {
	Host        string            `json:"host"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers"`
	PayloadHash string            `json:"payload_hash"`
	ReceiptKey  []byte            `json:"receipt_key,omitempty"`
}

type Request struct {
	SessionID string `json:"session_id"`
	Payload   []byte `json:"payload"`
	Route     []byte `json:"route"`
}

type Frame struct {
	Type        string `json:"type"`
	Status      int    `json:"status,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Data        []byte `json:"data,omitempty"`
	Code        string `json:"code,omitempty"`
	Bytes       int64  `json:"bytes,omitempty"`
}

type WireFrame struct {
	Ciphertext []byte `json:"ciphertext,omitempty"`
	Receipt    []byte `json:"receipt,omitempty"`
}

type Receipt struct {
	Status            int   `json:"status"`
	Bytes             int64 `json:"bytes"`
	UsageAvailable    bool  `json:"usage_available"`
	InputTokens       int64 `json:"input_tokens"`
	OutputTokens      int64 `json:"output_tokens"`
	CachedInputTokens int64 `json:"cached_input_tokens"`
}

func Digest(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func ReportData(e Evidence, challenge []byte) []byte {
	data, _ := json.Marshal(struct {
		Version   string `json:"version"`
		ID        string `json:"id"`
		Key       []byte `json:"key"`
		Expires   int64  `json:"expires"`
		Policy    string `json:"policy"`
		Challenge []byte `json:"challenge"`
	}{Version, e.ID, e.PublicKey, e.ExpiresAt, e.PolicyHash, challenge})
	sum := sha512.Sum512(data)
	return sum[:]
}

func Info(id, purpose string) []byte {
	return []byte(Version + "\x00" + id + "\x00" + purpose)
}

func Key() (hpke.PrivateKey, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return hpke.NewDHKEMPrivateKey(k)
}

func Public(raw []byte) (hpke.PublicKey, error) {
	k, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, errors.New("invalid public key")
	}
	return hpke.NewDHKEMPublicKey(k)
}

func Seal(rawKey []byte, id, purpose string, value any) ([]byte, error) {
	k, err := Public(rawKey)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	return hpke.Seal(k, hpke.HKDFSHA256(), hpke.AES256GCM(), Info(id, purpose), data)
}

func Open(key hpke.PrivateKey, id, purpose string, ciphertext []byte, value any) error {
	data, err := hpke.Open(key, hpke.HKDFSHA256(), hpke.AES256GCM(), Info(id, purpose), ciphertext)
	if err != nil {
		return errors.New("invalid envelope")
	}
	defer clear(data)
	return json.Unmarshal(data, value)
}

type ResponseCipher struct {
	aead     cipher.AEAD
	sequence uint64
	aad      []byte
}

func NewResponseCipher(key []byte, id, payloadHash string) (*ResponseCipher, error) {
	if len(key) != 32 {
		return nil, errors.New("invalid response key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &ResponseCipher{aead: aead, aad: Info(id, "response:"+payloadHash)}, nil
}

func (s *ResponseCipher) nonce() []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.sequence)
	return nonce
}

func (s *ResponseCipher) Seal(data []byte) ([]byte, error) {
	if s.sequence >= 1<<32 {
		return nil, errors.New("frame limit exceeded")
	}
	out := s.aead.Seal(nil, s.nonce(), data, s.aad)
	s.sequence++
	return out, nil
}

func (s *ResponseCipher) Open(data []byte) ([]byte, error) {
	if s.sequence >= 1<<32 {
		return nil, errors.New("frame limit exceeded")
	}
	out, err := s.aead.Open(nil, s.nonce(), data, s.aad)
	if err == nil {
		s.sequence++
	}
	return out, err
}
