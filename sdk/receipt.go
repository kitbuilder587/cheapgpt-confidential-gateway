package sdk

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"

	"github.com/kitbuilder587/cheapgpt-confidential-gateway/protocol"
)

type Routing struct {
	Envelope []byte
	cipher   *protocol.ResponseCipher
	mu       sync.Mutex
	used     bool
}

func (s *Session) PrepareRoute(payload []byte, route protocol.Route) (*Routing, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	defer clear(key)
	route.ReceiptKey = key
	envelope, err := s.SealRoute(payload, route)
	if err != nil {
		return nil, err
	}
	cipher, err := protocol.NewResponseCipher(key, s.evidence.ID, "receipt:"+protocol.Digest(payload))
	if err != nil {
		return nil, err
	}
	return &Routing{Envelope: envelope, cipher: cipher}, nil
}

func (r *Routing) OpenReceipt(wire protocol.WireFrame) (protocol.Receipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var receipt protocol.Receipt
	if r.used || len(wire.Receipt) == 0 {
		return receipt, errors.New("receipt unavailable")
	}
	plain, err := r.cipher.Open(wire.Receipt)
	if err != nil {
		return receipt, errors.New("receipt authentication failed")
	}
	defer clear(plain)
	if json.Unmarshal(plain, &receipt) != nil {
		return receipt, errors.New("invalid receipt")
	}
	r.used = true
	return receipt, nil
}
