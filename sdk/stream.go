package sdk

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"

	"github.com/kitbuilder587/cheapgpt-confidential-gateway/protocol"
)

type Response struct {
	StatusCode  int
	ContentType string
	Body        io.ReadCloser
}

func (p *Prepared) OpenResponse(body io.ReadCloser) (*Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.opened {
		body.Close()
		return nil, errors.New("response already opened")
	}
	p.opened = true
	r := &reader{source: body, cipher: p.cipher, scanner: bufio.NewScanner(body)}
	r.scanner.Buffer(make([]byte, 4096), 128<<10)
	frame, err := r.next()
	if err != nil {
		body.Close()
		return nil, err
	}
	if frame.Type != "head" || frame.Status < 100 || frame.Status > 599 {
		body.Close()
		return nil, errors.New("invalid response header")
	}
	return &Response{StatusCode: frame.Status, ContentType: frame.ContentType, Body: r}, nil
}

type reader struct {
	source  io.ReadCloser
	cipher  *protocol.ResponseCipher
	scanner *bufio.Scanner
	pending []byte
	total   int64
	done    bool
	failure error
}

func (r *reader) next() (protocol.Frame, error) {
	var frame protocol.Frame
	if !r.scanner.Scan() {
		return frame, io.ErrUnexpectedEOF
	}
	var wire protocol.WireFrame
	if json.Unmarshal(r.scanner.Bytes(), &wire) != nil || len(wire.Ciphertext) == 0 {
		return frame, errors.New("invalid encrypted frame")
	}
	plain, err := r.cipher.Open(wire.Ciphertext)
	if err != nil {
		return frame, errors.New("response authentication failed")
	}
	defer clear(plain)
	if json.Unmarshal(plain, &frame) != nil {
		return frame, errors.New("invalid response frame")
	}
	if frame.Type == "error" {
		return frame, errors.New("gateway request failed")
	}
	return frame, nil
}

func (r *reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.failure != nil {
		return 0, r.failure
	}
	if r.done {
		return 0, io.EOF
	}
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		clear(r.pending[:n])
		r.pending = r.pending[n:]
		return n, nil
	}
	frame, err := r.next()
	if err != nil {
		r.failure = err
		return 0, err
	}
	switch frame.Type {
	case "data":
		r.total += int64(len(frame.Data))
		if len(frame.Data) == 0 || len(frame.Data) > protocol.ChunkSize || r.total > protocol.MaxResponse {
			r.failure = errors.New("response limit exceeded")
			return 0, r.failure
		}
		r.pending = frame.Data
		return r.Read(p)
	case "end":
		if frame.Bytes != r.total {
			r.failure = errors.New("response length mismatch")
			return 0, r.failure
		}
		r.done = true
		return 0, io.EOF
	default:
		r.failure = errors.New("unexpected response frame")
		return 0, r.failure
	}
}

func (r *reader) Close() error { clear(r.pending); r.done = true; return r.source.Close() }
