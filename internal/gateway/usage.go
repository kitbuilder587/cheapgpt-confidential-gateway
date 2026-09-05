package gateway

import (
	"bytes"
	"encoding/json"
	"strconv"

	"github.com/kitbuilder587/cheapgpt-confidential-gateway/protocol"
)

type usageReader struct {
	kind        string
	buffer      []byte
	event       []byte
	disabled    bool
	receipt     protocol.Receipt
	inputKnown  bool
	outputKnown bool
	countOnly   bool
}

const maxUsageBuffer = 1 << 20

func (u *usageReader) write(data []byte) {
	if u.disabled {
		return
	}
	if u.kind != "application/json" && u.kind != "text/event-stream" {
		return
	}
	u.buffer = append(u.buffer, data...)
	if len(u.buffer) > maxUsageBuffer {
		u.disable()
		return
	}
	if u.kind != "text/event-stream" {
		return
	}
	for {
		idx := bytes.IndexByte(u.buffer, '\n')
		if idx < 0 {
			break
		}
		line := bytes.TrimSuffix(u.buffer[:idx], []byte{'\r'})
		if len(line) == 0 {
			u.consume(u.event)
			clear(u.event)
			u.event = u.event[:0]
		} else if bytes.HasPrefix(line, []byte("data:")) {
			part := bytes.TrimPrefix(line[5:], []byte{' '})
			if len(u.event) > 0 {
				u.event = append(u.event, '\n')
			}
			u.event = append(u.event, part...)
			if len(u.event) > maxUsageBuffer {
				u.disable()
				return
			}
		}
		u.buffer = u.buffer[idx+1:]
	}
}

func (u *usageReader) finish() protocol.Receipt {
	if !u.disabled && u.kind == "application/json" {
		u.consume(u.buffer)
	}
	clear(u.buffer)
	clear(u.event)
	u.receipt.UsageAvailable = !u.disabled && u.inputKnown && (u.outputKnown || u.countOnly)
	return u.receipt
}

func (u *usageReader) disable() {
	clear(u.buffer)
	clear(u.event)
	u.buffer, u.event = nil, nil
	u.disabled = true
	u.receipt = protocol.Receipt{}
}

func (u *usageReader) consume(data []byte) {
	var object map[string]json.RawMessage
	if json.Unmarshal(data, &object) != nil {
		return
	}
	u.extract(object)
	for _, name := range []string{"response", "message"} {
		var nested map[string]json.RawMessage
		if json.Unmarshal(object[name], &nested) == nil {
			u.extract(nested)
		}
	}
}

func (u *usageReader) extract(object map[string]json.RawMessage) {
	for _, name := range []string{"usage", "usageMetadata"} {
		var usage map[string]json.RawMessage
		if json.Unmarshal(object[name], &usage) != nil {
			continue
		}
		input, inputOK := number(usage, "input_tokens", "prompt_tokens", "promptTokenCount")
		output, outputOK := number(usage, "output_tokens", "completion_tokens", "candidatesTokenCount")
		cached, _ := number(usage, "cache_read_input_tokens", "cachedContentTokenCount")
		for _, key := range []string{"prompt_tokens_details", "input_tokens_details"} {
			var details map[string]json.RawMessage
			if json.Unmarshal(usage[key], &details) == nil {
				if n, ok := number(details, "cached_tokens"); ok {
					cached = n
				}
			}
		}
		if inputOK {
			u.receipt.InputTokens = input
			u.inputKnown = true
		}
		if outputOK {
			u.receipt.OutputTokens = output
			u.outputKnown = true
		}
		if cached > u.receipt.CachedInputTokens {
			u.receipt.CachedInputTokens = cached
		}
	}
	if count, ok := number(object, "input_tokens"); ok {
		u.receipt.InputTokens, u.inputKnown = count, true
	}
}

func number(object map[string]json.RawMessage, keys ...string) (int64, bool) {
	for _, key := range keys {
		value, ok := object[key]
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(string(value), 10, 64)
		if err == nil && n >= 0 && n <= 1_000_000_000 {
			return n, true
		}
	}
	return 0, false
}
