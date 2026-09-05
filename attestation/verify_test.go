package attestation

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/policy"
	"github.com/kitbuilder587/cheapgpt-confidential-gateway/protocol"
)

func testPolicy() Policy {
	return Policy{MRTD: strings.Repeat("01", 48), RTMR0: strings.Repeat("02", 48), RTMR1: strings.Repeat("03", 48), RTMR2: strings.Repeat("04", 48), ComposeHash: strings.Repeat("05", 32)}
}

func testBody() *pb.TDQuoteBody {
	p := testPolicy()
	decode := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	return &pb.TDQuoteBody{TdAttributes: make([]byte, 8), MrTd: decode(p.MRTD), Rtmrs: [][]byte{decode(p.RTMR0), decode(p.RTMR1), decode(p.RTMR2), make([]byte, 48)}, ReportData: make([]byte, 64)}
}

func TestMeasurementsAndReportBinding(t *testing.T) {
	p := testPolicy()
	if err := checkBody(testBody(), make([]byte, 64), p); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*pb.TDQuoteBody){
		func(b *pb.TDQuoteBody) { b.TdAttributes[0] = 1 },
		func(b *pb.TDQuoteBody) { b.ReportData[0] = 1 },
		func(b *pb.TDQuoteBody) { b.Rtmrs[0][0] ^= 1 },
		func(b *pb.TDQuoteBody) { b.MrTd[0] ^= 1 },
		func(b *pb.TDQuoteBody) { b.Rtmrs = nil },
	} {
		b := testBody()
		change(b)
		if checkBody(b, make([]byte, 64), p) == nil {
			t.Fatal("unsafe quote accepted")
		}
	}
	if (Policy{}).Validate() == nil {
		t.Fatal("empty policy accepted")
	}
	p.RTMR2 = strings.Repeat("00", 48)
	if err := p.Validate(); err != nil {
		t.Fatal("explicitly approved empty register rejected")
	}
}

func eventsFixture(version int) ([]event, []byte) {
	items := []event{{IMR: 3, Type: 0x08000001, Name: "compose-hash", Payload: testPolicy().ComposeHash, Version: version}, {IMR: 3, Type: 0x08000001, Name: "boot-mr-done", Payload: "", Version: version}}
	r := make([]byte, 48)
	for i := range items {
		e := &items[i]
		payload, _ := hex.DecodeString(e.Payload)
		preimage := binary.LittleEndian.AppendUint32(nil, e.Type)
		preimage = append(preimage, []byte(":"+e.Name+":")...)
		preimage = append(preimage, payload...)
		if version == 2 {
			preimage, _ = json.Marshal(map[string]any{"name": e.Name, "payload": e.Payload, "type": e.Type})
			e.Preimage = hex.EncodeToString(preimage)
		}
		d := sha512.Sum384(preimage)
		e.Digest = hex.EncodeToString(d[:])
		h := sha512.New384()
		h.Write(r)
		h.Write(d[:])
		r = h.Sum(nil)
	}
	return items, r
}

func TestEventLogVerification(t *testing.T) {
	for _, version := range []int{1, 2} {
		events, r := eventsFixture(version)
		raw, _ := json.Marshal(events)
		if err := checkEvents(raw, r, testPolicy().ComposeHash); err != nil {
			t.Fatal(err)
		}
		events[0].Payload = strings.Repeat("06", 32)
		raw, _ = json.Marshal(events)
		if checkEvents(raw, r, testPolicy().ComposeHash) == nil {
			t.Fatal("substituted compose accepted")
		}
		events, r = eventsFixture(version)
		events = append(events, events[0])
		raw, _ = json.Marshal(events)
		if checkEvents(raw, r, testPolicy().ComposeHash) == nil {
			t.Fatal("duplicate identity accepted")
		}
		events, r = eventsFixture(version)
		events[0], events[1] = events[1], events[0]
		raw, _ = json.Marshal(events)
		if checkEvents(raw, r, testPolicy().ComposeHash) == nil {
			t.Fatal("reordered log accepted")
		}
	}
}

func TestUnsignedAndStaleEvidenceRejected(t *testing.T) {
	e := protocol.Evidence{ID: strings.Repeat("ab", 32), PublicKey: bytes.Repeat([]byte{3}, 32), ExpiresAt: time.Now().Add(time.Minute).Unix(), PolicyHash: policy.Hash(), Quote: []byte("unsigned"), EventLog: json.RawMessage(`[]`)}
	if Verify(context.Background(), e, make([]byte, 32), testPolicy()) == nil {
		t.Fatal("unsigned quote accepted")
	}
	e.ExpiresAt = time.Now().Add(-time.Second).Unix()
	if Verify(context.Background(), e, make([]byte, 32), testPolicy()) == nil {
		t.Fatal("stale quote accepted")
	}
	if _, _, err := (collateralGetter{ctx: context.Background()}).Get("http://127.0.0.1/secrets"); err == nil {
		t.Fatal("arbitrary collateral URL accepted")
	}
}

func FuzzEventLog(f *testing.F) {
	events, r := eventsFixture(2)
	raw, _ := json.Marshal(events)
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_ = checkEvents(data, r, testPolicy().ComposeHash)
	})
}
