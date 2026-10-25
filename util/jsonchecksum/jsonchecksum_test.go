package jsonchecksum

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"
)

func TestCompatibleEnvelope(t *testing.T) {
	for _, v := range []any{nil, []string{}, map[string]any{"escaped": "<>&\u2028\n\"\\", "utf8": "租约"}, []byte{0, 1, 255}} {
		payload, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		expected, e := json.Marshal(struct {
			Payload json.RawMessage
			SHA256  [32]byte
		}{payload, sha256.Sum256(payload)})
		if e != nil {
			t.Fatal(e)
		}
		actual, e := Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(actual, expected) {
			t.Fatalf("encoding changed: %s != %s", actual, expected)
		}
	}
}
func TestRejectUnsupportedPayload(t *testing.T) {
	if _, err := Marshal(func() {}); err == nil {
		t.Fatal("unsupported payload accepted")
	}
}
