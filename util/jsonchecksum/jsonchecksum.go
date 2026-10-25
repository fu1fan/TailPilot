// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package jsonchecksum encodes the existing Payload/SHA256 JSON envelope.
package jsonchecksum

import (
	"crypto/sha256"
	"encoding/json"
)

// Marshal produces exactly the same bytes as json.Marshal of a struct with a
// json.RawMessage Payload and [32]byte SHA256. Payload is marshaled here, so it
// is already valid compact escaped JSON: rescanning it as a RawMessage wastes
// substantial CPU for large lease journals.
func Marshal(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	checksum, _ := json.Marshal(sha256.Sum256(payload))
	result := make([]byte, 0, len(payload)+len(checksum)+24)
	result = append(result, `{"Payload":`...)
	result = append(result, payload...)
	result = append(result, `,"SHA256":`...)
	result = append(result, checksum...)
	return append(result, '}'), nil
}
