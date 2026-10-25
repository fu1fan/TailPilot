package ipnlocal

import (
	"bytes"
	"tailscale.com/ipn"
)

// atomicStateWriter commits all projections together. Other stores keep the
// existing write-ahead recovery protocol; they must not emulate this by looping.
type atomicStateWriter interface {
	WriteStates(map[ipn.StateKey][]byte) error
}
type bufferedConnectorStore struct {
	ipn.StateStore
	updates map[ipn.StateKey][]byte
}

func (s *bufferedConnectorStore) ReadState(k ipn.StateKey) ([]byte, error) {
	if v, ok := s.updates[k]; ok {
		if v == nil {
			return nil, ipn.ErrStateNotExist
		}
		return bytes.Clone(v), nil
	}
	return s.StateStore.ReadState(k)
}
func (s *bufferedConnectorStore) WriteState(k ipn.StateKey, v []byte) error {
	s.updates[k] = bytes.Clone(v)
	return nil
}
