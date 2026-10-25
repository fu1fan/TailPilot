// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_appconnectors

package appc

func (e *AppConnector) ObserveDNSResponse(res []byte) error { return nil }

func (e *AppConnector) CaptureDNSObserver() func([]byte) error { return e.ObserveDNSResponse }

func (e *AppConnector) CaptureDNSBatchObserver() func([][]byte) []error {
	return func(wires [][]byte) []error { return make([]error, len(wires)) }
}
