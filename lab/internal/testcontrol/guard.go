// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package testcontrol

import (
	"bytes"
	"io"
	"net/http"
)

// Shared budget includes Noise inner requests. The outer upgrade occupies one
// slot for its lifetime. This is deliberately small, local lab infrastructure.
var requests = make(chan struct{}, 64)

func (s *Server) guarded(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover() != nil {
				s.logf("lab control rejected invalid request")
				http.Error(w, "invalid lab control request", http.StatusBadRequest)
			}
		}()
		select {
		case requests <- struct{}{}:
			defer func() { <-requests }()
		default:
			http.Error(w, "lab busy", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/healthz" && r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		inner := r.Context().Value(peerMachinePublicContextKey{}) != nil
		allowed := false
		if inner {
			allowed = r.Method == "POST" && (r.URL.Path == "/machine/map" || r.URL.Path == "/machine/register" || r.URL.Path == "/machine/set-dns" || r.URL.Path == "/machine/update-health")
		} else {
			allowed = (r.Method == "GET" && (r.URL.Path == "/key" || r.URL.Path == "/generate_204")) || (r.Method == "POST" && r.URL.Path == "/ts2021")
		}
		if !allowed {
			http.Error(w, "unknown lab endpoint or method", http.StatusNotFound)
			return
		}
		if r.ContentLength > msgLimit {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		// Noise upgrade consumes the underlying connection, not an HTTP request body.
		if r.URL.Path != "/ts2021" {
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, msgLimit))
			if err != nil {
				http.Error(w, "invalid or oversized body", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))
		} else if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			http.Error(w, "upgrade body forbidden", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}
