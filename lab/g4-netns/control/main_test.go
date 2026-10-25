package main

import "testing"

func TestBind(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "127.1.2.3", "10.200.1.1", "192.168.1.1", "172.16.0.1"} {
		if err := validateBind(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"", "0.0.0.0", "::", "::1", "8.8.8.8", "localhost", "100.64.0.1", "169.254.1.1", "224.0.0.1"} {
		if validateBind(s) == nil {
			t.Errorf("accepted %q", s)
		}
	}
}
