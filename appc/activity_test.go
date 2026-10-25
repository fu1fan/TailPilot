package appc

import (
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestConntrackActivity(t *testing.T) {
	now := time.Unix(100, 0)
	ip := netip.MustParseAddr("192.0.2.1")
	line := "ipv4 2 tcp 6 431999 ESTABLISHED src=100.64.0.1 dst=192.0.2.1 sport=123 dport=443 src=192.0.2.1 dst=198.51.100.1 sport=443 dport=123 [ASSURED] mark=0 use=1\n"
	p := NewConntrackActivity("p", []netip.Addr{ip}, 10, 5*time.Second, func() time.Time { return now }, func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(line)), nil })
	if p.Activity("p", ip) != ActivityUnknown {
		t.Fatal("unrefreshed source not unknown")
	}
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	if p.Activity("p", ip) != ActivityActive || p.Activity("other", ip) != ActivityUnknown {
		t.Fatal("profile or active mismatch")
	}
	now = now.Add(6 * time.Second)
	if p.Activity("p", ip) != ActivityUnknown {
		t.Fatal("expired cache accepted")
	}
	line = "broken\n"
	if err := p.Refresh(); err == nil {
		t.Fatal("malformed table accepted")
	}
	if p.Activity("p", ip) != ActivityUnknown {
		t.Fatal("failure reported idle")
	}
}
func TestConntrackCapacityUnknown(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	line := "ipv4 2 udp 17 100 src=100.64.0.1 dst=192.0.2.1 sport=12 dport=443 src=192.0.2.1 dst=100.64.0.1 sport=443 dport=12\n"
	p := NewConntrackActivity("p", []netip.Addr{ip}, 1, time.Second, time.Now, func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(line + line)), nil })
	if err := p.Refresh(); err == nil {
		t.Fatal("capacity accepted")
	}
	if p.Activity("p", ip) != ActivityUnknown {
		t.Fatal("partial table used")
	}
}

func TestConntrackUDPTimeoutIsNotActivity(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	row := "ipv4 2 udp 17 999 src=100.64.0.1 dst=192.0.2.1 sport=12 dport=443 src=192.0.2.1 dst=100.64.0.1 sport=443 dport=12\n"
	p := NewConntrackActivity("p", []netip.Addr{ip}, 10, time.Minute, time.Now, func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(row)), nil })
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	if p.Activity("p", ip) != ActivityUnknown {
		t.Fatal("kernel UDP timeout misrepresented as last packet time")
	}
}
