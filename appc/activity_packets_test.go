package appc

import (
	"net/netip"
	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"testing"
	"time"
)

func TestPacketActivityUDPIdle(t *testing.T) {
	now := time.Unix(100, 0)
	p := NewPacketActivity("p", 1, 120*time.Second, func() time.Time { return now })
	ip := netip.MustParseAddr("192.0.2.1")
	p.SetManaged([]netip.Addr{ip})
	pkt := &packet.Parsed{IPProto: ipproto.UDP, Src: netip.MustParseAddrPort("100.64.0.1:1234"), Dst: netip.AddrPortFrom(ip, 443)}
	p.Observe(pkt, true)
	if p.Activity("p", ip) != ActivityActive || p.Activity("other", ip) != ActivityUnknown {
		t.Fatal("activity scope")
	}
	now = now.Add(119 * time.Second)
	if p.Activity("p", ip) != ActivityActive {
		t.Fatal("UDP expired early")
	}
	now = now.Add(time.Second)
	if p.Activity("p", ip) != ActivityUnknown {
		t.Fatal("UDP activity extended beyond idle")
	}
	pkt.Src, pkt.Dst = pkt.Dst, pkt.Src
	p.Observe(pkt, false)
	if p.Activity("p", ip) != ActivityActive {
		t.Fatal("reply activity not observed")
	}
	p.SetManaged(nil)
	if len(p.recent) != 0 || p.Activity("p", ip) != ActivityUnknown {
		t.Fatal("removed destination retained")
	}
}
