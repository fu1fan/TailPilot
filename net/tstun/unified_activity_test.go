package tstun

import (
	"tailscale.com/net/packet"
	"tailscale.com/util/eventbus/eventbustest"
	"tailscale.com/wgengine/filter"
	"testing"
)

func TestUnifiedActivityAfterACLAndComposed(t *testing.T) {
	_, tun := newChannelTUN(t.Logf, eventbustest.NewBus(t), true)
	defer tun.Close()
	observed, conn25 := 0, 0
	tun.SetActivityObserver(func(_ *packet.Parsed, inbound bool) {
		if !inbound {
			t.Error("wrong direction")
		}
		observed++
	})
	tun.PostFilterPacketInboundFromWireGuardAppConnector = func(*packet.Parsed, *Wrapper) filter.Response { conn25++; return filter.Accept }
	var p packet.Parsed
	p.Decode(udp4("5.6.7.8", "1.2.3.4", 22, 22))
	verdict, _ := tun.filterPacketInboundFromWireGuard(&p, nil, tun.peerConfig.Load(), nil)
	if !verdict.IsDrop() || observed != 0 || conn25 != 0 {
		t.Fatal("ACL-rejected packet reached activity or Conn25")
	}
	p.Decode(udp4("5.6.7.8", "1.2.3.4", 89, 89))
	verdict, _ = tun.filterPacketInboundFromWireGuard(&p, nil, tun.peerConfig.Load(), nil)
	if verdict.IsDrop() || observed != 1 || conn25 != 1 {
		t.Fatal("accepted hook not composed", verdict, observed, conn25)
	}
	tun.SetActivityObserver(nil)
	verdict, _ = tun.filterPacketInboundFromWireGuard(&p, nil, tun.peerConfig.Load(), nil)
	if verdict.IsDrop() || observed != 1 || conn25 != 2 {
		t.Fatal("removing observer changed Conn25")
	}
}
