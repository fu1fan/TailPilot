// SPDX-License-Identifier: MIT

package device

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/tun/tuntest"
)

type pathTestEndpoint struct {
	initAwareEP
	context conn.TransportContext
	allow   func([32]byte, conn.PacketKind, conn.TransportContext) bool
	health  atomic.Int32
}

func (e *pathTestEndpoint) TransportContext() conn.TransportContext { return e.context }
func (e *pathTestEndpoint) AllowAuthenticatedPeer(k [32]byte, kind conn.PacketKind, ctx conn.TransportContext) bool {
	return e.allow(k, kind, ctx)
}
func (e *pathTestEndpoint) FromPeer([32]byte) { e.health.Add(1) }

func pathTestPair(t *testing.T) (a, b *Device, ab, ba *Peer) {
	t.Helper()
	a = newTestDevice(t)
	b = NewDevice(&pathCountingTUN{Device: tuntest.NewChannelTUN().TUN()}, conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
	sk, err := newPrivateKey()
	assertNil(t, err)
	assertNil(t, b.SetPrivateKey(sk))
	t.Cleanup(b.Close)
	ab, err = a.NewPeer(b.staticIdentity.publicKey)
	assertNil(t, err)
	ba, err = b.NewPeer(a.staticIdentity.publicKey)
	assertNil(t, err)
	ab.Start()
	ba.Start()
	return
}

func TestAuthenticatedPathHandshake(t *testing.T) {
	a, b, ab, ba := pathTestPair(t)
	msg, err := a.CreateMessageInitiation(ab)
	assertNil(t, err)
	calls := 0
	ep := &pathTestEndpoint{context: conn.TransportContext{Kind: conn.TransportDERP, Generation: 7}}
	ep.allow = func(k [32]byte, kind conn.PacketKind, ctx conn.TransportContext) bool {
		calls++
		if k != a.staticIdentity.publicKey || kind != conn.PacketInitiation || ctx.Generation != 7 {
			t.Fatal("incorrect authenticated identity/context")
		}
		if ba.handshake.state != handshakeZeroed || !ba.handshake.lastInitiationConsumption.IsZero() {
			t.Fatal("gate after commit")
		}
		return false
	}
	bad := *msg
	bad.Timestamp[0] ^= 1
	if b.ConsumeMessageInitiation(&bad, ep) != nil || calls != 0 {
		t.Fatal("unauthenticated timestamp reached gate")
	}
	if b.ConsumeMessageInitiation(msg, ep) != nil || calls != 1 {
		t.Fatal("denied initiation accepted")
	}
	if ba.handshake.state != handshakeZeroed || ba.handshake.lastTimestamp != ([12]byte{}) || !ba.handshake.lastInitiationConsumption.IsZero() {
		t.Fatal("denied initiation mutated handshake")
	}
	if _, err := b.CreateMessageResponse(ba); err == nil {
		t.Fatal("denied initiation permits response")
	}
	alteredInit := *msg
	alteredInit.Sender ^= 1
	if b.ConsumeMessageInitiation(&alteredInit, ep) != nil {
		t.Fatal("denied altered initiation sender accepted")
	}
	ep.allow = func(k [32]byte, kind conn.PacketKind, ctx conn.TransportContext) bool { calls++; return true }
	if b.ConsumeMessageInitiation(msg, ep) != ba {
		t.Fatal("denial consumed timestamp")
	}
	callsBefore := calls
	if b.ConsumeMessageInitiation(msg, ep) != nil || calls != callsBefore {
		t.Fatal("replayed initiation reached gate")
	}
	resp, err := b.CreateMessageResponse(ba)
	assertNil(t, err)
	ep.allow = func(k [32]byte, kind conn.PacketKind, ctx conn.TransportContext) bool {
		calls++
		if k != b.staticIdentity.publicKey || kind != conn.PacketResponse {
			t.Fatal("response identity from wrong peer")
		}
		if ab.handshake.state != handshakeInitiationCreated {
			t.Fatal("response committed before gate")
		}
		return false
	}
	badResp := *resp
	badResp.Empty[0] ^= 1
	callsBefore = calls
	if a.ConsumeMessageResponseWithEndpoint(&badResp, ep) != nil || calls != callsBefore {
		t.Fatal("bad response AEAD reached gate")
	}
	badResp = *resp
	badResp.Receiver ^= 0x80000000
	if a.ConsumeMessageResponseWithEndpoint(&badResp, ep) != nil || calls != callsBefore {
		t.Fatal("forged receiver reached gate")
	}
	if a.ConsumeMessageResponseWithEndpoint(resp, ep) != nil {
		t.Fatal("denied response accepted")
	}
	if ab.handshake.state != handshakeInitiationCreated || ab.keypairs.Current() != nil || ab.lastHandshakeNano.Load() != 0 {
		t.Fatal("denied response changed session")
	}
	// Sender index is deliberately not an authenticated identity field in Noise.
	// Altering it must never change the public key passed to the predicate.
	altered := *resp
	altered.Sender ^= 1
	if a.ConsumeMessageResponseWithEndpoint(&altered, ep) != nil {
		t.Fatal("denied altered sender accepted")
	}
	ep.allow = func(k [32]byte, kind conn.PacketKind, ctx conn.TransportContext) bool { return true }
	if a.ConsumeMessageResponseWithEndpoint(resp, ep) != ab {
		t.Fatal("denial consumed response")
	}
	if ep.health.Load() != 0 {
		t.Fatal("consume functions must not call health under handshake lock")
	}
}

// Exercise the actual decryption -> sequential receiver pipeline, with real
// session AEAD, mixed endpoint contexts in one batch, and replay filtering.
func TestAuthenticatedPathTransportBatch(t *testing.T) {
	a, b, ab, ba := pathTestPair(t)
	msg, err := a.CreateMessageInitiation(ab)
	assertNil(t, err)
	if b.ConsumeMessageInitiation(msg, nil) != ba {
		t.Fatal("init")
	}
	resp, err := b.CreateMessageResponse(ba)
	assertNil(t, err)
	if a.ConsumeMessageResponse(resp) != ab {
		t.Fatal("response")
	}
	assertNil(t, ab.BeginSymmetricSession())
	assertNil(t, ba.BeginSymmetricSession())
	send := ab.keypairs.Current()
	recv := ba.keypairs.next.Load()
	if recv == nil {
		t.Fatal("no next keypair")
	}
	ba.SetAllowedIPs([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")})
	counted := b.tun.device.(*pathCountingTUN)
	calls := 0
	kinds := map[conn.PacketKind]int{}
	deny := &pathTestEndpoint{context: conn.TransportContext{Kind: conn.TransportRelay, Generation: 10}}
	deny.allow = func(k [32]byte, kind conn.PacketKind, ctx conn.TransportContext) bool {
		calls++
		kinds[kind]++
		if k != a.staticIdentity.publicKey || ctx.Generation != 10 {
			t.Fatal("wrong peer/context")
		}
		if ba.keypairs.next.Load() != recv || ba.lastHandshakeNano.Load() != 0 {
			t.Fatal("denied packet promoted key")
		}
		return false
	}
	allow := &pathTestEndpoint{context: conn.TransportContext{Kind: conn.TransportDirect, Generation: 11}}
	allow.allow = func(k [32]byte, kind conn.PacketKind, ctx conn.TransportContext) bool {
		calls++
		if k != a.staticIdentity.publicKey || ctx.Generation != 11 {
			t.Fatal("batch context overwritten")
		}
		return true
	}
	data := tuntest.Ping(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1"))
	type input struct {
		ep      conn.Endpoint
		counter uint64
		data    []byte
		corrupt bool
	}
	run := func(inputs ...input) {
		t.Helper()
		c := b.GetInboundElementsContainer()
		for _, in := range inputs {
			buf := b.GetMessageBuffer()
			binary.LittleEndian.PutUint32(buf[:4], MessageTransportType)
			binary.LittleEndian.PutUint32(buf[4:8], recv.localIndex)
			binary.LittleEndian.PutUint64(buf[8:16], in.counter)
			var nonce [12]byte
			binary.LittleEndian.PutUint64(nonce[4:], in.counter)
			packet := send.send.Seal(buf[:16], nonce[:], in.data, nil)
			if in.corrupt {
				packet[len(packet)-1] ^= 1
			}
			el := b.GetInboundElement()
			el.buffer = buf
			el.packet = packet
			el.keypair = recv
			el.endpoint = in.ep
			c.elems = append(c.elems, el)
		}
		c.filling.Add(1)
		b.queue.decryption.c <- c
		ba.processInboundContainer(c, make([][]byte, 0, len(inputs)))
	}
	ba.timers.newHandshake.Mod(time.Hour)
	ba.timers.retransmitHandshake.Mod(time.Hour)
	run(input{deny, 0, data, false}, input{deny, 1, nil, false}, input{deny, 2, data, true})
	if calls != 2 || counted.writes != 0 || deny.health.Load() != 0 || ba.rxBytes.Load() != 0 || ba.keypairs.next.Load() != recv {
		t.Fatal("deny/AEAD failure had side effects")
	}
	if kinds[conn.PacketTransport] != 1 || kinds[conn.PacketKeepalive] != 1 {
		t.Fatal("wrong authenticated packet kind")
	}
	if !ba.timers.newHandshake.IsPending() || !ba.timers.retransmitHandshake.IsPending() {
		t.Fatal("denial changed timers")
	}
	// Same counter rejected on one path can be accepted on another. In-batch
	// duplicates must not produce health, TUN delivery, or byte accounting twice.
	run(input{allow, 0, data, false}, input{allow, 0, data, false}, input{allow, 1, nil, false})
	if counted.writes != 1 || allow.health.Load() != 2 || ba.keypairs.Current() != recv {
		t.Fatalf("accept/replay: writes=%d health=%d", counted.writes, allow.health.Load())
	}
	bytesBefore := ba.rxBytes.Load()
	run(input{allow, 0, data, false}, input{allow, 1, nil, false})
	if counted.writes != 1 || allow.health.Load() != 2 || ba.rxBytes.Load() != bytesBefore {
		t.Fatal("replay updated health/TUN/counters")
	}
	// A packet encrypted under an unrelated/old session key cannot reach gate.
	other, _ := newPrivateKey()
	wrongAEAD, _ := chacha20poly1305New(other[:])
	oldSend := send.send
	send.send = wrongAEAD
	before := calls
	run(input{allow, 3, data, false})
	send.send = oldSend
	if calls != before {
		t.Fatal("wrong key reached gate")
	}
}

// The counting TUN retains the real device lifecycle but does not block on a
// consumer. It counts actual Write submissions by processInboundContainer.
type pathCountingTUN struct {
	tun.Device
	writes int
}

func (t *pathCountingTUN) Write(bufs [][]byte, offset int) (int, error) {
	t.writes += len(bufs)
	return len(bufs), nil
}

func TestAuthenticatedPathConcurrentInitiation(t *testing.T) {
	a, b, ab, _ := pathTestPair(t)
	msg, err := a.CreateMessageInitiation(ab)
	assertNil(t, err)
	var calls, accepted atomic.Int32
	// Do not implement the upstream preauth callback's mutable test field here.
	ep := &concurrentPathEndpoint{pathTestEndpoint: pathTestEndpoint{allow: func([32]byte, conn.PacketKind, conn.TransportContext) bool { calls.Add(1); return true }}}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if b.ConsumeMessageInitiation(msg, ep) != nil {
				accepted.Add(1)
			}
		})
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handshake gate lock deadlock")
	}
	if calls.Load() != 1 || accepted.Load() != 1 {
		t.Fatalf("concurrent replay accepted: gate=%d accepted=%d", calls.Load(), accepted.Load())
	}
}

type concurrentPathEndpoint struct{ pathTestEndpoint }

func (*concurrentPathEndpoint) InitiationMessagePublicKey([32]byte) {}

// Send valid MAC1-protected messages through the real handshake worker, not
// just ConsumeMessage*. Its invalid-message log is a completion barrier after
// the gate returned false. No packet bytes or key material are logged here.
func TestAuthenticatedPathHandshakeWorkerOrder(t *testing.T) {
	stopped := make(chan string, 4)
	var sends atomic.Int32
	logger := &Logger{Errorf: DiscardLogf, Verbosef: func(format string, args ...any) {
		if strings.Contains(format, "Sending handshake") || strings.Contains(format, "Sending keepalive") {
			sends.Add(1)
		}
		if strings.Contains(format, "Received invalid initiation message") {
			stopped <- "initiation"
		}
		if strings.Contains(format, "Received invalid response message") {
			stopped <- "response"
		}
	}}
	makeDev := func() *Device {
		d := NewDevice(&pathCountingTUN{Device: tuntest.NewChannelTUN().TUN()}, conn.NewDefaultBind(), logger)
		sk, err := newPrivateKey()
		assertNil(t, err)
		assertNil(t, d.SetPrivateKey(sk))
		t.Cleanup(d.Close)
		return d
	}
	a, b := makeDev(), makeDev()
	ab, err := a.NewPeer(b.staticIdentity.publicKey)
	assertNil(t, err)
	ba, err := b.NewPeer(a.staticIdentity.publicKey)
	assertNil(t, err)
	ab.Start()
	ba.Start()
	msg, err := a.CreateMessageInitiation(ab)
	assertNil(t, err)
	var calls atomic.Int32
	ep := &pathTestEndpoint{allow: func([32]byte, conn.PacketKind, conn.TransportContext) bool { calls.Add(1); return false }}
	ba.timers.newHandshake.Mod(time.Hour)
	ab.timers.newHandshake.Mod(time.Hour)
	queue := func(d *Device, p *Peer, kind uint32, size int, marshal func([]byte) error, want string) {
		buf := d.GetMessageBuffer()
		assertNil(t, marshal(buf[:size]))
		p.cookieGenerator.AddMacs(buf[:size])
		d.queue.handshake.c <- QueueHandshakeElement{msgType: kind, buffer: buf, packet: buf[:size], endpoint: ep}
		select {
		case got := <-stopped:
			if got != want {
				t.Fatal(got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("handshake worker did not reject")
		}
	}
	queue(b, ab, MessageInitiationType, MessageInitiationSize, msg.marshal, "initiation")
	if calls.Load() != 1 || ep.health.Load() != 0 || ba.handshake.state != handshakeZeroed || !ba.timers.newHandshake.IsPending() || sends.Load() != 0 || ba.rxBytes.Load() != 0 {
		t.Fatal("initiation rejection had side effects")
	}
	if b.ConsumeMessageInitiation(msg, nil) != ba {
		t.Fatal("denial consumed initiation")
	}
	resp, err := b.CreateMessageResponse(ba)
	assertNil(t, err)
	queue(a, ba, MessageResponseType, MessageResponseSize, resp.marshal, "response")
	if calls.Load() != 2 || ep.health.Load() != 0 || ab.handshake.state != handshakeInitiationCreated || !ab.timers.newHandshake.IsPending() || sends.Load() != 0 || ab.rxBytes.Load() != 0 || ab.keypairs.Current() != nil {
		t.Fatal("response rejection had side effects")
	}
}

func TestAuthenticatedPathExpiredKeyAndUnknownIndex(t *testing.T) {
	a, b, ab, ba := pathTestPair(t)
	msg, err := a.CreateMessageInitiation(ab)
	assertNil(t, err)
	if b.ConsumeMessageInitiation(msg, nil) != ba {
		t.Fatal("init")
	}
	resp, err := b.CreateMessageResponse(ba)
	assertNil(t, err)
	if a.ConsumeMessageResponse(resp) != ab {
		t.Fatal("response")
	}
	assertNil(t, ab.BeginSymmetricSession())
	assertNil(t, ba.BeginSymmetricSession())
	recv := ba.keypairs.next.Load()
	recv.created = time.Now().Add(-RejectAfterTime - time.Second)
	unknown := recv.localIndex + 1
	for b.indexTable.Lookup(unknown).keypair != nil || b.indexTable.Lookup(unknown).handshake != nil {
		unknown++
	}
	var calls atomic.Int32
	ep := &pathTestEndpoint{allow: func([32]byte, conn.PacketKind, conn.TransportContext) bool { calls.Add(1); return false }}
	read := false
	fn := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if read {
			return 0, net.ErrClosed
		}
		read = true
		for i, index := range []uint32{recv.localIndex, unknown} {
			clear(bufs[i][:MessageTransportSize])
			binary.LittleEndian.PutUint32(bufs[i], MessageTransportType)
			binary.LittleEndian.PutUint32(bufs[i][4:], index)
			sizes[i] = MessageTransportSize
			eps[i] = ep
		}
		return 2, nil
	}
	b.queue.decryption.wg.Add(1)
	b.queue.handshake.wg.Add(1)
	b.net.stopping.Add(1)
	b.RoutineReceiveIncoming(2, fn)
	if calls.Load() != 0 || ep.health.Load() != 0 || ba.rxBytes.Load() != 0 || ba.keypairs.next.Load() != recv {
		t.Fatal("expired/unknown index reached authentication gate or changed session")
	}
}

func TestAuthenticatedPathConcurrentResponse(t *testing.T) {
	a, b, ab, ba := pathTestPair(t)
	msg, err := a.CreateMessageInitiation(ab)
	assertNil(t, err)
	if b.ConsumeMessageInitiation(msg, nil) != ba {
		t.Fatal("init")
	}
	resp, err := b.CreateMessageResponse(ba)
	assertNil(t, err)
	var calls, accepted atomic.Int32
	ep := &pathTestEndpoint{allow: func(k [32]byte, kind conn.PacketKind, ctx conn.TransportContext) bool {
		if k != b.staticIdentity.publicKey || kind != conn.PacketResponse {
			t.Error("wrong response identity")
		}
		calls.Add(1)
		return true
	}}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if a.ConsumeMessageResponseWithEndpoint(resp, ep) != nil {
				accepted.Add(1)
			}
		})
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("response gate deadlock")
	}
	if calls.Load() != 1 || accepted.Load() != 1 {
		t.Fatalf("response committed multiple times: gate=%d accepted=%d", calls.Load(), accepted.Load())
	}
}
