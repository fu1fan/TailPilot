// Local unauthenticated test infrastructure. Default loopback; private bridge opt-in.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/netutil"
	"tailscale.com/derp/derpserver"
	"tailscale.com/lab/internal/testcontrol"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
)

func main() {
	bind := flag.String("bind", "127.0.0.1", "loopback, or explicitly selected private run-owned bridge IPv4")
	flagPort := flag.Int("port", 0, "control TCP port (0 allocates a free port)")
	appcFixture := flag.Bool("appc-fixture", false, "assign *.example.test and static 198.51.100.0/24 to lab connectors")
	appcDomains := flag.Int("appc-domains", 0, "with --appc-fixture, also assign this many *.dN.example.test domains")
	appcRoutes := flag.Int("appc-routes", 0, "with --appc-fixture, also assign this many 10.x.y.0/24 static control routes")
	dnsResolver := flag.String("dns-resolver", "", "loopback lab DNS resolver IP:port")
	flag.Parse()
	if *dnsResolver != "" {
		ap, err := netip.ParseAddrPort(*dnsResolver)
		if err != nil || !ap.Addr().IsLoopback() {
			log.Fatal("DNS resolver must be loopback IP:port")
		}
	}
	if err := validateBind(*bind); err != nil {
		log.Fatal(err)
	}
	controlPort := *flagPort
	listen := func() net.Listener {
		ln, err := net.Listen("tcp4", net.JoinHostPort(*bind, "0"))
		if err != nil {
			log.Fatal(err)
		}
		return netutil.LimitListener(ln, 32)
	}
	d := derpserver.New(key.NewNode(), log.Printf)
	defer d.Close()
	ds := httptest.NewUnstartedServer(derpserver.Handler(d))
	ds.Listener.Close()
	ds.Listener = listen()
	ds.Config.ReadHeaderTimeout = 5 * time.Second
	ds.Config.ReadTimeout = 30 * time.Second
	ds.Config.IdleTimeout = 30 * time.Second
	ds.Config.MaxHeaderBytes = 16 << 10
	ds.StartTLS()
	defer ds.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(*bind)})
	if err != nil {
		log.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, src, err := udp.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			tx, err := stun.ParseBindingRequest(buf[:n])
			if err != nil {
				continue
			}
			udp.WriteToUDPAddrPort(stun.Response(tx, src), src)
		}
	}()
	dm := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{900: {
		RegionID: 900, RegionCode: "g4", RegionName: "local g4 lab",
		Nodes: []*tailcfg.DERPNode{{Name: "g4", RegionID: 900, HostName: *bind, IPv4: *bind,
			IPv6: "none", DERPPort: ds.Listener.Addr().(*net.TCPAddr).Port,
			STUNPort: udp.LocalAddr().(*net.UDPAddr).Port, STUNTestIP: *bind, InsecureForTests: true}},
	}}}
	cs := &testcontrol.Server{DERPMap: dm, AllNodesSameUser: true}
	if *dnsResolver != "" {
		cs.DNSConfig = &tailcfg.DNSConfig{Resolvers: []*dnstype.Resolver{{Addr: *dnsResolver}}, Routes: map[string][]*dnstype.Resolver{"example.test": {{Addr: *dnsResolver}}}}
	}
	if *appcFixture {
		requireScale := *appcDomains >= 0 && *appcDomains <= 4096 && *appcRoutes >= 0 && *appcRoutes <= 8192
		if !requireScale {
			log.Fatal("appc-domains/appc-routes out of reviewed lab range")
		}
		attr := appctype.AppConnectorAttr{Name: "r26", Domains: []string{"*.example.test"},
			Routes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, Connectors: []string{"*"}}
		for i := 0; i < *appcDomains; i++ {
			attr.Domains = append(attr.Domains, fmt.Sprintf("*.d%d.example.test", i))
		}
		for i := 0; i < *appcRoutes; i++ {
			attr.Routes = append(attr.Routes, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i / 256), byte(i % 256), 0}), 24))
		}
		raw, err := json.Marshal(attr)
		if err != nil {
			log.Fatal(err)
		}
		caps := tailcfg.NodeCapMap{
			tailcfg.NodeAttrStoreAppCRoutes: {},
			"tailscale.com/app-connectors":  {tailcfg.RawMessage(raw)},
		}
		cs.DefaultNodeCapabilities = &caps
	}
	ln, err := net.Listen("tcp4", net.JoinHostPort(*bind, fmt.Sprint(controlPort)))
	if err != nil {
		log.Fatal(err)
	}
	cs.ExplicitBaseURL = "http://" + ln.Addr().String()
	hs := &http.Server{Handler: cs, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("lab control starting bind=%s health=%s/healthz", ln.Addr(), cs.ExplicitBaseURL)
	defer hs.Close()
	go func() {
		if err := hs.Serve(netutil.LimitListener(ln, 32)); err != http.ErrServerClosed {
			log.Print(err)
		}
	}()
	json.NewEncoder(os.Stdout).Encode(map[string]any{"controlURL": "http://" + ln.Addr().String(), "derpMap": dm})
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	signal.Stop(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = hs.Shutdown(ctx)
	log.Print("lab control stopped; closing DERP/STUN")
}

func validateBind(bind string) error {
	ip, err := netip.ParseAddr(bind)
	if err != nil || !ip.Is4() || !(ip.IsLoopback() || ip.IsPrivate()) {
		return fmt.Errorf("bind must be literal loopback or explicitly selected private IPv4: %q", bind)
	}
	return nil
}
