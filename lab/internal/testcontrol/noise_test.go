package testcontrol

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailscale.com/control/ts2021"
	"tailscale.com/control/tsp"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/must"
)

func TestNoiseRegistrationAndHostileRequests(t *testing.T) {
	s := &Server{DERPMap: &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{}}}
	s.HTTPTestServer = httptest.NewServer(s)
	defer s.HTTPTestServer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	url := s.HTTPTestServer.URL
	pub := must.Get(tsp.DiscoverServerKey(ctx, url))
	machine, node := key.NewMachine(), key.NewNode()
	c := must.Get(tsp.NewClient(tsp.ClientOpts{ServerURL: url, MachineKey: machine}))
	defer c.Close()
	c.SetControlPublicKey(pub)
	must.Get(c.Register(ctx, tsp.RegisterOpts{NodeKey: node, Hostinfo: &tailcfg.Hostinfo{Hostname: "lab-security"}}))
	nc := must.Get(ts2021.NewClient(ts2021.ClientOpts{ServerURL: url, PrivKey: machine, ServerPubKey: pub, Dialer: tsdial.NewFromFuncForDebug(t.Logf, (&net.Dialer{}).DialContext)}))
	defer nc.Close()
	for _, tc := range []struct {
		path, body string
		status     int
	}{
		{"/board.cgi?cmd=invalid", "", 404},
		{"/machine/unknown", "", 404},
		{"/machine/register", "{invalid", 400},
		{"/machine/map", "{invalid", 400},
	} {
		req := must.Get(http.NewRequestWithContext(ctx, "POST", strings.Replace(url, "http:", "https:", 1)+tc.path, strings.NewReader(tc.body)))
		res := must.Get(nc.Do(req))
		res.Body.Close()
		if res.StatusCode != tc.status {
			t.Fatalf("%s: %d", tc.path, res.StatusCode)
		}
	}
	if err := c.SendMapUpdate(ctx, tsp.SendMapUpdateOpts{NodeKey: node, Hostinfo: &tailcfg.Hostinfo{Hostname: "still-alive"}}); err != nil {
		t.Fatal(err)
	}
	if s.Node(node.Public()) == nil {
		t.Fatal("lost registered node")
	}
}
