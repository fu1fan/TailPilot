package testcontrol

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"tailscale.com/control/controlclient"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/eventbus/eventbustest"
)

// Exercise the daemon's login client, not just tsp.Register. An unset
// RequireAuthKey accepts both an empty key and the old lab-only placeholder.
func TestDaemonLoginFixture(t *testing.T) {
	for _, auth := range []string{"", "lab-only"} {
		t.Run("auth="+auth, func(t *testing.T) {
			s := &Server{AllNodesSameUser: true, DERPMap: &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{}}}
			s.HTTPTestServer = httptest.NewServer(s)
			defer s.HTTPTestServer.Close()
			bus := eventbustest.NewBus(t)
			dialer := tsdial.NewDialer(netmon.NewStatic())
			dialer.SetBus(bus)
			defer dialer.Close()
			machine := key.NewMachine()
			c, err := controlclient.NewDirect(controlclient.Options{
				ServerURL: s.HTTPTestServer.URL, AuthKey: auth, Bus: bus, Dialer: dialer,
				HealthTracker: health.NewTracker(bus), Logf: t.Logf,
				Hostinfo:             &tailcfg.Hostinfo{Hostname: "r27-login", BackendLogID: "lab-only"},
				GetMachinePrivateKey: func() (key.MachinePrivate, error) { return machine, nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			url, err := c.TryLogin(ctx, controlclient.LoginInteractive)
			if err != nil || url != "" {
				t.Fatalf("login: url=%q err=%v", url, err)
			}
		})
	}
}
