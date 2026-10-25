package testcontrol

import (
	"reflect"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestMapResponsePreservesConnectorAssignment(t *testing.T) {
	nk := key.NewNode().Public()
	caps := tailcfg.NodeCapMap{
		"tailscale.com/app-connectors": {tailcfg.RawMessage(`{"domains":["*.example.test"],"routes":["198.51.100.0/24"],"connectors":["*"]}`)},
	}
	s := &Server{nodes: map[key.NodePublic]*tailcfg.Node{
		nk: {ID: 1, Key: nk, StableID: "fixture", CapMap: caps},
	}}
	for _, tc := range []struct {
		name      string
		overrides map[key.NodePublic]tailcfg.NodeCapMap
		want      tailcfg.NodeCapMap
	}{
		{"default", nil, caps},
		{"explicit-empty", map[key.NodePublic]tailcfg.NodeCapMap{nk: nil}, nil},
		{"explicit-value", map[key.NodePublic]tailcfg.NodeCapMap{nk: {tailcfg.CapabilitySSH: nil}}, tailcfg.NodeCapMap{tailcfg.CapabilitySSH: nil}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s.nodeCapMaps = tc.overrides
			res, err := s.MapResponse(&tailcfg.MapRequest{NodeKey: nk})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(res.Node.CapMap, tc.want) {
				t.Fatalf("cap map=%v, want %v", res.Node.CapMap, tc.want)
			}
			if !reflect.DeepEqual(s.Node(nk).CapMap, caps) {
				t.Fatal("response changed registered capabilities")
			}
		})
	}
}
