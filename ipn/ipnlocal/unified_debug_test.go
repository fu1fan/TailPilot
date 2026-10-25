// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
package ipnlocal

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"tailscale.com/ipn"
	"testing"
	"time"

	"tailscale.com/appc"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/util/eventbus/eventbustest"
)

func TestUnifiedDebugCASPreview(t *testing.T) {
	data := []byte(`{"schema_version":1}`)
	r := newUnifiedPolicyRuntime(func() ([]byte, error) { return data, nil })
	if err := r.refresh(featurepolicy.Inputs{ProfileID: "p", PeerIdentityEpoch: 1}, UnifiedPolicyStore{Store: new(mem.Store), ProfileID: "p", ProfileKey: "profile-p"}); err != nil {
		t.Fatal(err)
	}
	b := &LocalBackend{unifiedProfileID: "p", unifiedRevision: 1}
	before := r.manager.Current()
	data = []byte(`{"schema_version":1,"enabled":true}`)
	call := unifiedDebugCall{ctx: context.Background(), action: "unified-policy-preview"}
	v, err := b.inspectUnifiedPolicy(r, call)
	if err != nil || !v.SchemaValid || !v.RuntimeReady || v.Accepted || v.Applied || r.manager.Current() != before {
		t.Fatalf("%+v %v", v, err)
	}
	call.action = "unified-policy-reload"
	call.req = UnifiedDebugRequest{ExpectGeneration: before.Fence().Generation + 1, ExpectSHA256: v.RequestedSHA256}
	if _, err = b.inspectUnifiedPolicy(r, call); err == nil || r.manager.Current() != before {
		t.Fatal("CAS conflict published")
	}
	call.req.ExpectGeneration = before.Fence().Generation
	call.req.ExpectSHA256 = strings.Repeat("0", 64)
	if _, err = b.inspectUnifiedPolicy(r, call); err == nil || r.manager.Current() != before {
		t.Fatal("hash conflict published")
	}
	call.req.ExpectSHA256 = v.RequestedSHA256
	v, err = b.inspectUnifiedPolicy(r, call)
	if err != nil || !v.Accepted || v.Applied || r.manager.Current() == before {
		t.Fatalf("%+v %v", v, err)
	}
	b.unifiedRevision++
	if _, err = b.inspectUnifiedPolicy(r, call); err == nil {
		t.Fatal("stale inputs accepted")
	}
}
func TestUnifiedDebugStatusRedaction(t *testing.T) {
	b := &LocalBackend{unifiedStatus: UnifiedPolicyStatus{Degraded: "SENTINEL private key or DNS body"}}
	v := b.UnifiedPolicyDebugStatus()
	raw, _ := json.Marshal(v)
	if !v.Degraded || strings.Contains(string(raw), "SENTINEL") || v.Applied || v.RuntimeReady {
		t.Fatalf("%s", raw)
	}
}

func TestUnifiedDebugPendingOwnerDoesNotBlockStatus(t *testing.T) {
	b := &LocalBackend{unifiedPrefsPending: make(chan struct{}), unifiedPrefsPendingSince: time.Now().Add(-time.Second)}
	done := make(chan UnifiedDebugStatus, 1)
	go func() { done <- b.UnifiedPolicyDebugStatus() }()
	select {
	case v := <-done:
		if v.OwnerQueueAgeSeconds == nil || *v.OwnerQueueAgeSeconds < 1 {
			t.Fatalf("%+v", v)
		}
	case <-time.After(time.Second):
		t.Fatal("status blocked on pending owner transaction")
	}
}

func TestUnifiedDebugWorkerPreviewDoesNotPollOrPublish(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &LocalBackend{ctx: ctx, unifiedWake: make(chan struct{}, 1), pm: &profileManager{currentProfile: (&ipn.LoginProfile{}).View(), prefs: ipn.NewPrefs().View()}}
	b.currentNodeAtomic.Store(&nodeBackend{})
	var data atomic.Value
	data.Store([]byte(`{"schema_version":1,"reload_seconds":60}`))
	var reads atomic.Int32
	r := newUnifiedPolicyRuntime(func() ([]byte, error) { reads.Add(1); return data.Load().([]byte), nil })
	b.unifiedRuntime = r
	b.startUnifiedPolicy(r)
	defer b.stopUnifiedPolicy()
	requestCtx, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	if _, err := b.UnifiedPolicyInspect(requestCtx, "unified-policy-preview", UnifiedDebugRequest{}); err != nil {
		t.Fatal(err)
	}
	before := r.manager.Current()
	data.Store([]byte(`{"schema_version":1,"reload_seconds":60,"machine":"preview-only"}`))
	for range 2 {
		v, err := b.UnifiedPolicyInspect(requestCtx, "unified-policy-preview", UnifiedDebugRequest{})
		if err != nil || !v.Changed || v.Accepted || v.Applied {
			t.Fatalf("%+v %v", v, err)
		}
	}
	if reads.Load() != 4 || r.manager.Current() != before {
		t.Fatalf("preview triggered poll/publication: reads=%d", reads.Load())
	}
}

func TestUnifiedTimeConfirmationRequestGate(t *testing.T) {
	data := []byte(`{"schema_version":1,"enabled":true,"lease":{"enabled":true}}`)
	store := new(mem.Store)
	r := newUnifiedPolicyRuntime(func() ([]byte, error) { return data, nil })
	if err := r.refresh(featurepolicy.Inputs{ProfileID: "p"}, UnifiedPolicyStore{Store: store, ProfileID: "p", ProfileKey: "p"}); err != nil {
		t.Fatal(err)
	}
	s := r.manager.Current()
	r.ownerSnapshot = s
	c := appc.NewAppConnector(appc.Config{SourceID: 1, Logf: t.Logf, EventBus: eventbustest.NewBus(t)})
	if err := c.InstallTTLTakeover(appc.ConnectorTTLConfig{Fence: s.Fence(), Options: appc.LeaseOptions{MaxEntries: 10}, Commit: func(appc.ConnectorTTLTransition) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	r.connector = c

	b := &LocalBackend{logf: t.Logf, unifiedProfileID: "p"}
	good := UnifiedDebugRequest{ConfirmTime: true, Source: "Lead-checked-clock", ExpectGeneration: s.Fence().Generation, ExpectSHA256: r.manager.SourceHash()}
	for _, kind := range []string{"no-assertion", "no-source", "wrong-generation", "wrong-hash", "canceled", "valid"} {
		t.Run(kind, func(t *testing.T) {
			req := good
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "no-assertion":
				req.ConfirmTime = false
			case "no-source":
				req.Source = ""
			case "wrong-generation":
				req.ExpectGeneration++
			case "wrong-hash":
				req.ExpectSHA256 = "wrong"
			case "canceled":
				cancel()
			}
			out, err := b.inspectUnifiedPolicy(r, unifiedDebugCall{ctx: ctx, action: "unified-time-confirm", req: req})
			_, uncertain, _ := c.TTLDebugSummary(time.Now())
			if kind == "valid" {
				if err != nil || !out.Accepted || uncertain {
					t.Fatal(out, err, uncertain)
				}
			} else if err == nil || !uncertain {
				t.Fatal("unauthorized assertion thawed", out, err)
			}
		})
	}
}
