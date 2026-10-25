package ipnlocal

import (
	"context"
	"errors"
	"sync"
	"tailscale.com/appc"
	"tailscale.com/featurepolicy"
	"tailscale.com/ipn/store/mem"
	"testing"
	"testing/synctest"
	"time"
)

func TestUnifiedDNSQueueBoundsCancelTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newUnifiedPolicyRuntime(nil)
		done := make(chan struct{})
		f := featurepolicy.Fence{}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := r.enqueueDNS(ctx, done, f, time.Second, func() error { t.Error("canceled callback"); return nil }); err == nil || len(r.dns) != 0 {
			t.Fatal("cancellation ignored")
		}
		start := time.Now()
		if err := r.enqueueDNS(context.Background(), done, f, 3*time.Second, func() error { return nil }); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != 2*time.Second {
			t.Fatal("wait not capped at schema maximum 2s", err, time.Since(start))
		}
		for len(r.dns) < cap(r.dns) {
			r.dns <- unifiedDNSCall{}
		}
		if err := r.enqueueDNS(context.Background(), done, f, 0, func() error { return nil }); err == nil {
			t.Fatal("unbounded mailbox")
		}
	})
}
func TestUnifiedDNSQueueDurableZeroAndFailures(t *testing.T) {
	for _, zero := range []bool{false, true} {
		for _, fail := range []bool{false, true} {
			t.Run(map[bool]string{true: "zero", false: "wait"}[zero]+map[bool]string{true: "/fail", false: "/ok"}[fail], func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					r := newUnifiedPolicyRuntime(nil)
					r.manager = featurepolicy.NewManager(nil)
					r.ownerSnapshot = r.manager.Current()
					f := r.ownerSnapshot.Fence()
					st := UnifiedLeaseStore{Store: new(mem.Store), ProfileKey: "p"}
					gate := make(chan struct{})
					entered := make(chan struct{})
					c, err := appc.NewLeaseController(f, appc.LeaseOptions{MaxEntries: 10}, time.Now, st, func(featurepolicy.Fence, []appc.Lease) error {
						close(entered)
						<-gate
						if fail {
							return errors.New("route write failed")
						}
						return nil
					})
					if err != nil {
						t.Fatal(err)
					}
					b := &LocalBackend{logf: t.Logf}
					done := make(chan struct{})
					result := make(chan error, 1)
					workerDone := make(chan struct{})
					wait := time.Second
					if zero {
						wait = 0
					}
					go func() {
						result <- r.enqueueDNS(context.Background(), done, f, wait, func() error { return c.ObserveDNSAt(f, nil) })
					}()
					go func() { b.handleUnifiedDNS(r, <-r.dns); close(workerDone) }()
					<-entered
					if _, err := st.Load(); err != nil {
						t.Fatal("ack before durable evidence", err)
					}
					synctest.Wait()
					select {
					case <-result:
						t.Fatal("ack before complete durable commit")
					default:
					}

					close(gate)
					<-workerDone
					{
						if err := <-result; (err != nil) != fail {
							t.Fatal("wrong commit result", err)
						}
					}
					if fail && b.unifiedStatus.Degraded == "" {
						t.Fatal("failure hidden")
					}
				})
			})
		}
	}
}
func TestUnifiedDNSQueueConcurrent(t *testing.T) {
	r := newUnifiedPolicyRuntime(nil)
	r.manager = featurepolicy.NewManager(nil)
	r.ownerSnapshot = r.manager.Current()
	b := &LocalBackend{logf: t.Logf}
	done := make(chan struct{})
	workerDone := make(chan struct{})
	const n = 32
	go func() {
		defer close(workerDone)
		for range n {
			b.handleUnifiedDNS(r, <-r.dns)
		}
	}()
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			if err := r.enqueueDNS(context.Background(), done, r.manager.Current().Fence(), time.Second, func() error { return nil }); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	<-workerDone
}

func TestUnifiedDNSQueueCancelAfterDurableIntent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := newUnifiedPolicyRuntime(nil)
		r.manager = featurepolicy.NewManager(nil)
		r.ownerSnapshot = r.manager.Current()
		f := r.ownerSnapshot.Fence()
		st := UnifiedLeaseStore{Store: new(mem.Store), ProfileKey: "p"}
		entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
		c, err := appc.NewLeaseController(f, appc.LeaseOptions{MaxEntries: 10}, time.Now, st, func(featurepolicy.Fence, []appc.Lease) error { close(entered); <-release; return nil })
		if err != nil {
			t.Fatal(err)
		}
		b := &LocalBackend{logf: t.Logf}
		done := make(chan struct{})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		reply := make(chan error, 1)
		go func() {
			reply <- r.enqueueDNS(ctx, done, f, time.Second, func() error { return c.ObserveDNSAt(f, nil) })
		}()
		go func() { b.handleUnifiedDNS(r, <-r.dns); close(finished) }()
		<-entered
		cancel()
		if err := <-reply; !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation blocked", err)
		}
		if _, err := st.Load(); err != nil {
			t.Fatal("intent lost", err)
		}
		close(release)
		<-finished
	})
}
