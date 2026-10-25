package ipnlocal

import "testing"

func TestUnifiedReadvertiseWaitsForSnapshot(t *testing.T) {
	b := newTestLocalBackend(t)
	b.stopUnifiedPolicy()
	b.mu.Lock()
	b.unifiedOwnership = true
	b.unifiedSnapshot = nil
	before := b.pm.CurrentPrefs()
	b.mu.Unlock()
	b.readvertiseAppConnectorRoutes()
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.pm.CurrentPrefs().Equals(before) || !b.unifiedOwnership {
		t.Fatal("missing snapshot changed prefs or abandoned typed ownership")
	}
}
