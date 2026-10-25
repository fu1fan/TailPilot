package featurepolicy

import "testing"

// TestStrictConfig covers U-C01's structural rejection and defaults.
func TestStrictConfig(t *testing.T) {
	for _, s := range []string{`{}`, `{"schema_version":3}`, `{"schema_version":1,"enabled":null}`, `{"schema_version":1,"x":1}`, `{"schema_version":1,"lease":{"enabled":true,"enabled":false}}`, `{"schema_version":1} {}`, `{"schema_version":1,"reload_seconds":1.5}`, `{"schema_version":1,"reload_seconds":0}`, `{"schema_version":1,"lease":{"jitter_seconds":30,"sweep_seconds":1}}`} {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
	c, err := Parse([]byte(`{"schema_version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled || c.Lease.TTLCapSeconds != 86400 || !c.AutoIPv6.Publish {
		t.Fatalf("defaults: %+v", c)
	}
}

func FuzzPolicyConfig(f *testing.F) {
	f.Add([]byte(`{"schema_version":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, e := Parse(b)
		if e == nil {
			if _, e = Parse(c.JSON()); e != nil {
				t.Fatal(e)
			}
		}
	})
}

func TestV2Migration(t *testing.T) {
	v1 := []byte(`{"schema_version":1,"enabled":true,"lease":{"enabled":true,"grace_seconds":17,"max_entries":2000},"dns_ipv4_only":{"enabled":true,"targets":["example.test"]}}`)
	c, err := Parse(v1)
	if err != nil {
		t.Fatal(err)
	}
	if c.SchemaVersion != 2 || !c.Lease.Enabled || c.Lease.GraceSeconds != 17 || c.Lease.MaxEntries != 2000 {
		t.Fatal(c)
	}
	if Inspect(v1, nil, nil).Migration != "migrated-from-v1" {
		t.Fatal("migration not reported")
	}
	next, err := Parse(c.JSON())
	if err != nil || !equalJSON(c, next) {
		t.Fatal("migration round trip", err)
	}
	for _, s := range []string{`{"schema_version":2,"lease":{"enabled":true}}`, `{"schema_version":2,"lease":{},"app_connector_ttl":{}}`, `{"schema_version":1,"app_connector_ttl":{}}`} {
		if _, e := Parse([]byte(s)); e == nil {
			t.Fatal("accepted conflicting schema", s)
		}
	}
}
