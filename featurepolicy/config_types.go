// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package featurepolicy

// Config holds normalized schema-v2 settings. Parse applies defaults and validation.
type Config struct {
	SchemaVersion int                 `json:"schema_version"`
	Machine       string              `json:"machine"`
	Enabled       bool                `json:"enabled"`
	ReloadSeconds int                 `json:"reload_seconds"`
	Lease         LeaseConfig         `json:"app_connector_ttl"`
	AutoIPv6      AutoIPv6Config      `json:"auto_ipv6"`
	DNSIPv4Only   DNSConfig           `json:"dns_ipv4_only"`
	PathPolicy    PathConfig          `json:"path_policy"`
	Observability ObservabilityConfig `json:"observability"`
}

// LeaseConfig holds schema-v1 settings. Parse applies defaults and validation.
type LeaseConfig struct {
	Enabled                   bool   `json:"enabled"`
	ActivityMode              string `json:"activity_mode"`
	Migration                 string `json:"migration"`
	TTLCapSeconds             int    `json:"ttl_cap_seconds"`
	GraceSeconds              int    `json:"grace_seconds"`
	SweepSeconds              int    `json:"sweep_seconds"`
	BatchSize                 int    `json:"batch_size"`
	JitterSeconds             int    `json:"jitter_seconds"`
	MinAdvertiseSeconds       int    `json:"min_advertise_seconds"`
	MaxActiveRetentionSeconds int    `json:"max_active_retention_seconds"`
	UDPIdleSeconds            int    `json:"udp_idle_seconds"`
	ClockJumpSeconds          int    `json:"clock_jump_seconds"`
	MaxEntries                int    `json:"max_entries"`
	MaxFlowEntries            int    `json:"max_flow_entries"`
}

// AutoIPv6Config holds schema-v1 settings. Parse applies defaults and validation.
type AutoIPv6Config struct {
	Enabled bool `json:"enabled"`
	Publish bool `json:"publish"`
}

// DNSConfig holds schema-v1 settings. Parse applies defaults and validation.
type DNSConfig struct {
	Enabled            bool     `json:"enabled"`
	Targets            []string `json:"targets"`
	NegativeTTLSeconds int      `json:"negative_ttl_seconds"`
	DNSSECMode         string   `json:"dnssec_mode"`
	MaxChainDepth      int      `json:"max_chain_depth"`
	LocalRouteWaitMS   int      `json:"local_route_wait_ms"`
}

// PathConfig holds schema-v1 settings. Parse applies defaults and validation.
type PathConfig struct {
	Enabled             bool   `json:"enabled"`
	Rules               []Rule `json:"rules"`
	ProbeSeconds        int    `json:"probe_seconds"`
	ProbeTimeoutSeconds int    `json:"probe_timeout_seconds"`
	FailureThreshold    int    `json:"failure_threshold"`
	RecoverySuccesses   int    `json:"recovery_successes"`
	RecoveryHoldSeconds int    `json:"recovery_hold_seconds"`
	CooldownSeconds     int    `json:"cooldown_seconds"`
}

// ObservabilityConfig holds schema-v1 settings. Parse applies defaults and validation.
type ObservabilityConfig struct {
	LogDecisions     bool `json:"log_decisions"`
	LogRatePerMinute int  `json:"log_rate_per_minute"`
}

// Rule holds schema-v1 settings. Parse applies defaults and validation.
type Rule struct {
	ID             string   `json:"id"`
	StableIDs      []string `json:"stable_ids"`
	Tags           []string `json:"tags"`
	Allow          Allow    `json:"allow"`
	Prefer         []string `json:"prefer"`
	Fallback       string   `json:"fallback"`
	AllowBlackhole bool     `json:"allow_blackhole"`
}

// Allow holds schema-v1 settings. Parse applies defaults and validation.
type Allow struct {
	Direct    bool `json:"direct"`
	PeerRelay bool `json:"peer_relay"`
	Derp      bool `json:"derp"`
}
