// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package featurepolicy compiles opt-in policy into immutable, fenced snapshots.
package featurepolicy

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxConfigBytes bounds parsing work and file reads.
const MaxConfigBytes = 1 << 20

//go:embed schema.json
var schemaBytes []byte

//go:embed schema-v2.json
var schemaV2Bytes []byte

// JSON returns a fresh, normalized representation of c.
func (c Config) JSON() []byte { b, _ := json.Marshal(c); return b }

// Parse strictly validates schema v1 and all cross-field invariants. No caller
// should construct an active snapshot directly from a mutable Config.
func Parse(b []byte) (Config, error) {
	var c Config
	if len(b) > MaxConfigBytes || !utf8.Valid(b) {
		return c, fmt.Errorf("config: size or UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, e := readValue(d, "$", 0)
	if e != nil {
		return c, e
	}
	if _, e = d.Token(); e != io.EOF {
		return c, fmt.Errorf("config: trailing JSON")
	}
	var schema map[string]any
	selected := schemaBytes
	if obj, ok := v.(map[string]any); ok && obj["schema_version"] == json.Number("2") {
		selected = schemaV2Bytes
	}
	if e = json.Unmarshal(selected, &schema); e != nil {
		panic(e)
	}
	v, e = validate(v, schema, "$")
	if e != nil {
		return c, e
	}
	obj := v.(map[string]any)
	if obj["schema_version"] == json.Number("1") {
		obj["app_connector_ttl"] = obj["lease"]
		delete(obj, "lease")
		obj["schema_version"] = 2
	}
	data, _ := json.Marshal(v)
	if e = json.Unmarshal(data, &c); e != nil {
		return c, e
	}
	l := c.Lease
	if l.JitterSeconds > l.SweepSeconds || l.MaxActiveRetentionSeconds < l.GraceSeconds || l.MinAdvertiseSeconds > l.TTLCapSeconds+l.GraceSeconds+l.MaxActiveRetentionSeconds {
		return c, fmt.Errorf("lease: inconsistent timing")
	}
	seen := map[string]bool{}
	for i := range c.DNSIPv4Only.Targets {
		n, e := NormalizeDomain(c.DNSIPv4Only.Targets[i])
		if e != nil {
			return c, e
		}
		if seen[n] {
			return c, fmt.Errorf("dns targets: duplicate %q", n)
		}
		seen[n] = true
		c.DNSIPv4Only.Targets[i] = n
	}
	if c.DNSIPv4Only.Enabled && len(c.DNSIPv4Only.Targets) == 0 {
		return c, fmt.Errorf("dns_ipv4_only.targets: empty")
	}
	seen = map[string]bool{}
	for _, r := range c.PathPolicy.Rules {
		if seen[r.ID] {
			return c, fmt.Errorf("path_policy: duplicate rule id")
		}
		seen[r.ID] = true
		if len(r.Tags) > 0 {
			return c, fmt.Errorf("path_policy: tags not supported in v1")
		}
		if len(r.StableIDs) == 0 {
			return c, fmt.Errorf("path_policy: selector required")
		}
		allowed := map[string]bool{"direct": r.Allow.Direct, "peer_relay": r.Allow.PeerRelay, "derp": r.Allow.Derp}
		n := 0
		for _, v := range allowed {
			if v {
				n++
			}
		}
		if n == 0 && !r.AllowBlackhole {
			return c, fmt.Errorf("path_policy: blackhole requires opt-in")
		}
		if len(r.Prefer) != n {
			return c, fmt.Errorf("path_policy: prefer must cover allow")
		}
		for _, p := range r.Prefer {
			if !allowed[p] {
				return c, fmt.Errorf("path_policy: forbidden preference")
			}
		}
	}
	return c, nil
}

// readValue rejects duplicate members before encoding/json can discard them.
func readValue(d *json.Decoder, path string, depth int) (any, error) {
	if depth > 32 {
		return nil, fmt.Errorf("%s: nesting too deep", path)
	}
	t, e := d.Token()
	if e != nil {
		return nil, fmt.Errorf("%s: %w", path, e)
	}
	switch t {
	case json.Delim('{'):
		m := map[string]any{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return nil, e
			}
			s, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("%s: member name", path)
			}
			if _, ok := m[s]; ok {
				return nil, fmt.Errorf("%s.%s: duplicate", path, s)
			}
			v, e := readValue(d, path+"."+s, depth+1)
			if e != nil {
				return nil, e
			}
			m[s] = v
		}
		_, e = d.Token()
		return m, e
	case json.Delim('['):
		a := []any{}
		for d.More() {
			v, e := readValue(d, fmt.Sprintf("%s[%d]", path, len(a)), depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		_, e = d.Token()
		return a, e
	default:
		return t, nil
	}
}

// validate implements only the closed vocabulary of the embedded v1 schema.
func validate(v any, s map[string]any, path string) (any, error) {
	fail := func() (any, error) { return nil, fmt.Errorf("%s: invalid %s", path, s["type"]) }
	switch s["type"] {
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			return fail()
		}
		ps := s["properties"].(map[string]any)
		for k := range m {
			if _, ok := ps[k]; !ok {
				return nil, fmt.Errorf("%s.%s: unknown field", path, k)
			}
		}
		if r, ok := s["required"].([]any); ok {
			for _, k := range r {
				if _, ok := m[k.(string)]; !ok {
					return nil, fmt.Errorf("%s.%s: required", path, k)
				}
			}
		}
		for k, p := range ps {
			ss := p.(map[string]any)
			x, ok := m[k]
			if !ok {
				if def, yes := ss["default"]; yes {
					x = def
				} else if ss["type"] == "object" {
					x = map[string]any{}
				} else {
					continue
				}
			}
			// Schema defaults are decoded as floats, while input numbers are JSON numbers.
			if f, ok := x.(float64); ok {
				x = json.Number(fmt.Sprint(f))
			}
			y, e := validate(x, ss, path+"."+k)
			if e != nil {
				return nil, e
			}
			m[k] = y
		}
		return m, nil
	case "array":
		a, ok := v.([]any)
		if !ok {
			return fail()
		}
		if lim, ok := s["maxItems"].(float64); ok && len(a) > int(lim) {
			return fail()
		}
		seen := map[string]bool{}
		for i, x := range a {
			y, e := validate(x, s["items"].(map[string]any), fmt.Sprintf("%s[%d]", path, i))
			if e != nil {
				return nil, e
			}
			b, _ := json.Marshal(y)
			if s["uniqueItems"] == true && seen[string(b)] {
				return nil, fmt.Errorf("%s: duplicate item", path)
			}
			seen[string(b)] = true
			a[i] = y
		}
		return a, nil
	case "integer":
		n, ok := v.(json.Number)
		if !ok {
			return fail()
		}
		i, e := n.Int64()
		if e != nil {
			return fail()
		}
		if min, ok := s["minimum"].(float64); ok && i < int64(min) {
			return fail()
		}
		if max, ok := s["maximum"].(float64); ok && i > int64(max) {
			return fail()
		}
		if c, ok := s["const"].(float64); ok && i != int64(c) {
			return fail()
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return fail()
		}
	case "string":
		str, ok := v.(string)
		if !ok {
			return fail()
		}
		n := utf8.RuneCountInString(str)
		if min, ok := s["minLength"].(float64); ok && n < int(min) {
			return fail()
		}
		if max, ok := s["maxLength"].(float64); ok && n > int(max) {
			return fail()
		}
		if pat, ok := s["pattern"].(string); ok && !regexp.MustCompile(pat).MatchString(str) {
			return fail()
		}
	default:
		return fail()
	}
	if enums, ok := s["enum"].([]any); ok {
		found := false
		for _, x := range enums {
			if x == v {
				found = true
			}
		}
		if !found {
			return fail()
		}
	}
	return v, nil
}

// NormalizeDomain accepts ASCII A-label names with an optional leading wildcard.
func NormalizeDomain(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	n := strings.TrimPrefix(s, "*.")
	if n == "" || len(s) > 253 {
		return "", fmt.Errorf("domain: invalid length")
	}
	for _, label := range strings.Split(n, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("domain: invalid label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("domain: expected ASCII A-label")
			}
		}
	}
	return s, nil
}

// matches uses label boundaries; a wildcard excludes its apex.
func matches(pattern, name string) bool {
	if strings.HasPrefix(pattern, "*.") {
		root := pattern[2:]
		return name != root && strings.HasSuffix(name, "."+root)
	}
	return name == pattern
}
