// Package application — SEC-702.A IEEE OUI → vendor lookup helper.
//
// When a device self-discloses its MAC address pre-auth (TC-004
// Ubiquiti AIROS_<MAC> cookie + TLS cert CN, TC-015 Raisecom
// /status.htm MAC field), the first 24 bits of the MAC are the
// IEEE OUI prefix, registered to a specific manufacturer.
//
// The catalog's intended uses are (a) confirming a vendor attribution
// arrived at via other signals (defense against single-signal
// mis-attribution per the anti-patterns list), and (b) seeding a
// MODEL_LOOKUP for architecture inference when a vendor's product
// line maps cleanly to a single CPU family.

package application

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"

	yaml "gopkg.in/yaml.v3"
)

// ouiLookupYAML is the embedded YAML source of truth for the
// OUI → vendor table. Read once at first use into ouiLookupTable.
// Per-cluster PRs (Cluster F Ubiquiti, Cluster I Raisecom, Cluster P
// broader sweep) append entries by editing the YAML.
//
//go:embed _data/oui.yaml
var ouiLookupYAML []byte

type ouiLookupFile struct {
	Ouis map[string]string `yaml:"ouis"`
}

// ouiLookupTable is the in-memory mirror of _data/oui.yaml.
//
// Key format: 6 uppercase hex characters, no separators
// (e.g. "001AEF" for Raisecom Technology). Value: IEEE-registered
// manufacturer name as published in the public OUI registry,
// preserving spacing and punctuation ("Ubiquiti Networks Inc.",
// "Raisecom Technology Co., Ltd.").
var (
	ouiLookupTable   map[string]string
	ouiLookupOnce    sync.Once
	ouiLookupLoadErr error
)

func loadOuiLookup() {
	var parsed ouiLookupFile
	if err := yaml.Unmarshal(ouiLookupYAML, &parsed); err != nil {
		ouiLookupLoadErr = fmt.Errorf("oui.yaml unmarshal: %w", err)
		return
	}
	table := make(map[string]string, len(parsed.Ouis))
	for prefix, vendor := range parsed.Ouis {
		// OUI keys in the YAML may be written with or without
		// separators; strip and uppercase the hex digits, then assert
		// exactly 6. We fail-loud on any key that doesn't normalize to
		// 6 hex digits — silent skip would silently lose vendor entries
		// that the catalog explicitly relied on.
		normalized := stripToHex(prefix)
		if len(normalized) != 6 {
			ouiLookupLoadErr = fmt.Errorf("oui.yaml: prefix %q must normalize to exactly 6 hex digits (got %d)", prefix, len(normalized))
			return
		}
		vendor = strings.TrimSpace(vendor)
		if vendor == "" {
			continue
		}
		table[normalized] = vendor
	}
	ouiLookupTable = table
}

// stripToHex extracts the hex digits from s (skipping :, -, ., space,
// and anything else) and uppercases lowercase hex. Used by the OUI
// loader and by normalizeOuiPrefix.
func stripToHex(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'F':
			b.WriteRune(r)
		case r >= 'a' && r <= 'f':
			b.WriteRune(r - 32)
		}
	}
	return b.String()
}

// lookupOuiVendor returns the IEEE-registered vendor for the OUI
// prefix of mac, or ("", false) if the prefix is not in the table.
// Accepts MACs in any common form:
//   - "00:1A:EF:67:31:34" (colon-separated, mixed case)
//   - "00-1A-EF-67-31-34" (dash-separated)
//   - "001a.ef67.3134"    (Cisco dotted-quad)
//   - "001AEF673134"      (compact, uppercase)
//
// Returns the vendor for any input that contains at least 12 hex
// digits after normalization; shorter inputs fail-closed with
// ("", false). Never emits a guess.
func lookupOuiVendor(mac string) (string, bool) {
	ouiLookupOnce.Do(loadOuiLookup)
	if ouiLookupLoadErr != nil {
		return "", false
	}
	prefix := normalizeOuiPrefix(mac)
	if prefix == "" {
		return "", false
	}
	vendor, ok := ouiLookupTable[prefix]
	if !ok || vendor == "" {
		return "", false
	}
	return vendor, true
}

// ouiLookupLoadError exposes any error from the lazy YAML load.
// Used by tests to assert the embedded file parses cleanly.
func ouiLookupLoadError() error {
	ouiLookupOnce.Do(loadOuiLookup)
	return ouiLookupLoadErr
}

// normalizeOuiPrefix strips MAC separators, uppercases the result,
// and returns the leading 6 hex characters — or "" if mac yields
// fewer than 12 hex digits after stripping (i.e. not a complete
// 48-bit MAC).
func normalizeOuiPrefix(mac string) string {
	hex := stripToHex(mac)
	if len(hex) < 12 {
		return ""
	}
	return hex[:6]
}

// NormalizeMac returns mac in canonical colon-separated uppercase
// form ("AA:BB:CC:DD:EE:FF"), or "" if mac does not contain a
// complete 48-bit MAC. Used by engine.go to populate
// ApplicationFingerprintAttempt.deviceMac so consumers see a single
// canonical form regardless of how the source device formatted its
// MAC. Exported (and capitalized) because the engine in this same
// package writes the canonical value into the fingerprint struct.
func NormalizeMac(mac string) string {
	hex := stripToHex(mac)
	if len(hex) < 12 {
		return ""
	}
	hex = hex[:12]
	return hex[0:2] + ":" + hex[2:4] + ":" + hex[4:6] + ":" +
		hex[6:8] + ":" + hex[8:10] + ":" + hex[10:12]
}
