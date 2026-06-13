// SEC-702.A — seed unit tests for the three shared engine helpers.
//
// The lookup tables at SEC-702.A are intentionally empty (per-cluster
// PRs populate them). These tests therefore exercise the contracts
// the helpers expose rather than concrete table entries:
//
//   - empty / malformed inputs return the no-hit sentinel
//   - vendor key lowercasing happens at the helper, not the caller
//   - MAC normalization handles colon / dash / dot / compact forms
//   - confidence clamping pins out-of-range values to [0.0, 1.0]
//
// Per-cluster PRs (C MikroTik, E Dahua, F Ubiquiti, I Raisecom)
// extend with table-hit cases as they populate their respective
// data entries. The tests here form the contract those later cases
// MUST not break.

package application

import (
	"testing"
)

func TestLookupArchitectureEmptyInputs(t *testing.T) {
	for _, tc := range []struct {
		name          string
		vendor, model string
	}{
		{"empty vendor", "", "RB951G"},
		{"empty model", "mikrotik", ""},
		{"both empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arch, ok := lookupArchitecture(tc.vendor, tc.model)
			if ok || arch != "" {
				t.Fatalf("expected (\"\", false), got (%q, %v)", arch, ok)
			}
		})
	}
}

func TestLookupArchitectureNoHitOnEmptyTable(t *testing.T) {
	// SEC-702.A ships with an empty archLookupTable. Until Cluster C /
	// E / F / P populate it, every well-formed lookup must miss.
	arch, ok := lookupArchitecture("mikrotik", "RB951G-2HnD")
	if ok || arch != "" {
		t.Fatalf("seed table should be empty; got (%q, %v)", arch, ok)
	}
}

func TestLookupOuiVendorEmptyAndShortInputs(t *testing.T) {
	for _, mac := range []string{
		"",
		"00:1A:EF",       // too few hex digits
		"not a mac",      // garbage
		"00:zz:ef:67:31", // non-hex
	} {
		vendor, ok := lookupOuiVendor(mac)
		if ok || vendor != "" {
			t.Fatalf("input %q expected miss, got (%q, %v)", mac, vendor, ok)
		}
	}
}

func TestLookupOuiVendorNormalizesAcceptedForms(t *testing.T) {
	// Every form should normalize to the same OUI prefix. Until the
	// table is populated they all miss — but we verify the
	// normalization works by accepting input without panic.
	for _, mac := range []string{
		"00:1A:EF:67:31:34",
		"00-1A-EF-67-31-34",
		"001a.ef67.3134",
		"001AEF673134",
	} {
		if prefix := normalizeOuiPrefix(mac); prefix != "001AEF" {
			t.Fatalf("input %q normalized to %q; expected 001AEF", mac, prefix)
		}
	}
}

func TestNormalizeMacCanonicalForm(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"00:1A:EF:67:31:34", "00:1A:EF:67:31:34"},
		{"00-1a-ef-67-31-34", "00:1A:EF:67:31:34"},
		{"001a.ef67.3134", "00:1A:EF:67:31:34"},
		{"001AEF673134", "00:1A:EF:67:31:34"},
		{"", ""},
		{"too short", ""},
	}
	for _, tc := range cases {
		if got := NormalizeMac(tc.in); got != tc.want {
			t.Errorf("NormalizeMac(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLookupMikrotikAssetHashEmptyAndMiss(t *testing.T) {
	if v, ok := lookupMikrotikAssetHash(""); ok || v != "" {
		t.Fatalf("empty hash should miss, got (%q, %v)", v, ok)
	}
	if v, ok := lookupMikrotikAssetHash("0123456789abcdef"); ok || v != "" {
		t.Fatalf("seed table should be empty; got (%q, %v)", v, ok)
	}
}

func TestClampConfidence(t *testing.T) {
	cases := []struct {
		in, want float64
	}{
		{-1.0, 0.0},
		{0.0, 0.0},
		{0.5, 0.5},
		{1.0, 1.0},
		{1.5, 1.0},
	}
	for _, tc := range cases {
		if got := clampConfidence(tc.in); got != tc.want {
			t.Errorf("clampConfidence(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
