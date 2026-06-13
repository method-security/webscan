// Package application — SEC-702.A engine tests.
//
// Covers the catalog's contract for the per-cluster PRs that ride on
// top of this foundation:
//   - extractor outputs override template metadata (delta 1)
//   - go:embed YAML helpers parse cleanly even at empty seed-time
//     (delta 2)
//   - OUI vendor disagreement is detected (delta 3 — log emission is
//     verified by exercising the pure detector; the engine wraps it
//     in svc1log.Info, which is not unit-testable here without a
//     wlog test fixture)
//   - the architecture value path round-trips through the closed
//     ApplicationArchitectureValue enum (delta 5)

package application

import (
	"testing"

	nuclei "github.com/Method-Security/webscan/generated/go/common/nuclei"
	"github.com/Method-Security/webscan/generated/go/discover"
)

// --- Delta 2: embedded YAML files parse cleanly at SEC-702.A seed time.

func TestArchLookupYAMLEmbedsAndParses(t *testing.T) {
	if err := archLookupLoadError(); err != nil {
		t.Fatalf("arch-lookup.yaml failed to load: %v", err)
	}
	// Seed table is intentionally empty; lookup should miss without
	// erroring.
	if _, ok := lookupArchitecture("mikrotik", "RB750Gr3"); ok {
		t.Fatalf("expected empty seed table to miss on every lookup")
	}
}

func TestOuiLookupYAMLEmbedsAndParses(t *testing.T) {
	if err := ouiLookupLoadError(); err != nil {
		t.Fatalf("oui.yaml failed to load: %v", err)
	}
	if _, ok := lookupOuiVendor("00:1A:EF:67:31:34"); ok {
		t.Fatalf("expected empty seed table to miss on every lookup")
	}
}

func TestMikrotikAssetHashYAMLEmbedsAndParses(t *testing.T) {
	if err := mikrotikAssetHashLoadError(); err != nil {
		t.Fatalf("mikrotik-asset-hashes.yaml failed to load: %v", err)
	}
	if _, ok := lookupMikrotikAssetHash("abcdef0123ab"); ok {
		t.Fatalf("expected empty seed table to miss on every lookup")
	}
}

// --- NormalizeMac / OUI helpers.

func TestNormalizeMacAcceptsCommonForms(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"colons", "00:1A:EF:67:31:34", "00:1A:EF:67:31:34"},
		{"dashes", "00-1a-ef-67-31-34", "00:1A:EF:67:31:34"},
		{"compact", "001aef673134", "00:1A:EF:67:31:34"},
		{"cisco-dot", "001a.ef67.3134", "00:1A:EF:67:31:34"},
		{"short", "00:1A:EF", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NormalizeMac(c.in); got != c.want {
				t.Errorf("NormalizeMac(%q) = %q; want %q", c.in, got, c.want)
			}
		})
	}
}

// --- Delta 3: OUI vendor mismatch detection (pure function, log
// emission tested via the detector return value).

func TestDetectOuiVendorMismatch(t *testing.T) {
	// Seed the in-memory table directly for the test — the YAML is
	// empty at SEC-702.A and we don't want to depend on per-cluster
	// PRs landing first.
	ouiLookupOnce.Do(loadOuiLookup)
	if ouiLookupLoadErr != nil {
		t.Fatalf("oui lookup load error: %v", ouiLookupLoadErr)
	}
	prior := ouiLookupTable
	t.Cleanup(func() { ouiLookupTable = prior })
	ouiLookupTable = map[string]string{
		// Hao Yun An Fang OEM rebrand of a Dahua HCVR — OUI is
		// Dahua's IEEE assignment but the template module is the
		// rebrand. The catalog says: log the disagreement, never
		// overwrite the module.
		"3CEF8C": "Dahua Technology Co., Ltd.",
	}

	cases := []struct {
		name         string
		mac          *string
		module       string
		wantVendor   string
		wantMismatch bool
	}{
		{
			name:         "no mac",
			mac:          nil,
			module:       "HAO_YUN_AN_FANG",
			wantMismatch: false,
		},
		{
			name:         "no module",
			mac:          strPtr("3C:EF:8C:11:22:33"),
			module:       "",
			wantMismatch: false,
		},
		{
			name:         "unknown OUI",
			mac:          strPtr("DE:AD:BE:EF:00:00"),
			module:       "MIKROTIK",
			wantMismatch: false,
		},
		{
			name:         "OUI agrees with module",
			mac:          strPtr("3C:EF:8C:11:22:33"),
			module:       "DAHUA",
			wantMismatch: false,
		},
		{
			name:         "OEM rebrand disagreement (Hao Yun / Dahua)",
			mac:          strPtr("3C:EF:8C:11:22:33"),
			module:       "HAO_YUN_AN_FANG",
			wantMismatch: true,
			wantVendor:   "Dahua Technology Co., Ltd.",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vendor, mismatch := detectOuiVendorMismatch(c.mac, c.module)
			if mismatch != c.wantMismatch {
				t.Errorf("detectOuiVendorMismatch mismatch = %v; want %v", mismatch, c.wantMismatch)
			}
			if vendor != c.wantVendor {
				t.Errorf("detectOuiVendorMismatch vendor = %q; want %q", vendor, c.wantVendor)
			}
		})
	}
}

// --- Engine wiring: convertNucleiAttemptToFingerprintAttemptStruct
// honors extractor-over-metadata precedence (delta 1) and round-trips
// the architecture enum (delta 5).

func TestConvertExtractorOverridesMetadata(t *testing.T) {
	module := "MIKROTIK"
	deviceMacMeta := "11:11:11:11:11:11"
	deviceMacExtract := "22:22:22:22:22:22"

	attempt := &nuclei.NucleiAttemptInfo{
		TemplateId: "mikrotik-routeros-7-17",
		Finding: &nuclei.NucleiFindingInfo{
			Finding: true,
			Metadata: map[string]string{
				metaApplicationType:        "NETWORK_EDGE_APPLICATION",
				metaModuleName:             module,
				metaDeviceMac:              deviceMacMeta,
				metaArchitectureValue:      "MIPSBE",
				metaArchitectureSource:     "DEVICE_DISCLOSED",
				metaArchitectureConfidence: "0.95",
			},
			ExtractedFields: map[string]string{
				extractDeviceMac:    deviceMacExtract,
				extractDeviceSerial: "ROUTER-001",
			},
		},
	}

	got := convertNucleiAttemptToFingerprintAttemptStruct(nil, attempt)
	if got == nil {
		t.Fatalf("convert returned nil")
	}
	// Extractor wins over metadata for MAC.
	if got.DeviceMac == nil || *got.DeviceMac != "22:22:22:22:22:22" {
		t.Errorf("DeviceMac = %v; want 22:22:22:22:22:22 (extractor wins)", got.DeviceMac)
	}
	// Serial comes from extractor only.
	if got.DeviceSerial == nil || *got.DeviceSerial != "ROUTER-001" {
		t.Errorf("DeviceSerial = %v; want ROUTER-001", got.DeviceSerial)
	}
	// Architecture: metadata-only path; value round-trips through
	// the closed enum.
	if got.Architecture == nil {
		t.Fatalf("Architecture is nil")
	}
	if got.Architecture.Value != discover.ApplicationArchitectureValueMipsbe {
		t.Errorf("Architecture.Value = %v; want MIPSBE", got.Architecture.Value)
	}
	if got.Architecture.Source != discover.ArchitectureSourceDeviceDisclosed {
		t.Errorf("Architecture.Source = %v; want DEVICE_DISCLOSED", got.Architecture.Source)
	}
	if got.Architecture.Confidence != 0.95 {
		t.Errorf("Architecture.Confidence = %v; want 0.95", got.Architecture.Confidence)
	}
	// Module unaffected.
	if got.Module != module {
		t.Errorf("Module = %q; want %q", got.Module, module)
	}
}

func TestConvertArchitectureFromExtractorOverridesMetadata(t *testing.T) {
	attempt := &nuclei.NucleiAttemptInfo{
		TemplateId: "qnap-qts",
		Finding: &nuclei.NucleiFindingInfo{
			Finding: true,
			Metadata: map[string]string{
				metaApplicationType:    "HARDWARE_MANAGEMENT_SYSTEM",
				metaModuleName:         "QNAP",
				metaArchitectureValue:  "ARM",
				metaArchitectureSource: "MODEL_LOOKUP",
			},
			ExtractedFields: map[string]string{
				extractArchValue:      "x86_64",
				extractArchSource:     "DEVICE_DISCLOSED",
				extractArchConfidence: "0.92",
			},
		},
	}
	got := convertNucleiAttemptToFingerprintAttemptStruct(nil, attempt)
	if got == nil || got.Architecture == nil {
		t.Fatalf("expected architecture populated")
	}
	if got.Architecture.Value != discover.ApplicationArchitectureValueX8664 {
		t.Errorf("Architecture.Value = %v; want X86_64 (extractor wins)", got.Architecture.Value)
	}
	if got.Architecture.Source != discover.ArchitectureSourceDeviceDisclosed {
		t.Errorf("Architecture.Source = %v; want DEVICE_DISCLOSED (extractor wins)", got.Architecture.Source)
	}
	if got.Architecture.Confidence != 0.92 {
		t.Errorf("Architecture.Confidence = %v; want 0.92", got.Architecture.Confidence)
	}
}

func TestConvertOuiMismatchDoesNotOverwriteModule(t *testing.T) {
	ouiLookupOnce.Do(loadOuiLookup)
	prior := ouiLookupTable
	t.Cleanup(func() { ouiLookupTable = prior })
	ouiLookupTable = map[string]string{
		"3CEF8C": "Dahua Technology Co., Ltd.",
	}

	attempt := &nuclei.NucleiAttemptInfo{
		TemplateId: "hao-yun-an-fang-hcvr",
		Finding: &nuclei.NucleiFindingInfo{
			Finding: true,
			Metadata: map[string]string{
				metaApplicationType: "INTERNET_OF_THINGS",
				metaModuleName:      "HAO_YUN_AN_FANG",
			},
			ExtractedFields: map[string]string{
				extractDeviceMac: "3C:EF:8C:11:22:33",
			},
		},
	}

	got := convertNucleiAttemptToFingerprintAttemptStruct(nil, attempt)
	if got == nil {
		t.Fatalf("convert returned nil")
	}
	// Critical: module MUST NOT be rewritten to Dahua.
	if got.Module != "HAO_YUN_AN_FANG" {
		t.Errorf("Module = %q; want HAO_YUN_AN_FANG (OEM rebrand preserved)", got.Module)
	}
	if got.DeviceMac == nil || *got.DeviceMac != "3C:EF:8C:11:22:33" {
		t.Errorf("DeviceMac = %v; want 3C:EF:8C:11:22:33", got.DeviceMac)
	}
}

func TestConvertRejectsUnknownArchitectureValue(t *testing.T) {
	// A template that emits a value not in the closed enum should
	// drop the architecture inference rather than ship a half-formed
	// record.
	attempt := &nuclei.NucleiAttemptInfo{
		TemplateId: "future-arch-template",
		Finding: &nuclei.NucleiFindingInfo{
			Finding: true,
			Metadata: map[string]string{
				metaApplicationType:    "INTERNET_OF_THINGS",
				metaModuleName:         "FUTURE_VENDOR",
				metaArchitectureValue:  "riscv64",
				metaArchitectureSource: "DEVICE_DISCLOSED",
			},
		},
	}
	got := convertNucleiAttemptToFingerprintAttemptStruct(nil, attempt)
	if got == nil {
		t.Fatalf("convert returned nil")
	}
	if got.Architecture != nil {
		t.Errorf("Architecture = %v; want nil (riscv64 not in closed enum)", got.Architecture)
	}
}

func strPtr(s string) *string { return &s }
