// Package application — SEC-702.A architecture inference helper.
//
// The catalog defines three viable sources for the pre-auth HTTP
// architecture inference (see SEC-702 description, "Architecture
// inference" section):
//
//  1. DEVICE_DISCLOSED — template extracted an architecture string
//     directly from the device's pre-auth response (Synology
//     `unique`, QNAP `<platform>`, Dahua `/cap.js` `devType`).
//     Confidence ≥ 0.9. The template emits the architecture value
//     itself via method-architecture-value (or the architecture_value
//     extractor); this helper is not consulted.
//  2. MODEL_LOOKUP — template extracted a model identifier but the
//     architecture must be derived from a (vendor, model) lookup
//     table. Confidence 0.6–0.85. THIS helper handles that path.
//  3. INFERRED_FROM_FIRMWARE_URL — template extracted a firmware-URL
//     architecture token. Confidence 0.4–0.6. The template emits the
//     inferred value directly; not handled here.
//
// When the lookup returns no match the engine MUST NOT guess — the
// architecture field stays nil. Never fall back to "probably mips".

package application

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"

	discover "github.com/Method-Security/webscan/generated/go/discover"
	yaml "gopkg.in/yaml.v3"
)

// archLookupYAML is the embedded YAML source of truth for the
// (vendor, model) → architecture table. The file at
// internal/discover/application/_data/arch-lookup.yaml is read once
// at first use (lazy via sync.Once) and parsed into archLookupTable.
// Per-cluster PRs (Cluster C MikroTik, Cluster E Dahua, Cluster F
// Ubiquiti, Cluster P data sweep) append entries by editing the YAML.
//
//go:embed _data/arch-lookup.yaml
var archLookupYAML []byte

type archLookupFile struct {
	Vendors map[string]map[string]string `yaml:"vendors"`
}

// archLookupTable is the in-memory lookup map. Keys after load:
//   - outer: lowercase vendor (e.g. "mikrotik", "ubiquiti",
//     "synology"). Matches method-arch-lookup-vendor metadata
//     emitted by templates.
//   - inner: exact-match model string (case-sensitive). Matches the
//     device-reported model verbatim.
//   - value: validated ApplicationArchitectureValue enum constant.
//     YAML allows lowercase friendly form ("mipsbe"); the loader
//     uppercases and validates against the Fern enum, so a typo in
//     the YAML fails loud at package init, not silently at scan time.
var (
	archLookupTable   map[string]map[string]discover.ApplicationArchitectureValue
	archLookupOnce    sync.Once
	archLookupLoadErr error
)

// archLookupConfidence is the confidence value emitted for any
// MODEL_LOOKUP hit produced by this helper. 0.75 sits in the middle
// of the SEC-702 catalog's 0.6–0.85 range for MODEL_LOOKUP. Templates
// that want a different confidence can override via
// method-architecture-confidence (metadata or extractor), which the
// engine prefers when set.
const archLookupConfidence = 0.75

func loadArchLookup() {
	var parsed archLookupFile
	if err := yaml.Unmarshal(archLookupYAML, &parsed); err != nil {
		archLookupLoadErr = fmt.Errorf("arch-lookup.yaml unmarshal: %w", err)
		return
	}
	table := make(map[string]map[string]discover.ApplicationArchitectureValue, len(parsed.Vendors))
	for vendor, models := range parsed.Vendors {
		vendorKey := strings.ToLower(strings.TrimSpace(vendor))
		if vendorKey == "" {
			continue
		}
		inner := make(map[string]discover.ApplicationArchitectureValue, len(models))
		for model, archStr := range models {
			model = strings.TrimSpace(model)
			archStr = strings.TrimSpace(archStr)
			if model == "" || archStr == "" {
				continue
			}
			archEnum, err := discover.NewApplicationArchitectureValueFromString(strings.ToUpper(archStr))
			if err != nil {
				archLookupLoadErr = fmt.Errorf(
					"arch-lookup.yaml: vendor=%q model=%q has unknown architecture %q (must match ApplicationArchitectureValue enum): %w",
					vendor, model, archStr, err)
				return
			}
			inner[model] = archEnum
		}
		if len(inner) > 0 {
			table[vendorKey] = inner
		}
	}
	archLookupTable = table
}

// lookupArchitecture returns the architecture enum for a
// (vendor, model) pair, or (zero, false) if the pair is not in the
// table. Vendor is lowercased before lookup; model is matched as-is
// (devices that report case-varied model strings should normalize
// in the template extractor, not here).
//
// If the YAML failed to parse at init (e.g. a typo'd architecture
// string), every lookup returns (zero, false). The engine treats
// no-hit as the expected case (the seed table is empty), so a load
// failure degrades gracefully to "no architecture inference" rather
// than crashing the scan.
func lookupArchitecture(vendor, model string) (discover.ApplicationArchitectureValue, bool) {
	archLookupOnce.Do(loadArchLookup)
	if archLookupLoadErr != nil {
		return "", false
	}
	if vendor == "" || model == "" {
		return "", false
	}
	models, ok := archLookupTable[strings.ToLower(vendor)]
	if !ok {
		return "", false
	}
	arch, ok := models[model]
	if !ok {
		return "", false
	}
	return arch, true
}
