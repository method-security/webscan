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
//     itself via method-architecture-value; this helper is not
//     consulted.
//  2. MODEL_LOOKUP — template extracted a model identifier but the
//     architecture must be derived from a (vendor, model) lookup
//     table. Confidence 0.6–0.85. THIS helper handles that path.
//  3. INFERRED_FROM_FIRMWARE_URL — template extracted a firmware-URL
//     architecture token (mips/arm/x86_64 etc.). Confidence 0.4–0.6.
//     The template emits the inferred value directly; not handled
//     here.
//
// When the lookup returns no match the engine MUST NOT guess — the
// architecture field stays nil. Never fall back to "probably mips".

package application

import (
	"strings"
)

// archLookupTable is the in-memory mirror of
// utils/nuclei/templates/discover/application/_data/arch-lookup.yaml.
//
// The YAML file at that path is the human-facing source of truth;
// per-cluster PRs (Cluster C MikroTik, Cluster E Dahua, Cluster F
// Ubiquiti, Cluster P data sweep) populate it AND mirror the same
// entries into this map. A future `go generate` step will sync the
// two automatically; for SEC-702.A the table is empty by design —
// see the PR description for context.
//
// Key conventions:
//   - vendor: lowercase, hyphenated (e.g. "mikrotik", "ubiquiti",
//     "synology"). Matches method-arch-lookup-vendor metadata
//     emitted by templates.
//   - model: exact-match string (case-sensitive). Matches the
//     device-reported model verbatim.
//   - architecture: Linux/Go convention (arm, arm64, mipsbe,
//     mipsel, mips64be, x86, x86_64, ppc, ppc64, sh4, sparc,
//     riscv64, ...). Free string — the embedded-device universe
//     is wider than any practical enum.
var archLookupTable = map[string]map[string]string{
	// populated by per-cluster PRs; intentionally empty at SEC-702.A
}

// archLookupConfidence is the confidence value emitted for any
// MODEL_LOOKUP hit produced by this helper. 0.75 sits in the middle
// of the SEC-702 catalog's 0.6–0.85 range for MODEL_LOOKUP. Templates
// that want a different confidence can override via
// method-architecture-confidence metadata, which the engine prefers
// when set.
const archLookupConfidence = 0.75

// lookupArchitecture returns the architecture string for a
// (vendor, model) pair, or ("", false) if the pair is not in the
// table. Vendor is lowercased before lookup; model is matched as-is
// (devices that report case-varied model strings should normalize
// in the template extractor, not here).
func lookupArchitecture(vendor, model string) (string, bool) {
	if vendor == "" || model == "" {
		return "", false
	}
	models, ok := archLookupTable[strings.ToLower(vendor)]
	if !ok {
		return "", false
	}
	arch, ok := models[model]
	if !ok || arch == "" {
		return "", false
	}
	return arch, true
}
