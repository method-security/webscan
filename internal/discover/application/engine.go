package application

import (
	// Standard
	"context"
	"strconv"
	"strings"

	// Generated
	nuclei "github.com/Method-Security/webscan/generated/go/common/nuclei"
	"github.com/Method-Security/webscan/generated/go/discover"

	// Utils
	nucleiutils "github.com/Method-Security/webscan/utils/nuclei"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// Template-author input contract.
//
// Templates emit values via two channels and the engine reads BOTH:
//
//  1. `info.metadata.<key>:` — STATIC values shared by every host the
//     template fires on (e.g. method-module-name: "MIKROTIK"). The
//     keys listed in this block are the seed metadata contract.
//
//  2. `extractors[*].name: <key>` — PER-HOST values captured at scan
//     time (e.g. a regex extractor named `device_mac` whose value
//     varies by target). These ride along on each NucleiFindingInfo
//     in the new ExtractedFields map (see Builder in
//     utils/nuclei/report).
//
// PRECEDENCE: extractor output WINS over metadata. A template that
// statically declares method-device-mac AND defines an extractor
// named device_mac that doesn't fire will emit the metadata value;
// if the extractor does fire, the engine uses the per-host capture.
// Same rule applies to architecture_value / architecture_source /
// architecture_confidence and to device_serial.
//
// Per-cluster PRs are free to add more keys; the names below are the
// seed contract.
const (
	metaApplicationType        = "method-application-type"
	metaModuleName             = "method-module-name"
	metaSubModuleName          = "method-sub-module-name"
	metaDetectionState         = "method-detection-state"
	metaCPE                    = "cpe"
	metaArchitectureValue      = "method-architecture-value"
	metaArchitectureSource     = "method-architecture-source"
	metaArchitectureConfidence = "method-architecture-confidence"
	metaArchLookupVendor       = "method-arch-lookup-vendor"
	metaArchLookupModel        = "method-arch-lookup-model"
	metaDeviceMac              = "method-device-mac"
	metaDeviceSerial           = "method-device-serial"
	metaMikrotikAssetHash      = "method-mikrotik-asset-hash"
)

// Extractor name contract. Templates that need per-host
// values define Nuclei extractors with these exact `name:` strings;
// the Builder maps name → captured value into ExtractedFields.
const (
	extractArchValue         = "architecture_value"
	extractArchSource        = "architecture_source"
	extractArchConfidence    = "architecture_confidence"
	extractDeviceMac         = "device_mac"
	extractDeviceSerial      = "device_serial"
	extractMikrotikAssetHash = "mikrotik_asset_hash"
)

// pickField returns the extractor-output value for extractorKey if
// present and non-empty; otherwise falls back to the metadata value
// for metaKey. This is the canonical "extractor wins over metadata"
// helper for the metadata and extractor inputs.
//
// Pass extractorKey="" to skip the extractor lookup entirely (e.g.
// when the field is currently metadata-only at the template layer).
// Pass metaKey="" to skip the metadata fallback. The TrimSpace guard
// rejects whitespace-only values from either source.
func pickField(ef map[string]string, extractorKey string, md map[string]string, metaKey string) string {
	if extractorKey != "" {
		if v, ok := ef[extractorKey]; ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	if metaKey != "" {
		if v, ok := md[metaKey]; ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// convertNucleiAttemptToFingerprintAttemptStruct converts a Nuclei
// attempt to an application fingerprint attempt. log is the engine
// log handle threaded through from LaunchFingerprintEngine; it's used
// for the OUI-vs-module observability warning.
// Passing a nil log is safe — the OUI helper short-circuits.
func convertNucleiAttemptToFingerprintAttemptStruct(log svc1log.Logger, nucleiAttempt *nuclei.NucleiAttemptInfo) *discover.ApplicationFingerprintAttempt {
	if nucleiAttempt == nil || nucleiAttempt.TemplateId == "" {
		return nil
	}

	// Extract resource type, module, detection state, and CPE from template metadata
	var resourceTypeMetadata discover.ApplicationResourceType
	var moduleNameFromMetadata string
	var subModuleNameFromMetadata *string
	var detectionStateFromMetadata *discover.ApplicationDetectionState
	var cpeFromMetadata *string
	var architectureFromMetadata *discover.ArchitectureInfo
	var deviceMacFromMetadata *string
	var deviceSerialFromMetadata *string

	// Pull the metadata + extractor maps from the finding. Either
	// may be nil (template without metadata, or without extractors).
	// We pass both to the helpers below; the pickField helper handles
	// nil gracefully and "extractor wins" is uniform across the call
	// sites.
	var md map[string]string
	var ef map[string]string
	if nucleiAttempt.Finding != nil {
		md = nucleiAttempt.Finding.Metadata
		ef = nucleiAttempt.Finding.ExtractedFields
	}

	if md != nil {
		// Check for method-application-type in metadata
		if appTypeStr, exists := md[metaApplicationType]; exists {
			if appType, err := discover.NewApplicationResourceTypeFromString(appTypeStr); err == nil {
				resourceTypeMetadata = appType
			}
		}

		// Check for method-module-name in metadata
		if moduleStr, exists := md[metaModuleName]; exists {
			moduleNameFromMetadata = strings.ToUpper(moduleStr)
		}

		// Check for method-sub-module-name in metadata
		if subModuleStr, exists := md[metaSubModuleName]; exists {
			subModuleNameFromMetadata = &subModuleStr
		}

		// Check for method-detection-state in metadata
		if detectionStateStr, exists := md[metaDetectionState]; exists {
			if detectionState, err := discover.NewApplicationDetectionStateFromString(detectionStateStr); err == nil {
				detectionStateFromMetadata = &detectionState
			}
		}

		// Check for cpe in metadata
		if cpeStr, exists := md[metaCPE]; exists {
			cpeFromMetadata = &cpeStr
		}
	}

	// Derive architecture from extractors first, then metadata.
	// Returns nil when neither path applies; never guesses.
	architectureFromMetadata = deriveArchitecture(md, ef)

	// Device MAC: extractor wins over metadata. Normalize to canonical
	// form before publishing. NormalizeMac fails-closed on inputs that
	// don't contain a full 48-bit MAC, so a garbage extractor result
	// produces no deviceMac (rather than a half-formed one).
	if rawMac := pickField(ef, extractDeviceMac, md, metaDeviceMac); rawMac != "" {
		if canonical := NormalizeMac(rawMac); canonical != "" {
			deviceMacFromMetadata = &canonical
		}
	}

	// Device serial: verbatim. Some devices (Dahua 2019+) emit a
	// 32-char hex realm that looks like a serial but is actually a
	// hash; templates must length-bound their extractors. The engine
	// trusts the template's extractor here — it does not re-validate.
	if rawSerial := pickField(ef, extractDeviceSerial, md, metaDeviceSerial); rawSerial != "" {
		trimmed := strings.TrimSpace(rawSerial)
		if trimmed != "" {
			deviceSerialFromMetadata = &trimmed
		}
	}

	// MikroTik 7.17+ asset-hash → version dereference. If the template
	// provided a CPE template containing the
	// literal placeholder "{version}" AND the asset-hash hits a
	// known RouterOS release, substitute. Otherwise leave the CPE
	// untouched. This keeps the asset-hash helper useful even
	// when the schema has no dedicated version field.
	if hash := pickField(ef, extractMikrotikAssetHash, md, metaMikrotikAssetHash); hash != "" {
		if version, ok := lookupMikrotikAssetHash(hash); ok && cpeFromMetadata != nil {
			substituted := strings.ReplaceAll(*cpeFromMetadata, "{version}", version)
			cpeFromMetadata = &substituted
		}
	}

	// OUI vendor confirmation, log-only.
	// When the device self-disclosed its MAC pre-auth and OuiLookup
	// returns a vendor that disagrees with the template's
	// method-module-name, log a warning at INFO. NEVER overwrite the
	// module — OEM-rebrand cases (Hao Yun An Fang / Dahua, Amcrest /
	// Dahua) intentionally surface the rebrand attribution from the
	// template, not the underlying ODM from the OUI. The disagreement
	// is forensically interesting (both vendors are recorded), not a
	// correction signal.
	maybeLogOuiVendorMismatch(log, nucleiAttempt.TemplateId, deviceMacFromMetadata, moduleNameFromMetadata)

	// Create the simplified fingerprint attempt using the new Fern structure
	attempt := &discover.ApplicationFingerprintAttempt{
		ResourceType:   resourceTypeMetadata,
		Module:         moduleNameFromMetadata,
		SubModule:      subModuleNameFromMetadata,
		DetectionState: detectionStateFromMetadata,
		Cpe:            cpeFromMetadata,
		Finding:        true,
		Request:        nucleiAttempt.HttpRequestResponse,
		Architecture:   architectureFromMetadata,
		DeviceMac:      deviceMacFromMetadata,
		DeviceSerial:   deviceSerialFromMetadata,
	}

	return attempt
}

// detectOuiVendorMismatch returns (vendor, true) if the device MAC's
// OUI prefix resolves to a vendor that disagrees with module, and
// ("", false) otherwise. Disagreement is case-insensitive on a
// substring basis — "DAHUA" matches "Dahua Technology Co., Ltd.";
// "MIKROTIK" matches "Routerboard.com" only if neither contains the
// other (i.e. truly different vendors).
//
// Returns ("", false) for any of: deviceMac nil/empty, OUI lookup
// miss, module empty, or vendor-and-module agree. Pulled out as a
// pure function so engine_test.go can exercise it without a logger
// or log capture.
func detectOuiVendorMismatch(deviceMac *string, module string) (string, bool) {
	if deviceMac == nil || *deviceMac == "" {
		return "", false
	}
	if module == "" {
		return "", false
	}
	vendor, found := lookupOuiVendor(*deviceMac)
	if !found {
		return "", false
	}
	// Case-insensitive substring agreement check. Either name may be
	// the abbreviated form of the other ("DAHUA" vs "Dahua Technology
	// Co., Ltd."), so a match in either direction means they agree.
	vendorLower := strings.ToLower(vendor)
	moduleLower := strings.ToLower(module)
	if strings.Contains(vendorLower, moduleLower) || strings.Contains(moduleLower, vendorLower) {
		return "", false
	}
	return vendor, true
}

// maybeLogOuiVendorMismatch is the engine-side caller. Logs a single
// INFO line when OUI vendor and template module disagree (matching
// the engine's existing observability level for fingerprint events);
// log == nil short-circuits so non-engine callers don't need to
// fabricate a logger.
func maybeLogOuiVendorMismatch(log svc1log.Logger, templateID string, deviceMac *string, module string) {
	if log == nil {
		return
	}
	vendor, mismatch := detectOuiVendorMismatch(deviceMac, module)
	if !mismatch {
		return
	}
	log.Info(
		"OUI vendor disagrees with template module — both retained, no overwrite",
		svc1log.SafeParam("templateId", templateID),
		svc1log.SafeParam("deviceMac", *deviceMac),
		svc1log.SafeParam("ouiVendor", vendor),
		svc1log.SafeParam("templateModule", module),
	)
}

// deriveArchitecture builds an ArchitectureInfo from template
// metadata + per-host extractor outputs, or returns nil when no
// source applies. Extractor values win over metadata for each
// field (value / source / confidence) independently — a template
// that statically declares method-architecture-source but emits a
// per-host architecture_value via extractor combines both. Two
// derivation paths:
//
//  1. Direct value path. Template emits architecture_value
//     (extractor) or method-architecture-value (metadata) AND a
//     parseable source. The value must match the
//     ApplicationArchitectureValue Fern enum (uppercase, case-
//     insensitive on read). Unsourced values are dropped to keep
//     the provenance contract honest. Confidence defaults to 0.0
//     when absent / unparseable.
//
//  2. Model-lookup path. Template emits method-arch-lookup-vendor +
//     method-arch-lookup-model AND no direct value. The engine calls
//     lookupArchitecture and on a hit emits source=MODEL_LOOKUP with
//     confidence=archLookupConfidence (0.75 midpoint of the 0.6–0.85
//     MODEL_LOOKUP range); a template-supplied confidence (extractor
//     or metadata) overrides.
//
// Returns nil when neither path applies — never guesses.
func deriveArchitecture(md, ef map[string]string) *discover.ArchitectureInfo {
	// Path 1: direct value (extractor wins per-field over metadata).
	archValueStr := pickField(ef, extractArchValue, md, metaArchitectureValue)
	if archValueStr != "" {
		archSourceStr := pickField(ef, extractArchSource, md, metaArchitectureSource)
		if archSourceStr == "" {
			return nil
		}
		archSrc, err := discover.NewArchitectureSourceFromString(archSourceStr)
		if err != nil {
			return nil
		}
		archEnum, err := discover.NewApplicationArchitectureValueFromString(strings.ToUpper(strings.TrimSpace(archValueStr)))
		if err != nil {
			// Value didn't match the closed enum (e.g. a template
			// emitted "riscv64" before that arch was added). Drop the
			// inference rather than emit a half-formed record.
			return nil
		}
		confidence := 0.0
		if confStr := pickField(ef, extractArchConfidence, md, metaArchitectureConfidence); confStr != "" {
			if parsed, parseErr := strconv.ParseFloat(strings.TrimSpace(confStr), 64); parseErr == nil {
				confidence = clampConfidence(parsed)
			}
		}
		return &discover.ArchitectureInfo{
			Value:      archEnum,
			Source:     archSrc,
			Confidence: confidence,
		}
	}

	// Path 2: (vendor, model) → arch lookup. The lookup keys are
	// template-static today (per-cluster PRs may add extractor-based
	// vendor/model keys later, in which case pickField will handle
	// the precedence automatically).
	vendor := pickField(ef, "", md, metaArchLookupVendor)
	model := pickField(ef, "", md, metaArchLookupModel)
	if vendor == "" || model == "" {
		return nil
	}
	archEnum, hit := lookupArchitecture(vendor, model)
	if !hit {
		// Empty table at seed-time; no hit is the expected path until
		// per-cluster PRs populate the table.
		return nil
	}
	confidence := archLookupConfidence
	if confStr := pickField(ef, extractArchConfidence, md, metaArchitectureConfidence); confStr != "" {
		if parsed, parseErr := strconv.ParseFloat(strings.TrimSpace(confStr), 64); parseErr == nil {
			confidence = clampConfidence(parsed)
		}
	}
	return &discover.ArchitectureInfo{
		Value:      archEnum,
		Source:     discover.ArchitectureSourceModelLookup,
		Confidence: confidence,
	}
}

// clampConfidence pins a confidence value to [0.0, 1.0]. The Fern
// schema doesn't constrain the range, so the engine enforces it
// here to keep downstream consumers honest.
func clampConfidence(c float64) float64 {
	if c < 0.0 {
		return 0.0
	}
	if c > 1.0 {
		return 1.0
	}
	return c
}

// createDiscoverApplicationNucleiConfig builds the Nuclei config for application discovery
func createDiscoverApplicationNucleiConfig(ctx context.Context, config *discover.DiscoverApplicationConfig) (nuclei.NucleiConfig, error) {
	log := svc1log.FromContext(ctx)

	// Get template paths based on resource type
	templatePaths, err := getTemplatePaths(config.ResourceType)
	if err != nil {
		log.Error("Failed to get template paths", svc1log.SafeParam("error", err.Error()))
		return nuclei.NucleiConfig{}, err
	}

	log.Info("Built Nuclei config for application discovery",
		svc1log.SafeParam("templatePaths", templatePaths),
		svc1log.SafeParam("targets", config.Targets),
		svc1log.SafeParam("timeout", config.Timeout),
		svc1log.SafeParam("threads", config.Threads))

	return nuclei.NucleiConfig{
		Targets:         config.Targets,
		TemplatePaths:   templatePaths,
		RunMode:         nuclei.NucleiRunModeScan,
		Timeout:         config.Timeout,
		Threads:         config.Threads,
		Proxy:           config.Proxy,
		VerboseLogs:     config.VerboseLogs,
		GlobalRateLimit: config.GlobalRateLimit,
		GlobalTimeout:   config.GlobalTimeout,
	}, nil
}

// LaunchFingerprintEngine runs the fingerprinting engine for all targets in the config and returns a report.
func LaunchFingerprintEngine(ctx context.Context, config *discover.DiscoverApplicationConfig) (*discover.DiscoverApplicationReport, error) {
	log := svc1log.FromContext(ctx)
	report := discover.DiscoverApplicationReport{Config: config}

	log.Info("Starting application fingerprinting engine",
		svc1log.SafeParam("targets", config.Targets),
		svc1log.SafeParam("resourceType", config.ResourceType),
		svc1log.SafeParam("timeout", config.Timeout),
		svc1log.SafeParam("threads", config.Threads),
		svc1log.SafeParam("proxy", config.Proxy),
		svc1log.SafeParam("verboseLogs", config.VerboseLogs))

	// Create the nuclei config
	nucleiConfig, err := createDiscoverApplicationNucleiConfig(ctx, config)
	if err != nil {
		log.Error("Failed to create Nuclei config", svc1log.SafeParam("error", err.Error()))
		return &report, err
	}

	log.Info("Running Nuclei engine for application discovery")
	// Run the nuclei engine
	nucleiReport, err := nucleiutils.RunNucleiEngine(ctx, nucleiConfig)
	if err != nil {
		log.Error("Nuclei engine execution failed", svc1log.SafeParam("error", err.Error()))
		return &report, err
	}

	// Process the nuclei results and convert to application fingerprint format
	targets := []*discover.ApplicationFingerprintTarget{}
	errors := []string{}

	for _, nucleiTarget := range nucleiReport {
		// Only process targets that have successful findings from Nuclei
		if len(nucleiTarget.Attempts) == 0 {
			continue
		}

		// Create application fingerprint target
		fingerprintTarget := &discover.ApplicationFingerprintTarget{
			Target:   nucleiTarget.Target,
			Attempts: []*discover.ApplicationFingerprintAttempt{},
		}

		// Track seen template IDs to avoid duplicates
		seenTemplateIds := make(map[string]bool)

		// Process each nuclei attempt (these are already successful matches from Nuclei)
		for _, nucleiAttempt := range nucleiTarget.Attempts {
			// Only process attempts that have actual findings and haven't been seen before
			if nucleiAttempt.Finding != nil && !seenTemplateIds[nucleiAttempt.TemplateId] {
				// Mark this template as seen
				seenTemplateIds[nucleiAttempt.TemplateId] = true

				// Convert nuclei attempt to application fingerprint attempt
				attempt := convertNucleiAttemptToFingerprintAttemptStruct(log, nucleiAttempt)
				if attempt != nil {
					fingerprintTarget.Attempts = append(fingerprintTarget.Attempts, attempt)
				}
			}
		}

		// Only include targets with successful findings
		if len(fingerprintTarget.Attempts) > 0 {
			targets = append(targets, fingerprintTarget)
		}
	}

	// Marshal Report
	report.Result = &discover.DiscoverApplicationResult{Targets: targets}
	report.Errors = errors
	return &report, nil
}
