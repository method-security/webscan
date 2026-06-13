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

// Template-author metadata key contract (SEC-702.A).
//
// Templates emit values via `info.metadata.<key>:` blocks. Static
// values flow through verbatim; "lookup" keys trigger a helper call
// in this file. Per-cluster PRs are free to add more keys, but these
// are the seed contract:
//
//	method-architecture-value         — literal arch string (free-form,
//	                                    Linux/Go convention)
//	method-architecture-source        — one of DEVICE_DISCLOSED,
//	                                    MODEL_LOOKUP,
//	                                    INFERRED_FROM_FIRMWARE_URL,
//	                                    INFERRED_FROM_REALM
//	method-architecture-confidence    — float string in [0.0, 1.0]
//	                                    (optional; default 0.0)
//	method-arch-lookup-vendor         — vendor key for arch-lookup table
//	                                    (only used if method-architecture-
//	                                    value is unset)
//	method-arch-lookup-model          — model key for arch-lookup table
//	method-device-mac                 — raw MAC; engine normalizes to
//	                                    canonical AA:BB:CC:DD:EE:FF
//	method-device-serial              — verbatim serial (preserved as-is)
//	method-mikrotik-asset-hash        — RouterOS 7.17+ asset content
//	                                    hash; engine resolves to version
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

// convertNucleiAttemptToFingerprintAttemptStruct converts a Nuclei attempt to an application fingerprint attempt
func convertNucleiAttemptToFingerprintAttemptStruct(nucleiAttempt *nuclei.NucleiAttemptInfo) *discover.ApplicationFingerprintAttempt {
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

	// Parse metadata from the Nuclei finding if available
	if nucleiAttempt.Finding != nil && nucleiAttempt.Finding.Metadata != nil {
		md := nucleiAttempt.Finding.Metadata

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

		// SEC-702.A — derive architecture from metadata.
		architectureFromMetadata = deriveArchitecture(md)

		// SEC-702.A — device MAC: normalize to canonical form before
		// publishing. NormalizeMac fails-closed on inputs that don't
		// contain a full 48-bit MAC, so a garbage extractor result
		// produces no deviceMac (rather than a half-formed one).
		if rawMac, exists := md[metaDeviceMac]; exists {
			if canonical := NormalizeMac(rawMac); canonical != "" {
				deviceMacFromMetadata = &canonical
			}
		}

		// SEC-702.A — device serial: verbatim. The catalog warns that
		// some devices (Dahua 2019+) emit a 32-char hex realm that
		// LOOKS like a serial but is actually a hash; templates must
		// length-bound their extractors. The engine trusts the
		// template's extractor here — it does not re-validate.
		if rawSerial, exists := md[metaDeviceSerial]; exists {
			trimmed := strings.TrimSpace(rawSerial)
			if trimmed != "" {
				deviceSerialFromMetadata = &trimmed
			}
		}

		// SEC-702.A — MikroTik 7.17+ asset-hash → version dereference.
		// If the template provided a CPE template containing the
		// literal placeholder "{version}" AND the asset-hash hits a
		// known RouterOS release, substitute. Otherwise leave the CPE
		// untouched. This keeps the asset-hash helper useful even
		// when the schema has no dedicated version field.
		if hash, exists := md[metaMikrotikAssetHash]; exists && hash != "" {
			if version, ok := lookupMikrotikAssetHash(hash); ok && cpeFromMetadata != nil {
				substituted := strings.ReplaceAll(*cpeFromMetadata, "{version}", version)
				cpeFromMetadata = &substituted
			}
		}
	}

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

// deriveArchitecture builds an ArchitectureInfo from template metadata,
// or returns nil when no source applies. Two paths:
//
//  1. Template emits method-architecture-value directly. method-
//     architecture-source MUST also be set (parseable as an
//     ArchitectureSource enum) for the result to be admitted —
//     unsourced architecture values are dropped to keep the
//     provenance contract honest. confidence defaults to 0.0 when
//     method-architecture-confidence is absent or unparseable.
//
//  2. Template emits method-arch-lookup-vendor + method-arch-lookup-
//     model AND method-architecture-value is unset. The engine calls
//     lookupArchitecture and on a hit emits source=MODEL_LOOKUP with
//     confidence=archLookupConfidence (catalog-defined 0.75 midpoint
//     of the MODEL_LOOKUP 0.6–0.85 range).
//
// Returns nil for both no-direct-value/no-lookup-hit AND
// direct-value-without-source — never guesses.
func deriveArchitecture(md map[string]string) *discover.ArchitectureInfo {
	if archValue, ok := md[metaArchitectureValue]; ok && archValue != "" {
		archSrcStr, hasSrc := md[metaArchitectureSource]
		if !hasSrc {
			return nil
		}
		archSrc, err := discover.NewArchitectureSourceFromString(archSrcStr)
		if err != nil {
			return nil
		}
		confidence := 0.0
		if confStr, hasConf := md[metaArchitectureConfidence]; hasConf {
			if parsed, parseErr := strconv.ParseFloat(strings.TrimSpace(confStr), 64); parseErr == nil {
				confidence = clampConfidence(parsed)
			}
		}
		return &discover.ArchitectureInfo{
			Value:      archValue,
			Source:     archSrc,
			Confidence: confidence,
		}
	}

	// Path 2: (vendor, model) → arch lookup.
	vendor, hasVendor := md[metaArchLookupVendor]
	model, hasModel := md[metaArchLookupModel]
	if !hasVendor || !hasModel || vendor == "" || model == "" {
		return nil
	}
	arch, hit := lookupArchitecture(vendor, model)
	if !hit {
		// Empty table at SEC-702.A seed-time; no hit is the expected
		// path until Cluster C / E / F / P populate the table.
		return nil
	}
	// Allow templates to override the helper's default confidence.
	confidence := archLookupConfidence
	if confStr, hasConf := md[metaArchitectureConfidence]; hasConf {
		if parsed, parseErr := strconv.ParseFloat(strings.TrimSpace(confStr), 64); parseErr == nil {
			confidence = clampConfidence(parsed)
		}
	}
	return &discover.ArchitectureInfo{
		Value:      arch,
		Source:     discover.ArchitectureSourceModelLookup,
		Confidence: confidence,
	}
}

// clampConfidence pins a confidence value to [0.0, 1.0]. The Fern
// schema doesn't constrain the range, so the engine enforces it
// here to keep downstream consumers (and the confidence rubric in
// the SEC-702 catalog) honest.
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
				attempt := convertNucleiAttemptToFingerprintAttemptStruct(nucleiAttempt)
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
