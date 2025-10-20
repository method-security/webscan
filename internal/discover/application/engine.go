package application

import (
	// Standard
	"context"
	"strings"

	// Generated
	nuclei "github.com/Method-Security/webscan/generated/go/common/nuclei"
	"github.com/Method-Security/webscan/generated/go/discover"

	// Utils
	nucleiutils "github.com/Method-Security/webscan/utils/nuclei"
	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// convertNucleiAttemptToFingerprintAttemptStruct converts a Nuclei attempt to an application fingerprint attempt
func convertNucleiAttemptToFingerprintAttemptStruct(nucleiAttempt *nuclei.NucleiAttemptInfo) *discover.ApplicationFingerprintAttempt {
	if nucleiAttempt == nil || nucleiAttempt.TemplateId == "" {
		return nil
	}

	// Extract resource type and module from template metadata
	var resourceTypeMetadata discover.ApplicationResourceType
	var moduleNameFromMetadata string

	// Parse metadata from the Nuclei finding if available
	if nucleiAttempt.Finding != nil && nucleiAttempt.Finding.Metadata != nil {
		// Check for method-application-type in metadata
		if appTypeStr, exists := nucleiAttempt.Finding.Metadata["method-application-type"]; exists {
			if appType, err := discover.NewApplicationResourceTypeFromString(appTypeStr); err == nil {
				resourceTypeMetadata = appType
			}
		}

		// Check for method-module-name in metadata
		if moduleStr, exists := nucleiAttempt.Finding.Metadata["method-module-name"]; exists {
			moduleNameFromMetadata = strings.ToUpper(moduleStr)
		}
	}

	// Create the simplified fingerprint attempt using the new Fern structure
	attempt := &discover.ApplicationFingerprintAttempt{
		ResourceType: resourceTypeMetadata,
		Module:       moduleNameFromMetadata,
		Finding:      true,
		Request:      nucleiAttempt.HttpRequestResponse,
	}

	return attempt
}

// createDiscoverApplicationNucleiConfig builds the Nuclei config for application discovery
func createDiscoverApplicationNucleiConfig(ctx context.Context, config *discover.DiscoverApplicationConfig) (nuclei.NucleiConfig, error) {
	log := svc1log.FromContext(ctx)

	// Get template paths based on resource type, modules, and request methods
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
		Targets:       config.Targets,
		TemplatePaths: templatePaths,
		RunMode:       nuclei.NucleiRunModeScan,
		Timeout:       config.Timeout,
		Threads:       config.Threads,
		Proxy:         config.Proxy,
		VerboseLogs:   config.VerboseLogs,
	}, nil
}

// LaunchFingerprintEngine runs the fingerprinting engine for all targets in the config and returns a report.
func LaunchFingerprintEngine(ctx context.Context, config *discover.DiscoverApplicationConfig) (*discover.DiscoverApplicationReport, error) {
	log := svc1log.FromContext(ctx)
	report := discover.DiscoverApplicationReport{Config: config}

	log.Info("Starting application fingerprinting engine",
		svc1log.SafeParam("targets", config.Targets),
		svc1log.SafeParam("resourceType", config.ResourceType),
		svc1log.SafeParam("modules", config.Modules))

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
