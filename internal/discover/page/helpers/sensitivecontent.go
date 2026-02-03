package discoverpage

import (
	"context"
	"encoding/json"
	"os"
	"regexp"

	// Generated
	"github.com/Method-Security/webscan/generated/go/discover"
	//External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// LoadSensitiveContextFingerprints loads fingerprints from the JSON configuration file
func LoadSensitiveContextFingerprints(ctx context.Context, configPath *string) (*discover.SensitiveContextFingerprints, error) {
	log := svc1log.FromContext(ctx)

	// Read the JSON file
	data, err := os.ReadFile(*configPath)
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON directly into Fern-generated type
	var fingerprints discover.SensitiveContextFingerprints
	if err := json.Unmarshal(data, &fingerprints); err != nil {
		return nil, err
	}

	log.Info("Loaded sensitive context fingerprints", svc1log.SafeParam("fingerprint count", len(fingerprints.Fingerprints)))

	return &fingerprints, nil
}

// ExtractSensitiveContextsFromWebContent searches for sensitive contexts in web content
func ExtractSensitiveContextsFromWebContent(ctx context.Context, content string, fingerprints *discover.SensitiveContextFingerprints) ([]*discover.SensitiveContext, []string) {
	log := svc1log.FromContext(ctx)

	var sensitiveContextValues []*discover.SensitiveContext
	var errors []string
	seen := make(map[string]bool) // Track unique credential values

	// Load fingerprints from JSON file
	for _, fingerprint := range fingerprints.Fingerprints {
		// Compile the pattern string into a regex
		compiledPattern, err := regexp.Compile(fingerprint.Pattern)
		if err != nil {
			log.Error("Failed to compile pattern", svc1log.SafeParam("error", err))
			errors = append(errors, err.Error())
			continue // Skip invalid patterns
		}

		matches := compiledPattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) > 1 && match[1] != "" {
				value := match[1]

				// Skip if we've already seen this credential value
				if seen[value] {
					log.Info("Skipping duplicate token", svc1log.SafeParam("type", fingerprint.Type))
					continue
				}

				log.Info("Found token", svc1log.SafeParam("type", fingerprint.Type))
				seen[value] = true

				sensitiveContext := discover.SensitiveContext{
					Value:       value,
					Fingerprint: fingerprint,
				}

				sensitiveContextValues = append(sensitiveContextValues, &sensitiveContext)
			}
		}
	}

	return sensitiveContextValues, errors
}
