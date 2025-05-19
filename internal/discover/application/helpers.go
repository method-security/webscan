package application

import (
	// Standard
	"encoding/json"
	"fmt"
	"os"
	"slices"

	// Generated
	discoverfern "github.com/Method-Security/webscan/generated/go/discover"
)

// LoadFingerprints loads and unmarshals the fingerprints.json file into the generated AppFingerprints struct
func LoadFingerprints(filePath string) (*discoverfern.ApplicationFingerprints, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config discoverfern.ApplicationFingerprints
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// FilterFingerprints filters the fingerprints based on resource types and modules
// Returns error if resource type or module doesn't exist
func FilterFingerprints(fingerprints *discoverfern.ApplicationFingerprints, resourceType string, modules []string) (*discoverfern.ApplicationFingerprintResource, error) {
	// Convert string to AppFingerprintResourceType
	resourceTypeEnum, err := discoverfern.NewApplicationFingerprintResourceTypeFromString(resourceType)
	if err != nil {
		return nil, fmt.Errorf("invalid resource type: %s", resourceType)
	}

	// Find the resource type
	var foundResourceType *discoverfern.ApplicationFingerprintResource
	for _, resourceType := range fingerprints.Fingerprints {
		if resourceType.Name == resourceTypeEnum {
			foundResourceType = resourceType
			break
		}
	}
	if foundResourceType == nil {
		return nil, fmt.Errorf("resource type %s not found", resourceType)
	}

	// If no module specified, return all modules for this type
	if len(modules) == 0 {
		return foundResourceType, nil
	}

	// Find the module
	var foundModules []*discoverfern.ApplicationFingerprintModule
	for _, m := range foundResourceType.Modules {
		if slices.Contains(modules, m.Name) {
			foundModules = append(foundModules, m)
		}
	}
	if len(foundModules) == 0 {
		return nil, fmt.Errorf("module %s not found for resource type %s", modules, resourceType)
	}

	// Return filtered config with just this module
	foundResourceType.Modules = foundModules
	return foundResourceType, nil
}

// GetModule returns the module configuration for a given resource type and module
func GetModule(resourceType discoverfern.ApplicationFingerprintResourceType, module string, fingerprints *discoverfern.ApplicationFingerprints) (*discoverfern.ApplicationFingerprintModule, error) {
	// Check if resource type exists
	for _, rt := range fingerprints.Fingerprints {
		if rt.Name == resourceType {
			// Check if module exists
			for _, m := range rt.Modules {
				if m.Name == module {
					return m, nil
				}
			}
			return nil, fmt.Errorf("module %s not found for resource type %s", module, resourceType)
		}
	}
	return nil, fmt.Errorf("resource type %s not found", resourceType)
}
