package fingerprint

import (
	// Standard
	"encoding/json"
	"fmt"
	"os"
	"slices"

	// Generated
	appFern "github.com/Method-Security/webscan/generated/go/app"
)

// LoadFingerprints loads and unmarshals the fingerprints.json file into the generated AppFingerprints struct
func LoadFingerprints(filePath string) (*appFern.AppFingerprints, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config appFern.AppFingerprints
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// FilterFingerprints filters the fingerprints based on resource types and modules
// Returns error if resource type or module doesn't exist
func FilterFingerprints(fingerprints *appFern.AppFingerprints, resourceType string, modules []string) (*appFern.AppResourceType, error) {
	// Convert string to AppFingerprintResourceType
	rt, err := appFern.NewAppFingerprintResourceTypeFromString(resourceType)
	if err != nil {
		return nil, fmt.Errorf("invalid resource type: %s", resourceType)
	}

	// Find the resource type
	var foundResourceType *appFern.AppResourceType
	for _, r := range fingerprints.ResourceTypes {
		if r.Name == rt {
			foundResourceType = r
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
	var foundModules []*appFern.AppResourceModule
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
func GetModule(resourceType appFern.AppFingerprintResourceType, module string, fingerprints *appFern.AppFingerprints) (*appFern.AppResourceModule, error) {
	// Check if resource type exists
	for _, rt := range fingerprints.ResourceTypes {
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
