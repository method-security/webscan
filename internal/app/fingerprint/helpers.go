package fingerprint

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"

	webscan "github.com/Method-Security/webscan/generated/go/app"
)

// LoadFingerprints loads and unmarshals the fingerprints.json file into the generated AppFingerprints struct
func LoadFingerprints(filePath string) (*webscan.AppFingerprints, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config webscan.AppFingerprints
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// FilterFingerprints filters the fingerprints based on resource types and modules
// Returns error if resource type or module doesn't exist
func FilterFingerprints(fingerprints *webscan.AppFingerprints, resourceType string, modules []string) (*webscan.AppFingerprints, error) {
	// Convert string to AppFingerprintResourceType
	rt, err := webscan.NewAppFingerprintResourceTypeFromString(resourceType)
	if err != nil {
		return nil, fmt.Errorf("invalid resource type: %s", resourceType)
	}

	// Find the resource type
	var foundResourceType *webscan.AppResourceType
	for _, r := range fingerprints.ResourcetTypes {
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
		return &webscan.AppFingerprints{
			ResourcetTypes: []*webscan.AppResourceType{foundResourceType},
		}, nil
	}

	// Find the module
	var foundModules []*webscan.AppResourceModule
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
	return &webscan.AppFingerprints{
		ResourcetTypes: []*webscan.AppResourceType{foundResourceType},
	}, nil
}

// GetModule returns the module configuration for a given resource type and module
func GetModule(resourceType webscan.AppFingerprintResourceType, module string, fingerprints *webscan.AppFingerprints) (*webscan.AppResourceModule, error) {
	// Check if resource type exists
	var foundResourceType bool
	for _, rt := range fingerprints.ResourcetTypes {
		if rt.Name == resourceType {
			foundResourceType = true
			// Check if module exists
			for _, m := range rt.Modules {
				if m.Name == module {
					return m, nil
				}
			}
			return nil, fmt.Errorf("module %s not found for resource type %s", module, resourceType)
		}
	}
	if !foundResourceType {
		return nil, fmt.Errorf("resource type %s not found", resourceType)
	}
	return nil, nil
}
