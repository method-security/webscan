package application

import (
	// Standard
	"encoding/json"
	"fmt"
	"os"
	"slices"

	"github.com/Method-Security/webscan/generated/go/discover"
	// Generated
)

// LoadFingerprints loads and unmarshals the fingerprints.json file into the generated AppFingerprints struct
func LoadFingerprints(filePath string) (*discover.ApplicationFingerprints, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config discover.ApplicationFingerprints
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// FilterFingerprints filters the fingerprints based on resource types and modules
// Returns error if resource type or module doesn't exist
// If resourceType is 'ALL', it returns all resource types combined into a single resource
func FilterFingerprints(fingerprints *discover.ApplicationFingerprints, resourceConfigType *discover.ApplicationResourceConfigType, modules []string) (*discover.ApplicationResource, error) {
	// Handle 'ALL' resource type - combine all resource types
	if resourceConfigType.GetApplicationResourceTypeAll() == discover.ApplicationResourceTypeAllAll {
		allModules := []*discover.ApplicationFingerprintModule{}

		// Collect all modules from all resource types
		for _, rt := range fingerprints.Fingerprints {
			// If specific modules are requested, filter them
			if len(modules) > 0 {
				for _, m := range rt.Modules {
					if slices.Contains(modules, m.Name) {
						allModules = append(allModules, m)
					}
				}
			} else {
				// No specific modules requested, add all modules from this resource type
				allModules = append(allModules, rt.Modules...)
			}
		}

		if len(allModules) == 0 {
			if len(modules) > 0 {
				return nil, fmt.Errorf("none of the specified modules %v were found", modules)
			}
			return nil, fmt.Errorf("no modules found for resource type ALL")
		}

		// Return a combined resource with all modules
		return &discover.ApplicationResource{
			Name:    resourceConfigType,
			Modules: allModules,
		}, nil
	}

	resourceTypeEnum, err := discover.NewApplicationResourceTypeFromString(string(resourceConfigType.GetApplicationResourceType()))
	if err != nil {
		return nil, fmt.Errorf("invalid resource type: %s", resourceConfigType)
	}

	// Handle specific resource type (existing logic)
	var foundResourceType *discover.ApplicationResource
	for _, rt := range fingerprints.Fingerprints {
		if rt.Name.GetApplicationResourceType() == resourceTypeEnum {
			foundResourceType = rt
			break
		}
	}
	if foundResourceType == nil {
		return nil, fmt.Errorf("resource type %s not found", resourceConfigType)
	}

	// If no module specified, return all modules for this type
	if len(modules) == 0 {
		return foundResourceType, nil
	}

	// Find the specific modules
	var foundModules []*discover.ApplicationFingerprintModule
	for _, m := range foundResourceType.Modules {
		if slices.Contains(modules, m.Name) {
			foundModules = append(foundModules, m)
		}
	}
	if len(foundModules) == 0 {
		return nil, fmt.Errorf("modules %v not found for resource type %s", modules, resourceConfigType)
	}

	// Return filtered config with just the requested modules
	return &discover.ApplicationResource{
		Name:    foundResourceType.Name,
		Modules: foundModules,
	}, nil
}

// GetModule returns the module configuration for a given resource type and module
func GetModule(resourceType discover.ApplicationResourceType, module string, fingerprints *discover.ApplicationFingerprints) (*discover.ApplicationFingerprintModule, error) {
	// Check if resource type exists
	for _, rt := range fingerprints.Fingerprints {
		if rt.Name.GetApplicationResourceType() == resourceType {
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
