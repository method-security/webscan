package application

import (
	// Standard
	"fmt"
	// Generated
	"github.com/Method-Security/webscan/generated/go/discover"
)

// getTemplatePaths creates template paths for Nuclei scanning based on resource type
// This replaces the old fingerprints.json approach with direct template path selection
func getTemplatePaths(resourceConfigType *discover.ApplicationResourceConfigType) ([]string, error) {
	// Get all supported resource types
	supportedResourceTypes := []discover.ApplicationResourceType{
		discover.ApplicationResourceTypeApiApplication,
		discover.ApplicationResourceTypeCiCdPlatform,
		discover.ApplicationResourceTypeCloudBucket,
		discover.ApplicationResourceTypeContentManagementSystem,
		discover.ApplicationResourceTypeHypervisor,
		discover.ApplicationResourceTypeKube,
		discover.ApplicationResourceTypeVdiApplication,
		discover.ApplicationResourceTypeVirtualCompute,
		discover.ApplicationResourceTypeWebServer,
	}

	// Map resource types to base template paths (without request method subdirectory)
	resourceTypeToPath := map[discover.ApplicationResourceType]string{
		discover.ApplicationResourceTypeApiApplication:          "apiapplication",
		discover.ApplicationResourceTypeCiCdPlatform:            "cicd",
		discover.ApplicationResourceTypeCloudBucket:             "cloud",
		discover.ApplicationResourceTypeContentManagementSystem: "cms",
		discover.ApplicationResourceTypeHypervisor:              "hypervisor",
		discover.ApplicationResourceTypeKube:                    "kube",
		discover.ApplicationResourceTypeVdiApplication:          "vdiapplication",
		discover.ApplicationResourceTypeVirtualCompute: "virutalcompute",
		discover.ApplicationResourceTypeWebServer:               "webserver",
	}

	var templatePaths []string

	// Handle 'ALL' resource type - return all template paths
	if resourceConfigType.GetApplicationResourceTypeAll() == discover.ApplicationResourceTypeAllAll {
		// Add all resource type template paths for each request method
		for _, resourceType := range supportedResourceTypes {
			if resourceTypeName, exists := resourceTypeToPath[resourceType]; exists {
				templatePath := fmt.Sprintf("discover/application/%s", resourceTypeName)
				templatePaths = append(templatePaths, templatePath)
			}
		}
		return templatePaths, nil
	}

	// Handle specific resource type
	resourceType := resourceConfigType.GetApplicationResourceType()

	// Validate that the resource type is supported
	resourceTypeName, exists := resourceTypeToPath[resourceType]
	if !exists {
		return nil, fmt.Errorf("resource type %v is not supported", resourceType)
	}

	templatePath := fmt.Sprintf("discover/application/%s", resourceTypeName)
	templatePaths = append(templatePaths, templatePath)

	return templatePaths, nil
}
