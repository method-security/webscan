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
		discover.ApplicationResourceTypeCamera,
		discover.ApplicationResourceTypeCiCdPlatform,
		discover.ApplicationResourceTypeCloudBucket,
		discover.ApplicationResourceTypeCollaborationApplication,
		discover.ApplicationResourceTypeContainerRegistry,
		discover.ApplicationResourceTypeContentManagementSystem,
		discover.ApplicationResourceTypeDatabaseManagementApplication,
		discover.ApplicationResourceTypeDistributedComputingPlatform,
		discover.ApplicationResourceTypeFileTransferApplication,
		discover.ApplicationResourceTypeNetworkFirewall,
		discover.ApplicationResourceTypeHardwareManagementSystem,
		discover.ApplicationResourceTypeHypervisor,
		discover.ApplicationResourceTypeIndustrialControlSystem,
		discover.ApplicationResourceTypeInternetOfThings,
		discover.ApplicationResourceTypeIpPhone,
		discover.ApplicationResourceTypeKube,
		discover.ApplicationResourceTypeNetworkController,
		discover.ApplicationResourceTypeNetworkEdgeApplication,
		discover.ApplicationResourceTypeNetworkManagementSystem,
		discover.ApplicationResourceTypeOutOfBandApplication,
		discover.ApplicationResourceTypePrinter,
		discover.ApplicationResourceTypeRouter,
		discover.ApplicationResourceTypeSecretManagementApplication,
		discover.ApplicationResourceTypeVdiApplication,
		discover.ApplicationResourceTypeWebServer,
		discover.ApplicationResourceTypeObservabilityPlatform,
	}

	// Map resource types to base template paths (without request method subdirectory)
	resourceTypeToPath := map[discover.ApplicationResourceType]string{
		discover.ApplicationResourceTypeApiApplication:                "apiapplication",
		discover.ApplicationResourceTypeCamera:                        "internetofthings/camera",
		discover.ApplicationResourceTypeCiCdPlatform:                  "cicdplatform",
		discover.ApplicationResourceTypeCloudBucket:                   "cloudbucket",
		discover.ApplicationResourceTypeCollaborationApplication:      "collaborationapplication",
		discover.ApplicationResourceTypeContainerRegistry:             "containerregistry",
		discover.ApplicationResourceTypeContentManagementSystem:       "contentmanagementsystem",
		discover.ApplicationResourceTypeDatabaseManagementApplication: "databasemanagementapplication",
		discover.ApplicationResourceTypeDistributedComputingPlatform:  "distributedcomputingplatform",
		discover.ApplicationResourceTypeFileTransferApplication:       "filetransferapplication",
		discover.ApplicationResourceTypeNetworkFirewall:               "networkfirewall",
		discover.ApplicationResourceTypeHardwareManagementSystem:      "hardwaremanagementsystem",
		discover.ApplicationResourceTypeHypervisor:                    "hypervisor",
		discover.ApplicationResourceTypeIndustrialControlSystem:       "industrialcontrolsystem",
		discover.ApplicationResourceTypeInternetOfThings:              "internetofthings",
		discover.ApplicationResourceTypeIpPhone:                       "internetofthings/ipphone",
		discover.ApplicationResourceTypeKube:                          "kube",
		discover.ApplicationResourceTypeNetworkController:             "networkcontroller",
		discover.ApplicationResourceTypeNetworkEdgeApplication:        "networkedgeapplication",
		discover.ApplicationResourceTypeNetworkManagementSystem:       "networkmanagementsystem",
		discover.ApplicationResourceTypeOutOfBandApplication:          "outofbandapplication",
		discover.ApplicationResourceTypePrinter:                       "internetofthings/printer",
		discover.ApplicationResourceTypeRouter:                        "router",
		discover.ApplicationResourceTypeSecretManagementApplication:   "secretmanagementapplication",
		discover.ApplicationResourceTypeVdiApplication:                "vdiapplication",
		discover.ApplicationResourceTypeWebServer:                     "webserver",
		discover.ApplicationResourceTypeObservabilityPlatform:         "observabilityplatform",
	}

	var templatePaths []string

	// Handle 'ALL' resource type - return all template paths
	if resourceConfigType.GetApplicationResourceTypeAll() == discover.ApplicationResourceTypeAllAll {
		// The top-level IoT path is recursive, so it already includes camera,
		// IP phone, and printer templates. Skip those nested buckets here to
		// avoid duplicate template execution for ALL scans.
		for _, resourceType := range supportedResourceTypes {
			switch resourceType {
			case discover.ApplicationResourceTypeCamera,
				discover.ApplicationResourceTypeIpPhone,
				discover.ApplicationResourceTypePrinter:
				continue
			}
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
