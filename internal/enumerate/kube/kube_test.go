package kube

import (
	"testing"

	enumeratekubefern "github.com/Method-Security/webscan/generated/go/enumerate/kube"
)

// TestPathClassification asserts that the sensitivity labels in commonKubepaths are correct
// for a representative set of SENSITIVE and STANDARD endpoints.
func TestPathClassification(t *testing.T) {
	// Build a lookup map from path to sensitivity.
	pathMap := make(map[string]enumeratekubefern.KubeEndpointSensitivity, len(commonKubepaths))
	for _, spec := range commonKubepaths {
		pathMap[spec.path] = spec.sensitivity
	}

	// SENSITIVE assertions
	sensitivePaths := []string{
		"/api/v1/secrets",
		"/api/v1/configmaps",
		"/api/v1/nodes",
		"/api/v1/pods",
		"/api/v1/services",
		"/api/v1/namespaces",
		"/apis/apps/v1/deployments",
		"/apis/networking.k8s.io/v1/ingresses",
		"/api/v1/persistentvolumes",
		"/metrics",
	}
	for _, p := range sensitivePaths {
		got, ok := pathMap[p]
		if !ok {
			t.Errorf("path %q not found in commonKubepaths", p)
			continue
		}
		if got != enumeratekubefern.KubeEndpointSensitivitySensitive {
			t.Errorf("path %q: want SENSITIVE, got %v", p, got)
		}
	}

	// STANDARD assertions
	standardPaths := []string{
		"/",
		"/api",
		"/api/v1",
		"/apis",
		"/version",
		"/healthz",
		"/livez",
		"/readyz",
		"/openapi/v2",
	}
	for _, p := range standardPaths {
		got, ok := pathMap[p]
		if !ok {
			t.Errorf("path %q not found in commonKubepaths", p)
			continue
		}
		if got != enumeratekubefern.KubeEndpointSensitivityStandard {
			t.Errorf("path %q: want STANDARD, got %v", p, got)
		}
	}

	// Spot-check: total path count should be 19
	if len(commonKubepaths) != 19 {
		t.Errorf("expected 19 paths in commonKubepaths, got %d", len(commonKubepaths))
	}
}
