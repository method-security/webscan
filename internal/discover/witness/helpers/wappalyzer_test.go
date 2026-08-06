package witnesshelpers

import (
	"testing"

	discover "github.com/Method-Security/webscan/generated/go/discover"
)

func TestFingerprintPreservesHeaderDetection(t *testing.T) {
	t.Parallel()

	technologies, err := Fingerprint(map[string][]string{
		"X-Powered-By": {"Express"},
	}, nil)
	if err != nil {
		t.Fatalf("Fingerprint returned error: %v", err)
	}

	technology := findTechnology(technologies.ServerSide, "EXPRESS")
	if technology == nil {
		t.Fatal("Express not found in server-side technologies")
	}
	if technology.TechnologyType != discover.DetectedTechnologyTypeWebFramework {
		t.Fatalf("Express technology type = %s, want %s", technology.TechnologyType, discover.DetectedTechnologyTypeWebFramework)
	}
}

func TestFingerprintDetectsRenderedAngularDOM(t *testing.T) {
	t.Parallel()

	technologies, err := Fingerprint(
		map[string][]string{"Content-Type": {"text/html"}},
		[]byte(`<html><body><app-root ng-version="21.2.17"></app-root></body></html>`),
	)
	if err != nil {
		t.Fatalf("Fingerprint returned error: %v", err)
	}

	technology := findTechnology(technologies.ClientSide, "ANGULAR")
	if technology == nil {
		t.Fatal("Angular not found in client-side technologies")
	}
	if technology.Version == nil || *technology.Version != "21.2.17" {
		t.Fatalf("Angular version = %v, want 21.2.17", technology.Version)
	}
	if technology.TechnologyType != discover.DetectedTechnologyTypeUiFramework {
		t.Fatalf("Angular technology type = %s, want %s", technology.TechnologyType, discover.DetectedTechnologyTypeUiFramework)
	}
}

func findTechnology(technologies []*discover.DetectedTechnology, name string) *discover.DetectedTechnology {
	for _, technology := range technologies {
		if technology.Name == name {
			return technology
		}
	}
	return nil
}
