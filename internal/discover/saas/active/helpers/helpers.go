package saas

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Method-Security/webscan/configs"
	discover "github.com/Method-Security/webscan/generated/go/discover"
)

// FilterFingerprints enables the user to only look for specific SaaS companies or SSO login pages
func FilterFingerprints(companies []string, fingerprints discover.SaasFingerprintFile) (*discover.SaasFingerprintFile, error) {
	if len(companies) == 0 {
		return &fingerprints, nil
	}

	filteredFingerprints := make(map[string]*discover.SaasFingerprintEntry)
	for _, company := range companies {
		if entry, exists := fingerprints.Fingerprints[company]; exists {
			filteredFingerprints[company] = entry
		} else {
			return nil, fmt.Errorf("company %s not found in fingerprints", company)
		}
	}
	return &discover.SaasFingerprintFile{Fingerprints: filteredFingerprints}, nil
}

// embeddedSaasFiles maps known container paths to their embedded config paths.
var embeddedSaasFiles = map[string]string{
	"/opt/method/webscan/var/conf/discover/saas/saas_fingerprints.json": "discover/saas/saas_fingerprints.json",
	"/opt/method/webscan/var/conf/discover/saas/sso_fingerprints.json":  "discover/saas/sso_fingerprints.json",
}

// UnmarshalFingerprints unmarshals the fingerprint files into a SaasFingerprintFile.
// Tries the filesystem first, then falls back to embedded configs for known default paths.
func UnmarshalFingerprints(fingerprintFiles []string) discover.SaasFingerprintFile {
	result := discover.SaasFingerprintFile{
		Fingerprints: make(map[string]*discover.SaasFingerprintEntry),
	}
	for _, file := range fingerprintFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			// Fall back to embedded config for known default paths
			if embeddedPath, ok := embeddedSaasFiles[file]; ok {
				data, err = configs.ReadFile(embeddedPath)
				if err != nil {
					continue
				}
			} else {
				continue
			}
		}
		var fingerprints discover.SaasFingerprintFile
		if err := json.Unmarshal(data, &fingerprints); err != nil {
			continue
		}
		for k, v := range fingerprints.Fingerprints {
			result.Fingerprints[k] = v
		}
	}

	return result
}

// ShouldAddRequest determines if a request should be included in results based on its findings and the successfulOnly flag
func ShouldAddRequest(request *discover.SaasActiveRequest) bool {
	if request == nil {
		return false
	}

	if request.Findings == nil {
		return false
	}

	hasCompanyPage := request.Findings.CompanyPage != nil && *request.Findings.CompanyPage
	hasSsoPage := request.Findings.SsoPage != nil

	return hasCompanyPage || hasSsoPage
}
