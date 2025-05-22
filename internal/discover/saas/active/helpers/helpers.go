package saas

import (
	"encoding/json"
	"fmt"
	"os"

	discoversaasfern "github.com/Method-Security/webscan/generated/go/discover/saas"
)

// FilterFingerprints enables the user to only look for specific SaaS companies or SSO login pages
func FilterFingerprints(companies []string, fingerprints discoversaasfern.SaasFingerprintFile) (*discoversaasfern.SaasFingerprintFile, error) {
	if len(companies) == 0 {
		return &fingerprints, nil
	}

	filteredFingerprints := make(map[string]*discoversaasfern.SaasFingerprintEntry)
	for _, company := range companies {
		if entry, exists := fingerprints.Fingerprints[company]; exists {
			filteredFingerprints[company] = entry
		} else {
			return nil, fmt.Errorf("company %s not found in fingerprints", company)
		}
	}
	return &discoversaasfern.SaasFingerprintFile{Fingerprints: filteredFingerprints}, nil
}

// UnmarshalFingerprints unmarshals the fingerprint files into a SaasFingerprintFile
func UnmarshalFingerprints(fingerprintFiles []string) discoversaasfern.SaasFingerprintFile {
	result := discoversaasfern.SaasFingerprintFile{
		Fingerprints: make(map[string]*discoversaasfern.SaasFingerprintEntry),
	}
	// Read and unmarshal each fingerprint file
	for _, file := range fingerprintFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		var fingerprints discoversaasfern.SaasFingerprintFile
		if err := json.Unmarshal(data, &fingerprints); err != nil {
			continue
		}
		// Merge fingerprints from this file into result
		for k, v := range fingerprints.Fingerprints {
			result.Fingerprints[k] = v
		}
	}

	return result
}

// ShouldAddRequest determines if a request should be included in results based on its findings and the successfulOnly flag
func ShouldAddRequest(request *discoversaasfern.SaasActiveRequest, successfulOnly bool) bool {
	if request == nil {
		return false
	}

	if request.Findings == nil {
		return !successfulOnly
	}

	hasCompanyPage := request.Findings.CompanyPage != nil && *request.Findings.CompanyPage
	hasSsoPage := request.Findings.SsoPage != nil

	return hasCompanyPage || hasSsoPage || !successfulOnly
}
