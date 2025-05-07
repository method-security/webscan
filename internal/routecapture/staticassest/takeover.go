package routecapture

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Method-Security/webscan/generated/go/common"
	routecapturefern "github.com/Method-Security/webscan/generated/go/routecapture"
	"github.com/Method-Security/webscan/internal/routecapture"
	"github.com/Method-Security/webscan/utils"
	"github.com/Method-Security/webscan/utils/headless/browserbase"
)

func PerformStaticAssetTakeOverAnalysis(ctx context.Context, target string, captureMethod common.CaptureMethod, baseURLsOnly bool, timeout int, minDOMStabalizeTime int, insecure bool, browserPath *string, browserBaseToken *string, browserBaseProject *string, browserBaseOptions *[]browserbase.Option, successfulOnly bool, fingerprints []routecapturefern.StaticAssetTakeOverFingerprint) routecapturefern.StaticAssetTakeOverReport {
	report := routecapturefern.StaticAssetTakeOverReport{
		Target: target,
	}
	errors := []string{}

	routeCaptureReport := routecapture.PerformRouteCapture(ctx, target, captureMethod, baseURLsOnly, true, timeout, minDOMStabalizeTime, insecure, browserPath, browserBaseToken, browserBaseProject, browserBaseOptions)
	if len(routeCaptureReport.Urls) == 0 {
		errors = append(errors, "no urls found")
		report.Errors = errors
		return report
	}

	// Target Request Data
	targetBaseURL, targetPath, err := utils.SplitTarget(target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("error splitting target: %s", err))
		report.Errors = errors
		return report
	}
	targetRequest := utils.PerformRequestScan(targetBaseURL, targetPath, common.HttpMethodGet, common.RequestParams{}, timeout, true)
	report.TargetRequest = &targetRequest

	// Static Asset Take Over Attempts
	StaticAssetTakeOverAttempts := []*routecapturefern.StaticAssetTakeOverAttempt{}
	for _, url := range routeCaptureReport.Urls {
		if !routecapture.IsStaticAsset(url) {
			continue
		}
		StaticAssetTakeOverAttempt := routecapturefern.StaticAssetTakeOverAttempt{StaticAsset: url}

		// Perform Request
		staticAssetBaseURL, staticAssetPath, err := utils.SplitTarget(url)
		if err != nil {
			errors = append(errors, fmt.Sprintf("error splitting target: %s", err))
			continue
		}

		request := utils.PerformRequestScan(staticAssetBaseURL, staticAssetPath, common.HttpMethodGet, common.RequestParams{}, timeout, true)
		StaticAssetTakeOverAttempt.Request = &request

		// Check if the request is vulnerable
		info := isStaticAssetTakeOver(&request, fingerprints, successfulOnly)
		if len(info) > 0 {
			StaticAssetTakeOverAttempt.Fingerprints = info
			StaticAssetTakeOverAttempts = append(StaticAssetTakeOverAttempts, &StaticAssetTakeOverAttempt)
		}
	}

	report.Attempts = StaticAssetTakeOverAttempts
	report.Errors = errors
	return report
}

// isStaticAssetTakeOver checks if the request is vulnerable to static asset take over
func isStaticAssetTakeOver(request *common.RequestInfo, fingerprints []routecapturefern.StaticAssetTakeOverFingerprint, successfulOnly bool) []*routecapturefern.StaticAssetTakeOverVulnerableInfo {
	info := []*routecapturefern.StaticAssetTakeOverVulnerableInfo{}

	successfulFingerprint := false
	for _, fingerprint := range fingerprints {
		instance := routecapturefern.StaticAssetTakeOverVulnerableInfo{
			Fingerprint: &fingerprint,
			Vulnerable:  false,
		}

		// If the request doesn't have a status code or response body, since the asset doesnt exist
		if request.StatusCode == nil || request.ResponseBody == nil {
			info = append(info, &instance)
			continue
		}

		// Does the status code and response body of the request match the fingerprint
		for _, responseBody := range fingerprint.ResponseBody {
			// Convert the response body to lowercase to make the comparison case insensitive
			lowerBody := strings.ToLower(responseBody)
			lowerRequestBody := strings.ToLower(*request.ResponseBody)
			if *request.StatusCode == fingerprint.StatusCode && strings.Contains(lowerRequestBody, lowerBody) {
				successfulFingerprint = true
				instance.Vulnerable = true
				break
			}
		}

		if instance.Vulnerable || !successfulOnly {
			info = append(info, &instance)
		}
	}

	// If no fingerprint was found but the asset returned a 404, an issue should still be reported
	if !successfulFingerprint && *request.StatusCode == 404 {
		instance := routecapturefern.StaticAssetTakeOverVulnerableInfo{
			Fingerprint: &routecapturefern.StaticAssetTakeOverFingerprint{
				Name:         "Service Unknown",
				Description:  "Service did not match any fingerprint but the asset returned a 404",
				ResponseBody: []string{"N/A"},
				StatusCode:   404,
			},
		}
		instance.Vulnerable = true
		info = append(info, &instance)
	}

	return info
}

// GrabStaticAssetTakeOverFingerprints grabs the fingerprints from the given file paths
func GrabStaticAssetTakeOverFingerprints(fingerprintFilePaths []string) []routecapturefern.StaticAssetTakeOverFingerprint {
	fingerprints := []routecapturefern.StaticAssetTakeOverFingerprint{}

	for _, path := range fingerprintFilePaths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			continue
		}
		file, err := os.Open(absPath)
		if err != nil {
			continue
		}

		// Read the entire file
		data, err := io.ReadAll(file)
		if err != nil {
			continue
		}

		var config struct {
			Fingerprints []routecapturefern.StaticAssetTakeOverFingerprint
		}

		if err := json.Unmarshal(data, &config); err != nil {
			continue
		}

		err = file.Close()
		if err != nil {
			continue
		}

		fingerprints = append(fingerprints, config.Fingerprints...)
	}

	return fingerprints
}
