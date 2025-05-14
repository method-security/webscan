package captureroute

import (
	// Standard
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	// Generated
	captureroutestaticassetfern "github.com/Method-Security/webscan/generated/go/capture/route/staticasset"
	common "github.com/Method-Security/webscan/generated/go/common"

	// Internal
	captureroute "github.com/Method-Security/webscan/internal/capture/route"
	// Utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
)

// createStaticAssetTakeOverRequestConfig creates a request config for seeing whats returned from a static asset
func createStaticAssetTakeOverRequestConfig(targetBaseURL, targetPath string, config captureroutestaticassetfern.StaticAssetTakeOverConfig, browserbaseSecrets *common.BrowserbaseSecrets) common.RequestConfig {
	requestConfig := common.RequestConfig{
		BaseUrl:            targetBaseURL,
		Path:               targetPath,
		Method:             common.HttpMethodGet,
		RequestParams:      &common.RequestParams{},
		Timeout:            config.CaptureRouteConfig.Timeout,
		Insecure:           config.CaptureRouteConfig.Insecure,
		FollowRedirects:    true,
		RequestMethod:      config.CaptureRouteConfig.RequestMethod,
		BrowserbaseConfig:  config.CaptureRouteConfig.BrowserbaseConfig,
		HeadlessConfig:     config.CaptureRouteConfig.HeadlessConfig,
		BrowserbaseSecrets: browserbaseSecrets,
	}

	return requestConfig
}

func PerformStaticAssetTakeOverAnalysis(ctx context.Context, config captureroutestaticassetfern.StaticAssetTakeOverConfig, browserbaseSecrets *common.BrowserbaseSecrets) captureroutestaticassetfern.StaticAssetTakeOverReport {
	// Create Report
	report := captureroutestaticassetfern.StaticAssetTakeOverReport{
		Target: config.CaptureRouteConfig.Target,
	}
	errors := []string{}

	// Perform Route Capture
	captureRouteReport := captureroute.PerformCaptureRoute(ctx, *config.CaptureRouteConfig, browserbaseSecrets)
	if len(captureRouteReport.Urls) == 0 {
		errors = append(errors, "no urls found")
		report.Errors = errors
		return report
	}

	// Split and standardize the target
	targetBaseURL, targetPath, err := utils.SplitTarget(config.CaptureRouteConfig.Target)
	if err != nil {
		errors = append(errors, fmt.Sprintf("error splitting target: %s", err))
		report.Errors = errors
		return report
	}

	// Send the request
	requestConfig := createStaticAssetTakeOverRequestConfig(targetBaseURL, targetPath, config, browserbaseSecrets)
	result, err := request.SendRequest(ctx, requestConfig)
	if err != nil {
		errors = append(errors, fmt.Sprintf("error performing request: %s", err))
		report.Errors = errors
		return report
	}
	report.TargetRequest = result

	// Static Asset Take Over Attempts
	StaticAssetTakeOverAttempts := []*captureroutestaticassetfern.StaticAssetTakeOverAttempt{}
	for _, url := range captureRouteReport.Urls {
		if !captureroute.IsStaticAsset(url) {
			continue
		}
		StaticAssetTakeOverAttempt := captureroutestaticassetfern.StaticAssetTakeOverAttempt{StaticAsset: url}

		// Perform Request
		staticAssetBaseURL, staticAssetPath, err := utils.SplitTarget(url)
		if err != nil {
			errors = append(errors, fmt.Sprintf("error splitting target: %s", err))
			continue
		}

		// Always send 'standard' requests as Browser is way to slow
		requestConfig := createStaticAssetTakeOverRequestConfig(staticAssetBaseURL, staticAssetPath, config, browserbaseSecrets)
		result, err := request.SendRequest(ctx, requestConfig)
		if err != nil {
			errors = append(errors, fmt.Sprintf("error performing request: %s", err))
			continue
		}
		StaticAssetTakeOverAttempt.Request = result

		// Check if the request is vulnerable
		info := isStaticAssetTakeOver(result, config.Fingerprints, config.SuccessfulOnly)
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
func isStaticAssetTakeOver(request *common.RequestInfo, fingerprints []*captureroutestaticassetfern.StaticAssetTakeOverFingerprint, successfulOnly bool) []*captureroutestaticassetfern.StaticAssetTakeOverVulnerableInfo {
	info := []*captureroutestaticassetfern.StaticAssetTakeOverVulnerableInfo{}

	successfulFingerprint := false
	for _, fingerprint := range fingerprints {
		instance := captureroutestaticassetfern.StaticAssetTakeOverVulnerableInfo{
			Fingerprint: fingerprint,
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
		instance := captureroutestaticassetfern.StaticAssetTakeOverVulnerableInfo{
			Fingerprint: &captureroutestaticassetfern.StaticAssetTakeOverFingerprint{
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
func GrabStaticAssetTakeOverFingerprints(fingerprintFilePaths []string) []*captureroutestaticassetfern.StaticAssetTakeOverFingerprint {
	fingerprints := []*captureroutestaticassetfern.StaticAssetTakeOverFingerprint{}

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
			Fingerprints []*captureroutestaticassetfern.StaticAssetTakeOverFingerprint
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
