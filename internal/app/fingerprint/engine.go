package fingerprint

import (
	"context"
	"strings"

	appFern "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
)

// createAppFingerprintRequestConfig creates a request config for the app fingerprint engine
func createAppFingerprintRequestConfig(baseURL, path string, method common.HttpMethod, requestParams common.RequestParams, config *appFern.AppFingerprintConfig) common.RequestConfig {
	maxRedirects := 10 // Default max redirects value
	return common.RequestConfig{
		BaseUrl:         baseURL,
		Path:            path,
		Method:          method,
		RequestParams:   &requestParams,
		Timeout:         config.Timeout,
		FollowRedirects: true,
		MaxRedirects:    &maxRedirects,
		Insecure:        config.Insecure,
	}
}

func Run(ctx context.Context, target string, config *appFern.AppFingerprintConfig, browserbaseSecrets *common.BrowserbaseSecrets) ([]*appFern.AppFingerprintAttemptInfo, []string) {
	if config == nil || config.Fingerprints == nil || len(config.Fingerprints.Modules) == 0 {
		return []*appFern.AppFingerprintAttemptInfo{}, []string{"invalid config: no resource types found"}
	}

	// Get the first (and should be only) resource type from the filtered config
	resourceType := config.Fingerprints
	if len(resourceType.Modules) == 0 {
		return []*appFern.AppFingerprintAttemptInfo{}, []string{"invalid config: no modules found for resource type"}
	}

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		return []*appFern.AppFingerprintAttemptInfo{}, []string{err.Error()}
	}

	var attempts []*appFern.AppFingerprintAttemptInfo
	var errors []string

	// Process each module separately
	for _, module := range resourceType.Modules {
		attempt := &appFern.AppFingerprintAttemptInfo{
			Name:    module.Name,
			Finding: false,
		}

		var requests []*common.RequestInfo
		for _, path := range module.Paths {
			// Request Configuration
			fullPath := parsedTargetPath + path
			var method = module.Method

			var requestParams common.RequestParams
			if module.RequestParams != nil {
				requestParams = *module.RequestParams
			}

			// Perform Request (Request, Browser, or Browserbase)
			requestConfig := createAppFingerprintRequestConfig(baseURL, fullPath, method, requestParams, config)
			request, err := request.SendRequest(ctx, requestConfig)
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}
			errors = append(errors, request.Errors...)
			requests = append(requests, request)

			if AnalyzeResponse(request, module) {
				attempt.Finding = true
				break
			}
		}
		attempt.Requests = requests
		attempts = append(attempts, attempt)
	}
	return attempts, errors
}

func AnalyzeResponse(response *common.RequestInfo, module *appFern.AppResourceModule) bool {
	// Check if response is nil or status code is 404
	if response == nil || response.StatusCode == nil || *response.StatusCode == 404 {
		return false
	}

	// Analysis Response Headers
	headerIndicators := module.HeaderIndicators
	if response.ResponseHeaders != nil && headerIndicators != nil {
		// Loop through response headers
		for responseHeader, responseHeaderValue := range response.ResponseHeaders {
			// Loop through header indicators
			for headerIndicator, headerIndicatorValues := range headerIndicators {
				if strings.EqualFold(responseHeader, headerIndicator) {
					if len(headerIndicatorValues) == 0 {
						return true // If empty array, the header presence alone is an indicator
					}
					// Loop through header values
					for _, headerIndicatorValue := range headerIndicatorValues {
						if strings.Contains(strings.ToLower(responseHeaderValue), strings.ToLower(headerIndicatorValue)) {
							return true
						}
					}
				}
			}
		}
	}

	// Analysis Response Body
	bodyIndicators := module.BodyIndicators
	if response.ResponseBody != nil && bodyIndicators != nil {
		lowerBody := strings.ToLower(*response.ResponseBody)
		for _, indicator := range bodyIndicators {
			if strings.Contains(lowerBody, indicator) {
				return true
			}
		}
	}

	return false
}

func Launch(ctx context.Context, config *appFern.AppFingerprintConfig, browserbaseSecrets *common.BrowserbaseSecrets) (*appFern.AppFingerprintReport, error) {
	report := appFern.AppFingerprintReport{Config: config}
	errors := []string{}

	var targets []*appFern.AppFingerprintTargetInfo
	for _, target := range config.Targets {
		var attempts []*appFern.AppFingerprintAttemptInfo

		// Marshal Attempt results
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			// Try both http and https schemes
			schemes := []string{"http://", "https://"}
			for _, scheme := range schemes {
				schemeTarget := scheme + target
				attempt, errs := Run(ctx, schemeTarget, config, browserbaseSecrets)
				attempts = append(attempts, attempt...)
				errors = append(errors, errs...)
			}
		} else {
			attempt, errs := Run(ctx, target, config, browserbaseSecrets)
			attempts = append(attempts, attempt...)
			errors = append(errors, errs...)
		}

		if config.SuccessfulOnly {
			successfulAttempts := []*appFern.AppFingerprintAttemptInfo{}
			for _, attempt := range attempts {
				if attempt.Finding {
					successfulAttempts = append(successfulAttempts, attempt)
				}
			}
			attempts = successfulAttempts
		}

		target := appFern.AppFingerprintTargetInfo{Target: target, Attempts: attempts}
		targets = append(targets, &target)
	}

	// Marshal Report
	report.Targets = targets
	report.Errors = errors
	return &report, nil
}
