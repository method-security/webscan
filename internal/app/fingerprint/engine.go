package fingerprint

import (
	"context"
	"strings"

	webscan "github.com/Method-Security/webscan/generated/go/app"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

func Run(ctx context.Context, target string, timeout int, config *webscan.AppFingerprintConfig) ([]*webscan.AppFingerprintAttemptInfo, []string) {
	if config == nil || config.Fingerprints == nil || len(config.Fingerprints.ResourcetTypes) == 0 {
		return []*webscan.AppFingerprintAttemptInfo{}, []string{"invalid config: no resource types found"}
	}

	// Get the first (and should be only) resource type from the filtered config
	resourceType := config.Fingerprints.ResourcetTypes[0]
	if len(resourceType.Modules) == 0 {
		return []*webscan.AppFingerprintAttemptInfo{}, []string{"invalid config: no modules found for resource type"}
	}

	baseURL, parsedTargetPath, err := utils.SplitTarget(target)
	if err != nil {
		return []*webscan.AppFingerprintAttemptInfo{}, []string{err.Error()}
	}

	var attempts []*webscan.AppFingerprintAttemptInfo
	var errors []string

	// Process each module separately
	for _, module := range resourceType.Modules {
		attempt := &webscan.AppFingerprintAttemptInfo{
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

			// Perform Request
			request := utils.PerformRequestScan(baseURL, fullPath, method, requestParams, timeout, true)
			errors = append(errors, request.Errors...)

			requests = append(requests, &request)
			if AnalyzeResponse(&request, module) {
				attempt.Finding = true
			}
		}

		attempt.Requests = requests
		attempts = append(attempts, attempt)
	}

	return attempts, errors
}

func AnalyzeResponse(response *common.RequestInfo, module *webscan.AppResourceModule) bool {
	if response == nil || response.StatusCode == nil {
		return false
	}

	// Analysis Response Headers
	if response.ResponseHeaders == nil {
		return false
	}
	headerIndicators := module.HeaderIndicators
	if headerIndicators == nil {
		return false
	}
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

	// Analysis Response Body
	if response.ResponseBody == nil {
		return false
	}
	bodyIndicators := module.BodyIndicators
	if bodyIndicators == nil {
		return false
	}
	lowerBody := strings.ToLower(*response.ResponseBody)
	for _, indicator := range bodyIndicators {
		if strings.Contains(lowerBody, indicator) {
			return true
		}
	}

	return false
}

func Launch(ctx context.Context, config *webscan.AppFingerprintConfig) (*webscan.AppFingerprintReport, error) {
	report := webscan.AppFingerprintReport{Config: config}
	errors := []string{}

	var targets []*webscan.AppFingerprintTargetInfo
	for _, target := range config.Targets {
		var attempts []*webscan.AppFingerprintAttemptInfo

		// Marshal Attempt results
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			// Try both http and https schemes
			schemes := []string{"http://", "https://"}
			for _, scheme := range schemes {
				schemeTarget := scheme + target
				attempt, errs := Run(ctx, schemeTarget, config.Timeout, config)
				attempts = append(attempts, attempt...)
				errors = append(errors, errs...)
			}
		} else {
			attempt, errs := Run(ctx, target, config.Timeout, config)
			attempts = append(attempts, attempt...)
			errors = append(errors, errs...)
		}

		if config.SuccessfulOnly {
			successfulAttempts := []*webscan.AppFingerprintAttemptInfo{}
			for _, attempt := range attempts {
				if attempt.Finding {
					successfulAttempts = append(successfulAttempts, attempt)
				}
			}
			attempts = successfulAttempts
		}

		target := webscan.AppFingerprintTargetInfo{Target: target, Attempts: attempts}
		targets = append(targets, &target)
	}

	// Marshal Report
	report.Targets = targets
	report.Errors = errors
	return &report, nil
}
