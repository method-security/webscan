package application

import (
	// Standard
	"context"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discoverfern "github.com/Method-Security/webscan/generated/go/discover"

	// Utils
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

func createSendHTTPRequestConfig(baseURL, path string, method common.HttpMethod, requestParams common.HttpRequestParams, config *discoverfern.ApplicationFingerprintConfig) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  method,
		Params:  &requestParams,
	}
	return common.SendHttpRequestConfig{
		Request:            &request,
		MaxRedirects:       0,
		Insecure:           config.Insecure,
		Timeout:            config.Timeout,
		RequestMethod:      common.RequestMethodStandard,
		HeadlessConfig:     nil,
		BrowserbaseConfig:  nil,
		BrowserbaseSecrets: nil,
	}
}

func Run(ctx context.Context, target string, config *discoverfern.ApplicationFingerprintConfig) ([]*discoverfern.ApplicationFingerprintAttempt, []string) {
	if config == nil || config.Fingerprints == nil || len(config.Fingerprints.Modules) == 0 {
		return []*discoverfern.ApplicationFingerprintAttempt{}, []string{"invalid config: no resource types found"}
	}

	// Get the first (and should be only) resource type from the filtered config
	resourceType := config.Fingerprints
	if len(resourceType.Modules) == 0 {
		return []*discoverfern.ApplicationFingerprintAttempt{}, []string{"invalid config: no modules found for resource type"}
	}

	baseURL, parsedTargetPath, err := requesthelpers.SplitTargetURL(target)
	if err != nil {
		return []*discoverfern.ApplicationFingerprintAttempt{}, []string{err.Error()}
	}

	var attempts []*discoverfern.ApplicationFingerprintAttempt
	var errors []string

	// Process each module separately
	for _, module := range resourceType.Modules {
		attempt := &discoverfern.ApplicationFingerprintAttempt{
			Name:    module.Name,
			Finding: false,
		}

		var requests []*common.HttpRequestResponse
		for _, path := range module.Paths {
			// Request Configuration
			fullPath := parsedTargetPath + path
			var method = module.Method

			var requestParams common.HttpRequestParams
			if module.RequestParams != nil {
				requestParams = *module.RequestParams
			}

			// set request config
			requestConfig := createSendHTTPRequestConfig(baseURL, fullPath, method, requestParams, config)

			// send request
			request, err := request.SendRequest(ctx, requestConfig)
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}
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

func AnalyzeResponse(httpRequestResponse *common.HttpRequestResponse, module *discoverfern.ApplicationFingerprintModule) bool {
	// Check if response is nil
	if httpRequestResponse == nil || httpRequestResponse.Response == nil || httpRequestResponse.Response.StatusCode == nil {
		return false
	}

	response := httpRequestResponse.Response

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
						// Check each header value in the array
						for _, headerValue := range responseHeaderValue {
							if strings.Contains(strings.ToLower(headerValue), strings.ToLower(headerIndicatorValue)) {
								return true
							}
						}
					}
				}
			}
		}
	}

	// Analysis Response Body
	bodyIndicators := module.BodyIndicators
	if response.ResponseBody != nil && bodyIndicators != nil {
		bodyString := requesthelpers.GetResponseBodyStringFromBodyStruct(response.ResponseBody)
		if bodyString != nil {
			lowerBody := strings.ToLower(*bodyString)
			for _, indicator := range bodyIndicators {
				if strings.Contains(lowerBody, indicator) {
					return true
				}
			}
		}
	}

	return false
}

func LaunchFingerprintEngine(ctx context.Context, config *discoverfern.ApplicationFingerprintConfig) (*discoverfern.ApplicationFingerprintReport, error) {
	report := discoverfern.ApplicationFingerprintReport{Config: config}
	errors := []string{}

	var targets []*discoverfern.ApplicationFingerprintTarget
	for _, target := range config.Targets {
		var attempts []*discoverfern.ApplicationFingerprintAttempt
		attempt, errs := Run(ctx, target, config)
		attempts = append(attempts, attempt...)
		errors = append(errors, errs...)

		filteredAttempts := []*discoverfern.ApplicationFingerprintAttempt{}
		for _, attempt := range attempts {
			if !config.SuccessfulOnly || attempt.Finding {
				filteredAttempts = append(filteredAttempts, attempt)
			}
		}
		attempts = filteredAttempts

		target := discoverfern.ApplicationFingerprintTarget{Target: target, Attempts: attempts}
		targets = append(targets, &target)
	}

	// Marshal Report
	report.Targets = targets
	report.Errors = errors
	return &report, nil
}
