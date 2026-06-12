package kube

import (
	// Standard
	"context"
	"fmt"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	enumeratekubefern "github.com/Method-Security/webscan/generated/go/enumerate/kube"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

var commonKubepaths = []string{"/api", "/livez", "/version"}

func createSendHTTPRequestConfig(baseURL, path string, verifyTLS bool, timeout int, userAgent common.UserAgentPreset) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params:  &common.HttpRequestParams{},
	}
	return common.SendHttpRequestConfig{
		Request:            &request,
		MaxRedirects:       0,
		VerifyTls:          verifyTLS,
		Timeout:            timeout,
		UserAgent:          userAgent,
		RequestMethod:      common.RequestMethodStandard,
		HeadlessConfig:     nil,
		BrowserbaseConfig:  nil,
		BrowserbaseSecrets: nil,
	}
}

// PerformAppEnumerateKube performs enumeration of common Kubernetes endpoints and returns an EnumerateKubeReport.
func PerformAppEnumerateKube(ctx context.Context, config *enumeratekubefern.EnumerateKubeConfig) *enumeratekubefern.EnumerateKubeReport {
	// Initialize report
	report := &enumeratekubefern.EnumerateKubeReport{Config: config, Result: &enumeratekubefern.EnumerateKubeResult{}}
	var errors []string

	// Split target URL into base URL and path
	baseURL, parsedTargetPath, _, err := requesthelpers.SplitTargetURL(config.Target)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return report
	}

	// Send requests to the common Kubernetes paths
	requests := []*common.HttpRequestResponse{}
	for i, path := range commonKubepaths {
		// Create Request Config
		requestConfig := createSendHTTPRequestConfig(baseURL, fmt.Sprintf("%s%s", parsedTargetPath, path), config.VerifyTls, config.Timeout, config.UserAgent)

		// Send Request
		request, err := request.SendRequest(ctx, requestConfig)
		if err != nil {
			errors = append(errors, err.Error())
			report.Errors = errors
			return report
		}

		// Populate Attempt
		requests = append(requests, request)

		// Apply stealth delay between requests
		if config.Sleep > 0 && i < len(commonKubepaths)-1 {
			delay := utils.CalculateDelayWithJitter(config.Sleep, config.Jitter)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				report.Result.Target = config.Target
				report.Result.Requests = requests
				report.Errors = errors
				return report
			}
		}
	}

	// Populate and return Report
	report.Result.Target = config.Target
	report.Result.Requests = requests
	report.Errors = errors
	return report
}
