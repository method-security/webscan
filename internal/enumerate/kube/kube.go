package kube

import (
	// Standard
	"context"
	"fmt"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	enumeratekubefern "github.com/Method-Security/webscan/generated/go/enumerate/kube"

	// Utils
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

var commonKubepaths = []string{"/api", "/livez", "/version"}

func createSendHTTPRequestConfig(baseURL, path string, verifyTls bool, timeout int) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params:  &common.HttpRequestParams{},
	}
	return common.SendHttpRequestConfig{
		Request:            &request,
		MaxRedirects:       0,
		VerifyTls:          verifyTls,
		Timeout:            timeout,
		RequestMethod:      common.RequestMethodStandard,
		HeadlessConfig:     nil,
		BrowserbaseConfig:  nil,
		BrowserbaseSecrets: nil,
	}
}

// PerformAppEnumerateKube performs enumeration of common Kubernetes endpoints and returns an EnumerateKubeReport.
func PerformAppEnumerateKube(ctx context.Context, config enumeratekubefern.EnumerateKubeConfig) *enumeratekubefern.EnumerateKubeReport {
	// Initialize report
	report := &enumeratekubefern.EnumerateKubeReport{Target: config.Target, Config: &config}
	var errors []string

	// Split target URL into base URL and path
	baseURL, parsedTargetPath, err := requesthelpers.SplitTargetURL(config.Target)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return report
	}

	// Send requests to the common Kubernetes paths
	requests := []*common.HttpRequestResponse{}
	for _, path := range commonKubepaths {
		// Create Request Config
		requestConfig := createSendHTTPRequestConfig(baseURL, fmt.Sprintf("%s%s", parsedTargetPath, path), config.VerifyTls, config.Timeout)

		// Send Request
		request, err := request.SendRequest(ctx, requestConfig)
		if err != nil {
			errors = append(errors, err.Error())
			report.Errors = errors
			return report
		}

		// Populate Attempt
		requests = append(requests, request)
	}

	// Populate and return Report
	report.Requests = requests
	report.Errors = errors
	return report
}
