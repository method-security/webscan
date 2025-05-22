package general

import (
	// Standard
	"context"
	"fmt"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"

	// Utils
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

func createSendHTTPRequestConfig(baseURL, path string, config *discover.DiscoverProbeConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params:  &common.HttpRequestParams{},
	}
	return common.SendHttpRequestConfig{
		Request:            &request,
		MaxRedirects:       config.MaxRedirects,
		VerifyTls:          config.VerifyTls,
		Timeout:            config.Timeout,
		RequestMethod:      config.RequestMethod,
		HeadlessConfig:     config.HeadlessConfig,
		BrowserbaseConfig:  config.BrowserbaseConfig,
		BrowserbaseSecrets: browserbaseSecrets,
	}
}

// sendRequests attempts to connect to a target using both HTTPS and HTTP protocols
func sendRequests(ctx context.Context, target string, config *discover.DiscoverProbeConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) ([]*common.HttpRequestResponse, []string) {
	httpRequestResponses := []*common.HttpRequestResponse{}
	errors := []string{}

	// Send HTTPS Request
	httpsURL := "https://" + target
	baseURL, path, err := requesthelpers.SplitTargetURL(httpsURL)
	if err != nil {
		errors = append(errors, fmt.Sprintf("invalid address %s: %v", httpsURL, err))
		return nil, errors
	}
	httpsConfig := createSendHTTPRequestConfig(baseURL, path, config, browserbaseSecrets)
	httpRequestResponse, httpsErr := request.SendRequest(ctx, httpsConfig)
	if httpsErr != nil {
		errors = append(errors, fmt.Sprintf("failed to probe %s: %s", httpsURL, httpsErr))
	} else {
		httpRequestResponses = append(httpRequestResponses, httpRequestResponse)
	}

	// Send HTTP Request
	if !config.HttpsOnly {
		httpURL := "http://" + target
		baseURL, path, err = requesthelpers.SplitTargetURL(httpURL)
		if err != nil {
			errors = append(errors, fmt.Sprintf("invalid address %s: %v", httpURL, err))
			return nil, errors
		}
		httpConfig := createSendHTTPRequestConfig(baseURL, path, config, browserbaseSecrets)
		httpRequestResponse, err := request.SendRequest(ctx, httpConfig)
		if err == nil {
			httpRequestResponses = append(httpRequestResponses, httpRequestResponse)
		}
	}

	return httpRequestResponses, errors
}

// PerformWebProbe performs web probing for the given config and returns a DiscoverProbeReport.
func PerformWebProbe(ctx context.Context, config *discover.DiscoverProbeConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) (*discover.DiscoverProbeReport, error) {
	report := &discover.DiscoverProbeReport{Config: config}
	errors := []string{}

	// Single loop to process all targets
	allResponses := []*common.HttpRequestResponse{}
	for _, target := range config.Targets {
		responses, errs := sendRequests(ctx, target, config, browserbaseSecrets)
		if len(errs) > 0 {
			errors = append(errors, errs...)
			continue
		}
		allResponses = append(allResponses, responses...)
	}

	report.Targets = allResponses
	report.Errors = errors
	return report, nil
}
