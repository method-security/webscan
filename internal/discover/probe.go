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

// sendHTTPRequest attempts to connect to a target using HTTP protocol
func sendHTTPRequest(ctx context.Context, target string, config *discover.DiscoverProbeConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) (*common.HttpRequestResponse, error) {
	sanitizedTarget := requesthelpers.RemoveScheme(target)
	httpURL := "http://" + sanitizedTarget

	baseURL, path, err := requesthelpers.SplitTargetURL(httpURL)
	if err != nil {
		return nil, fmt.Errorf("invalid address %s: %v", httpURL, err)
	}

	httpConfig := createSendHTTPRequestConfig(baseURL, path, config, browserbaseSecrets)
	httpRequestResponse, err := request.SendRequest(ctx, httpConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to probe %s - %s", httpURL, err)
	}

	return httpRequestResponse, nil
}

// sendHTTPSRequest attempts to connect to a target using HTTPS protocol
func sendHTTPSRequest(ctx context.Context, target string, config *discover.DiscoverProbeConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) (*common.HttpRequestResponse, error) {
	sanitizedTarget := requesthelpers.RemoveScheme(target)
	httpsURL := "https://" + sanitizedTarget

	baseURL, path, err := requesthelpers.SplitTargetURL(httpsURL)
	if err != nil {
		return nil, fmt.Errorf("invalid address %s: %v", httpsURL, err)
	}

	httpsConfig := createSendHTTPRequestConfig(baseURL, path, config, browserbaseSecrets)
	httpRequestResponse, err := request.SendRequest(ctx, httpsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to probe %s - %s", httpsURL, err)
	}

	return httpRequestResponse, nil
}

// sendRequests attempts to connect to a target using both HTTPS and HTTP protocols
func sendRequests(ctx context.Context, target string, config *discover.DiscoverProbeConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) ([]*common.HttpRequestResponse, []string) {
	httpRequestResponses := []*common.HttpRequestResponse{}
	var httpErr, httpsErr error

	// Try HTTP request
	if httpResponse, err := sendHTTPRequest(ctx, target, config, browserbaseSecrets); err != nil {
		httpErr = err
	} else {
		httpRequestResponses = append(httpRequestResponses, httpResponse)
	}

	// Try HTTPS request
	if httpsResponse, err := sendHTTPSRequest(ctx, target, config, browserbaseSecrets); err != nil {
		httpsErr = err
	} else {
		httpRequestResponses = append(httpRequestResponses, httpsResponse)
	}

	// Only return errors if both requests failed
	var errors []string
	if httpErr != nil && httpsErr != nil {
		errors = append(errors, httpErr.Error(), httpsErr.Error())
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
		}
		allResponses = append(allResponses, responses...)
	}

	report.Targets = allResponses
	report.Errors = errors
	return report, nil
}
