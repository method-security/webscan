package discoverpage

import (
	// Standard
	"context"
	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"
	"github.com/Method-Security/webscan/utils"

	// Utils
	headless "github.com/Method-Security/webscan/utils/request/headless"
	// Internal
	pagehelpers "github.com/Method-Security/webscan/internal/discover/page/helpers"
	//Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

func getHTTPRequestConfig(baseURL string, path string, config discover.DiscoverPageConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) common.SendHttpRequestConfig {
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

// PerformPageCapture determines whether to perform a screenshot or HTML capture based on the takeScreenshot parameter
func PerformPageCapture(
	ctx context.Context,
	config discover.DiscoverPageConfig,
	browserbaseSecrets *common.BrowserbaseRequestSecrets,
) *discover.DiscoverPageReport {
	// Initialize report
	result := discover.DiscoverPageResult{}
	errors := []string{}
	report := discover.DiscoverPageReport{Config: &config, Result: &result}

	// Split target
	baseURL, path, err := requesthelpers.SplitTargetURL(config.Target)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return &report
	}

	// Get request config
	requestConfig := getHTTPRequestConfig(baseURL, path, config, browserbaseSecrets)

	// Perform screenshot capture if enabled
	if config.Screenshot {
		requester := headless.NewRequester(config.Timeout, config.HeadlessConfig)
		img, err := pagehelpers.CaptureScreenshot(ctx, requester, &requestConfig)
		if err != nil {
			errors = append(errors, err.Error())
			report.Errors = errors
			return &report
		}
		result.Screenshot = &img
	}

	// Perform HTML capture
	httpRequestResponse, err := pagehelpers.PerformHTMLPageCapture(ctx, &requestConfig)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return &report
	}

	// Check if response code is in the allowed list
	validCodes, err := utils.ParseResponseCodes(config.ResponseCodes)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return &report
	}

	// Only add request if response code is in the allowed list
	if httpRequestResponse != nil &&
		httpRequestResponse.Response != nil &&
		httpRequestResponse.Response.StatusCode != nil {
		if _, exists := validCodes[*httpRequestResponse.Response.StatusCode]; exists {
			result.Request = httpRequestResponse
			return &report
		}
	}

	// Return report
	report.Errors = errors
	return &report
}
