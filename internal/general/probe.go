package webapplication

import (
	"context"
	"fmt"

	common "github.com/Method-Security/webscan/generated/go/common"
	generalfern "github.com/Method-Security/webscan/generated/go/general"
	"github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
)

// createWebserverProbeRequestConfig creates a common request configuration
func createGeneralProbeRequestConfig(baseURL, path string, config *generalfern.GeneralProbeConfig, browserbaseSecrets *common.BrowserbaseSecrets) common.RequestConfig {
	return common.RequestConfig{
		BaseUrl:            baseURL,
		Path:               path,
		Method:             common.HttpMethodGet,
		RequestParams:      &common.RequestParams{},
		Timeout:            config.Timeout,
		FollowRedirects:    true,
		MaxRedirects:       &config.MaxRedirects,
		Insecure:           true,
		RequestMethod:      config.RequestMethod,
		HeadlessConfig:     config.HeadlessConfig,
		BrowserbaseConfig:  config.BrowserbaseConfig,
		BrowserbaseSecrets: browserbaseSecrets,
	}
}

func PerformGeneralProbe(ctx context.Context, config *generalfern.GeneralProbeConfig, browserbaseSecrets *common.BrowserbaseSecrets) (*generalfern.GeneralProbeReport, error) {
	report := &generalfern.GeneralProbeReport{Config: config}
	errors := []string{}
	requests := []*common.RequestInfo{}

	// Single loop to process all targets
	for _, target := range config.Targets {
		result, err := tryHTTPSThenHTTP(ctx, target, config, browserbaseSecrets)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to probe %s: %v", target, err))
			continue
		}
		requests = append(requests, result)
	}

	report.Targets = requests
	report.Errors = errors
	return report, nil
}

// tryHTTPSThenHTTP attempts to connect to a target using HTTPS first, falling back to HTTP if HTTPS fails
func tryHTTPSThenHTTP(ctx context.Context, target string, config *generalfern.GeneralProbeConfig, browserbaseSecrets *common.BrowserbaseSecrets) (*common.RequestInfo, error) {
	// Try HTTPS first
	targetURL := "https://" + target
	baseURL, path, err := utils.SplitTarget(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid address %s: %v", targetURL, err)
	}
	requestConfig := createGeneralProbeRequestConfig(baseURL, path, config, browserbaseSecrets)

	result, err := request.SendRequest(ctx, requestConfig)
	if err != nil {
		// If HTTPS fails, try HTTP
		targetURL = "http://" + target
		baseURL, path, err = utils.SplitTarget(targetURL)
		if err != nil {
			return nil, fmt.Errorf("invalid address %s: %v", targetURL, err)
		}

		requestConfig = createGeneralProbeRequestConfig(baseURL, path, config, browserbaseSecrets)
		result, err = request.SendRequest(ctx, requestConfig)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}
