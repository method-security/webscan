package general

import (
	// Standard
	"context"
	"fmt"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	generalfern "github.com/Method-Security/webscan/generated/go/general"

	// Utils
	"github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
)

func createProbeRequestConfig(baseURL, path string, config *generalfern.GeneralProbeConfig, browserbaseSecrets *common.BrowserbaseSecrets) common.RequestConfig {
	return common.RequestConfig{
		BaseUrl:            baseURL,
		Path:               path,
		Method:             common.HttpMethodGet,
		RequestParams:      &common.RequestParams{},
		FollowRedirects:    true,
		MaxRedirects:       &config.MaxRedirects,
		Insecure:           true,
		Timeout:            config.Timeout,
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
		results, err := tryHTTPSThenHTTP(ctx, target, config, browserbaseSecrets)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to probe %s: %v", target, err))
			continue
		}
		requests = append(requests, results...)
	}

	report.Targets = requests
	report.Errors = errors
	return report, nil
}

// tryHTTPSThenHTTP attempts to connect to a target using both HTTPS and HTTP protocols
func tryHTTPSThenHTTP(ctx context.Context, target string, config *generalfern.GeneralProbeConfig, browserbaseSecrets *common.BrowserbaseSecrets) ([]*common.RequestInfo, error) {
	results := []*common.RequestInfo{}

	// Try HTTPS
	httpsURL := "https://" + target
	baseURL, path, err := utils.SplitTarget(httpsURL)
	if err != nil {
		return nil, fmt.Errorf("invalid address %s: %v", httpsURL, err)
	}
	httpsConfig := createProbeRequestConfig(baseURL, path, config, browserbaseSecrets)
	httpsResult, httpsErr := request.SendRequest(ctx, httpsConfig)
	if httpsErr == nil {
		results = append(results, httpsResult)
	}

	// Try HTTP
	if !config.OnlyHttps {
		httpURL := "http://" + target
		baseURL, path, err = utils.SplitTarget(httpURL)
		if err != nil {
			return nil, fmt.Errorf("invalid address %s: %v", httpURL, err)
		}
		httpConfig := createProbeRequestConfig(baseURL, path, config, browserbaseSecrets)
		httpResult, httpErr := request.SendRequest(ctx, httpConfig)
		if httpErr == nil {
			results = append(results, httpResult)
		}
	}

	return results, nil
}
