package capturepage

import (
	// Standard
	"context"
	// Generated
	capturepagefern "github.com/Method-Security/webscan/generated/go/capture/page"
	common "github.com/Method-Security/webscan/generated/go/common"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
)

func getHTMLRequestConfig(baseURL string, path string, config capturepagefern.CapturePageConfig, browserbaseSecrets *common.BrowserbaseSecrets) common.RequestConfig {
	return common.RequestConfig{
		BaseUrl:            baseURL,
		Path:               path,
		Method:             common.HttpMethodGet,
		RequestParams:      &common.RequestParams{},
		FollowRedirects:    true,
		MaxRedirects:       &config.MaxRedirects,
		Insecure:           config.Insecure,
		Timeout:            config.Timeout,
		RequestMethod:      config.RequestMethod,
		HeadlessConfig:     config.HeadlessConfig,
		BrowserbaseConfig:  config.BrowserbaseConfig,
		BrowserbaseSecrets: browserbaseSecrets,
	}
}

func PerformHTMLPageCapture(ctx context.Context, config capturepagefern.CapturePageConfig, browserbaseSecrets *common.BrowserbaseSecrets) capturepagefern.CapturePageReport {
	// Initialize report
	report := capturepagefern.CapturePageReport{}

	// Split the target into baseURL and path
	baseURL, path, err := utils.SplitTarget(config.Target)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	// Send request
	requestConfig := getHTMLRequestConfig(baseURL, path, config, browserbaseSecrets)
	request, err := request.SendRequest(ctx, requestConfig)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	// Marshal report
	report.Request = request
	return report
}
