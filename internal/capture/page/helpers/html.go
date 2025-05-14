package capturepage

import (
	"context"

	capturepagefern "github.com/Method-Security/webscan/generated/go/capture/page"
	common "github.com/Method-Security/webscan/generated/go/common"
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
)

func getCaputurePageHTMLRequestConfig(baseURL string, path string, config capturepagefern.CapturePageConfig, browserbaseSecrets *common.BrowserbaseSecrets) common.RequestConfig {
	return common.RequestConfig{
		BaseUrl:            baseURL,
		Path:               path,
		Method:             common.HttpMethodGet,
		RequestParams:      &common.RequestParams{},
		FollowRedirects:    true,
		Insecure:           config.Insecure,
		MaxRedirects:       &config.MaxRedirects,
		RequestMethod:      config.RequestMethod,
		HeadlessConfig:     config.HeadlessConfig,
		BrowserbaseConfig:  config.BrowserbaseConfig,
		BrowserbaseSecrets: browserbaseSecrets,
	}
}

func PerformHTMLPageCapture(ctx context.Context, config capturepagefern.CapturePageConfig, browserbaseSecrets *common.BrowserbaseSecrets) capturepagefern.CapturePageReport {
	report := capturepagefern.CapturePageReport{}

	// Split the target into baseURL and path
	baseURL, path, err := utils.SplitTarget(config.Target)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	// Set Request Config
	requestConfig := getCaputurePageHTMLRequestConfig(baseURL, path, config, browserbaseSecrets)

	// Send Request
	request, err := request.SendRequest(ctx, requestConfig)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	report.Request = request
	return report
}
