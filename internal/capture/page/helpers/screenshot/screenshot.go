package capturepage

import (
	"context"

	capturepagefern "github.com/Method-Security/webscan/generated/go/capture/page"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
	"github.com/Method-Security/webscan/utils/request/helpers/headless"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// getScreenshotRequestConfig returns a common.RequestConfig for a screenshot capture
func getScreenshotRequestConfig(baseURL string, path string, config capturepagefern.CapturePageConfig) *common.RequestConfig {
	return &common.RequestConfig{
		BaseUrl:            baseURL,
		Path:               path,
		Method:             common.HttpMethodGet,
		RequestParams:      &common.RequestParams{},
		FollowRedirects:    true,
		Insecure:           config.Insecure,
		Timeout:            config.Timeout,
		MaxRedirects:       &config.MaxRedirects,
		RequestMethod:      common.RequestMethodHeadless,
		HeadlessConfig:     config.HeadlessConfig,
		BrowserbaseConfig:  nil,
		BrowserbaseSecrets: nil,
	}
}

// PerformScreenshotPageCapture performs a screenshot capture on a page
func PerformScreenshotPageCapture(ctx context.Context, config capturepagefern.CapturePageConfig) *capturepagefern.CapturePageReport {
	log := svc1log.FromContext(ctx)

	baseURL, path, err := utils.SplitTarget(config.Target)
	if err != nil {
		return &capturepagefern.CapturePageReport{
			Errors: []string{err.Error()},
		}
	}
	requestConfig := getScreenshotRequestConfig(baseURL, path, config)

	switch config.RequestMethod {
	case common.RequestMethodHeadless:
		log.Info("Initiating page capture with browser method", svc1log.SafeParam("target", config.Target))
		requester := headless.NewRequester(config.HeadlessConfig, config.Timeout)
		report := CaptureScreenshot(ctx, requester, requestConfig)
		return report
	default:
		return &capturepagefern.CapturePageReport{
			Errors: []string{"unsupported capture method"},
		}
	}

}
