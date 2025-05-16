package capturepage

import (
	// Standard
	"context"
	// Generated
	capturepagefern "github.com/Method-Security/webscan/generated/go/capture/page"
	common "github.com/Method-Security/webscan/generated/go/common"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	headless "github.com/Method-Security/webscan/utils/request/helpers/headless"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// getScreenshotRequestConfig returns a common.RequestConfig for a screenshot capture
func getScreenshotRequestConfig(baseURL string, path string, config capturepagefern.CapturePageConfig) *common.RequestConfig {
	return &common.RequestConfig{
		BaseUrl:            baseURL,
		Path:               path,
		Method:             common.HttpMethodGet,
		RequestParams:      &common.RequestParams{},
		FollowRedirects:    true,
		MaxRedirects:       &config.MaxRedirects,
		Insecure:           config.Insecure,
		Timeout:            config.Timeout,
		RequestMethod:      common.RequestMethodHeadless,
		HeadlessConfig:     config.HeadlessConfig,
		BrowserbaseConfig:  nil,
		BrowserbaseSecrets: nil,
	}
}

// PerformScreenshotPageCapture performs a screenshot capture on a page
func PerformScreenshotPageCapture(ctx context.Context, config capturepagefern.CapturePageConfig) *capturepagefern.CapturePageReport {
	log := svc1log.FromContext(ctx)

	// Split target
	baseURL, path, err := utils.SplitTarget(config.Target)
	if err != nil {
		return &capturepagefern.CapturePageReport{
			Errors: []string{err.Error()},
		}
	}

	// Set request config
	requestConfig := getScreenshotRequestConfig(baseURL, path, config)

	// Perform capture
	switch config.RequestMethod {
	case common.RequestMethodHeadless:
		log.Info("Initiating page capture with browser method", svc1log.SafeParam("target", config.Target))
		requester := headless.NewRequester(config.Timeout, config.HeadlessConfig)
		report := CaptureScreenshot(ctx, requester, requestConfig)
		return report
	default:
		return &capturepagefern.CapturePageReport{
			Errors: []string{"unsupported capture method"},
		}
	}

}
