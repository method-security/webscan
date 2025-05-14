package capturepage

import (
	"context"

	capturepagefern "github.com/Method-Security/webscan/generated/go/capture/page"
	"github.com/Method-Security/webscan/generated/go/common"
	html "github.com/Method-Security/webscan/internal/capture/page/helpers"
	screenshot "github.com/Method-Security/webscan/internal/capture/page/helpers/screenshot"
)

// PerformCapturePage determines whether to perform a screenshot or HTML capture based on the takeScreenshot parameter
func PerformCapturePage(
	ctx context.Context,
	config capturepagefern.CapturePageConfig,
	browserbaseSecrets *common.BrowserbaseSecrets,
) *capturepagefern.CapturePageReport {
	if config.TakeScreenshot {
		result := screenshot.PerformScreenshotPageCapture(ctx, config)
		return result
	}
	result := html.PerformHTMLPageCapture(ctx, config, browserbaseSecrets)
	return &result
}
