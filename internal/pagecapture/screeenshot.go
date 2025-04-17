package pagecapture

import (
	"context"

	common "github.com/Method-Security/webscan/generated/go/common"
	pagecapturefern "github.com/Method-Security/webscan/generated/go/pagecapture"
	pagecapture "github.com/Method-Security/webscan/internal/pagecapture/helpers"
	"github.com/Method-Security/webscan/internal/pagecapture/helpers/browserbase"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func PerformScreenshotPageCapture(ctx context.Context, target string, captureMethod common.CaptureMethod, baseURLsOnly bool, captureStaticAssets bool, timeout int, minDOMStabalizeTime int, insecure bool, browserPath *string, browserBaseToken *string, browserBaseProject *string, browserBaseOptions *[]browserbase.Option) *pagecapturefern.PageCaptureScreenshotReport {
	log := svc1log.FromContext(ctx)

	switch captureMethod {
	case common.CaptureMethodBrowser:
		log.Info("Initiating page capture with browser method", svc1log.SafeParam("target", target))
		capturer := pagecapture.NewBrowserPageCapturer(browserPath, timeout, minDOMStabalizeTime)
		report := capturer.CaptureScreenshot(ctx, target, &pagecapture.Options{})
		_ = capturer.Close(ctx)

		return report
	case common.CaptureMethodBrowserbase:
		log.Info("Initiating page capture with browserbase method", svc1log.SafeParam("target", target))
		if browserBaseToken == nil || browserBaseProject == nil {
			return &pagecapturefern.PageCaptureScreenshotReport{
				Errors: []string{"browserbase token and project are required"},
			}
		}

		client := browserbase.NewBrowserbaseClient(*browserBaseToken, *browserBaseProject, browserbase.NewBrowserbaseOptions(ctx, *browserBaseOptions...))
		capturer := pagecapture.NewBrowserbasePageCapturer(ctx, timeout, minDOMStabalizeTime, client)
		report := capturer.CaptureScreenshot(ctx, target, &pagecapture.Options{})

		_ = capturer.Close(ctx)

		return report

	default:
		return &pagecapturefern.PageCaptureScreenshotReport{
			Errors: []string{"unsupported capture method"},
		}
	}

}
