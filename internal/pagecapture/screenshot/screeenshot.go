package pagecapture

import (
	"context"

	common "github.com/Method-Security/webscan/generated/go/common"
	pagecapturefern "github.com/Method-Security/webscan/generated/go/pagecapture"
	"github.com/Method-Security/webscan/utils/headless"
	"github.com/Method-Security/webscan/utils/headless/browserbase"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

var FollowRedirects = true

func PerformScreenshotPageCapture(ctx context.Context, target string, captureMethod common.CaptureMethod, baseURLsOnly bool, captureStaticAssets bool, timeout int, minDOMStabalizeTime int, insecure bool, browserPath *string, browserBaseToken *string, browserBaseProject *string, browserBaseOptions *[]browserbase.Option) *pagecapturefern.PageCaptureScreenshotReport {
	log := svc1log.FromContext(ctx)

	switch captureMethod {
	case common.CaptureMethodBrowser:
		log.Info("Initiating page capture with browser method", svc1log.SafeParam("target", target))
		capturer := headless.NewBrowserPageCapturer(browserPath, timeout, minDOMStabalizeTime)
		report := CaptureScreenshot(ctx, capturer, target, &headless.BrowserOptions{FollowRedirects: FollowRedirects})
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
		capturer := browserbase.NewBrowserbasePageCapturer(ctx, timeout, minDOMStabalizeTime, *client)
		report := CaptureScreenshot(ctx, capturer.Capturer, target, &headless.BrowserOptions{FollowRedirects: FollowRedirects})
		_ = capturer.Close(ctx)
		return report

	default:
		return &pagecapturefern.PageCaptureScreenshotReport{
			Errors: []string{"unsupported capture method"},
		}
	}

}
