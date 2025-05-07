package pagecapture

import (
	"context"

	pagecapturefern "github.com/Method-Security/webscan/generated/go/pagecapture"
	"github.com/Method-Security/webscan/utils/headless"
	browserbase "github.com/Method-Security/webscan/utils/headless/browserbase"
	"github.com/go-rod/rod/lib/proto"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/ysmood/gson"
)

func CaptureScreenshotWithBrowserbase(ctx context.Context, capturer *browserbase.PageCapturer, url string, options *browserbase.Options) *pagecapturefern.PageCaptureScreenshotReport {
	// Convert browserbase.Options to headless.Options
	headlessOptions := &headless.Options{}
	return CaptureScreenshot(ctx, capturer.Capturer, url, headlessOptions)
}

func CaptureScreenshot(ctx context.Context, capturer *headless.BrowserPageCapturer, url string, options *headless.Options) *pagecapturefern.PageCaptureScreenshotReport {
	report := pagecapturefern.PageCaptureScreenshotReport{}
	log := svc1log.FromContext(ctx)

	// Call the Capture function to get the HTML content and page
	requestInfo, err := capturer.Capture(ctx, url, options)
	if err != nil {
		log.Error("Failed to capture HTML content", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
		return &report
	}
	report.Request = requestInfo

	// Get the page from the browser
	page := capturer.Browser.MustPage(url)

	// Capture the screenshot
	log.Info("Capturing screenshot")
	img, err := page.Screenshot(true, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatPng,
		Quality: gson.Int(100),
	})

	if err != nil {
		log.Error("Failed to capture screenshot", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
		return &report
	}
	log.Info("Screenshot captured")

	err = page.Close()
	if err != nil {
		log.Error("Failed to close page", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
	}

	report.Screenshot = &img
	return &report
}
