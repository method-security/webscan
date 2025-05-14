package capturepage

import (
	// Standard
	"context"
	"fmt"

	// Generated
	capturepagefern "github.com/Method-Security/webscan/generated/go/capture/page"
	common "github.com/Method-Security/webscan/generated/go/common"
	headless "github.com/Method-Security/webscan/utils/request/helpers/headless"

	// External
	proto "github.com/go-rod/rod/lib/proto"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	gson "github.com/ysmood/gson"
)

func CaptureScreenshot(ctx context.Context, requester *headless.Requester, options *common.RequestConfig) *capturepagefern.CapturePageReport {
	report := capturepagefern.CapturePageReport{}
	log := svc1log.FromContext(ctx)

	// Call the Capture function to get the HTML content and page
	requestInfo, err := requester.Request(ctx, *options)
	if err != nil {
		log.Error("Failed to capture HTML content", svc1log.SafeParam("url", fmt.Sprintf("%s%s", options.BaseUrl, options.Path)), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
		return &report
	}
	report.Request = requestInfo

	// Get the page from the browser
	page := requester.Browser.MustPage(options.BaseUrl)

	// Capture the screenshot
	log.Info("Capturing screenshot")
	img, err := page.Screenshot(true, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatPng,
		Quality: gson.Int(100),
	})

	if err != nil {
		log.Error("Failed to capture screenshot", svc1log.SafeParam("url", fmt.Sprintf("%s%s", options.BaseUrl, options.Path)), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
		return &report
	}
	log.Info("Screenshot captured")

	err = page.Close()
	if err != nil {
		log.Error("Failed to close page", svc1log.SafeParam("url", fmt.Sprintf("%s%s", options.BaseUrl, options.Path)), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
	}

	report.Screenshot = &img
	return &report
}
