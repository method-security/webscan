package discoverpage

import (
	// Standard
	"context"
	"fmt"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	// Utils
	headless "github.com/Method-Security/webscan/utils/request/headless"
	// External
	proto "github.com/go-rod/rod/lib/proto"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	gson "github.com/ysmood/gson"
)

// CaptureScreenshot uses a headless browser to capture a screenshot of the given URL and returns the image bytes.
func CaptureScreenshot(ctx context.Context, requester *headless.Requester, sendHTTPRequestConfig *common.SendHttpRequestConfig) ([]byte, error) {
	log := svc1log.FromContext(ctx)

	// Initialize browser if not already initialized
	if requester.Browser == nil {
		log.Info("Initializing browser")
		requester.InitializeBrowser()
	}

	// Get the page from the browser
	fullURL := fmt.Sprintf("%s%s", sendHTTPRequestConfig.Request.BaseUrl, sendHTTPRequestConfig.Request.Path)
	log.Info("Capturing screenshot", svc1log.SafeParam("url", fullURL))
	page := requester.Browser.MustPage(fullURL)

	// Capture the screenshot
	log.Info("Capturing screenshot")
	img, err := page.Screenshot(true, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatPng,
		Quality: gson.Int(100),
	})

	if err != nil {
		log.Error("Failed to capture screenshot", svc1log.SafeParam("url", fmt.Sprintf("%s%s", sendHTTPRequestConfig.Request.BaseUrl, sendHTTPRequestConfig.Request.Path)), svc1log.SafeParam("error", err))
		return nil, err
	}
	log.Info("Screenshot captured")

	err = page.Close()
	if err != nil {
		log.Error("Failed to close page", svc1log.SafeParam("url", fmt.Sprintf("%s%s", sendHTTPRequestConfig.Request.BaseUrl, sendHTTPRequestConfig.Request.Path)), svc1log.SafeParam("error", err))
		return nil, err
	}

	return img, nil
}
