package discoverpage

import (
	// Standard
	"context"
	"fmt"
	"time"

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
func CaptureScreenshot(ctx context.Context, browser *headless.Requester, sendHTTPRequestConfig *common.SendHttpRequestConfig) ([]byte, error) {
	// Get the logger from the context
	log := svc1log.FromContext(ctx)

	// Initialize browser if not already initialized
	if browser.Browser == nil {
		log.Info("Initializing browser")
		err := browser.InitializeBrowser(ctx)
		if err != nil {
			log.Error("Failed to initialize browser", svc1log.SafeParam("error", err))
			return nil, err
		}
	}

	// Get the page from the browser
	fullURL := fmt.Sprintf("%s%s", sendHTTPRequestConfig.Request.BaseUrl, sendHTTPRequestConfig.Request.Path)
	log.Info("Capturing screenshot", svc1log.SafeParam("url", fullURL))

	// Create a new page
	page, err := browser.Browser.Page(proto.TargetCreateTarget{})
	if err != nil {
		log.Error("Failed to create page for screenshot", svc1log.SafeParam("error", err))
		return nil, err
	}

	// Navigate to the URL
	err = page.Navigate(fullURL)
	if err != nil {
		log.Warn("Navigation encountered error but continuing", svc1log.SafeParam("error", err.Error()))
	}

	// Wait for the page to load
	err = page.WaitLoad()
	if err != nil {
		log.Info("Page load wait timed out (this is normal)", svc1log.SafeParam("error", err.Error()))
	}

	// Additional wait for DOM stabilization (using the configured time from browser)
	if browser.MinDOMStabalizeTimeSeconds > 0 {
		log.Info("Waiting for DOM stabilization", svc1log.SafeParam("seconds", browser.MinDOMStabalizeTimeSeconds))
		select {
		case <-time.After(time.Duration(browser.MinDOMStabalizeTimeSeconds) * time.Second):
			// Normal case - sleep completed
		case <-ctx.Done():
			log.Warn("DOM stabilization interrupted by context timeout")
		}
	}

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
