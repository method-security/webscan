package capture

import (
	"context"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go/pagecapture"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/ysmood/gson"
)

func (b *BrowserbasePageCapturer) CaptureScreenshot(ctx context.Context, url string, options *Options) *webscan.PageScreenshotReport {
	return b.Capturer.CaptureScreenshot(ctx, url, options)
}

func (b *BrowserPageCapturer) CaptureScreenshot(ctx context.Context, url string, options *Options) *webscan.PageScreenshotReport {
	report := NewPageScreenshotReport(url)
	log := svc1log.FromContext(ctx)

	// Call the Capture function to get the HTML content
	captureResult, err := b.Capture(ctx, url, options)
	if err != nil {
		log.Error("Failed to capture HTML content", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
		return report
	}

	// Update report with capture results
	if captureResult.Request.ResponseBody != nil {
		report.Request.ResponseBody = captureResult.Request.ResponseBody
	}
	if captureResult.Request.ResponseHeaders != nil {
		report.Request.ResponseHeaders = captureResult.Request.ResponseHeaders
	}
	if captureResult.Request.StatusCode != nil {
		report.Request.StatusCode = captureResult.Request.StatusCode
	}

	if b.Browser == nil {
		log.Debug("Initializing browser")
		b.InitializeBrowser()
	}

	pageCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
	defer cancel()

	var page *rod.Page
	err = rod.Try(func() {
		page = b.Browser.MustPage(url).Context(pageCtx)

		// Get the final URL after any redirects and parse it
		finalURL := page.MustInfo().URL
		parsedURL, err := urlutil.Parse(finalURL)
		if err == nil {
			report.Request.BaseUrl = parsedURL.URL.String()
			report.Request.Path = parsedURL.Path
			parsedURL.Query().Iterate(func(key string, value []string) bool {
				report.Request.QueryParams[key] = value[0]
				return true
			})
		} else {
			report.Request.BaseUrl = finalURL
			log.Error("Failed to parse URL", svc1log.SafeParam("url", finalURL), svc1log.SafeParam("error", err))
		}

		// Capture response status and headers using CDP
		router := page.HijackRequests()
		defer func() {
			if err := router.Stop(); err != nil {
				log.Error("Error stopping router", svc1log.SafeParam("error", err))
			}
		}()

		router.MustAdd("*", func(ctx *rod.Hijack) {
			ctx.MustLoadResponse()
			response := ctx.Response
			statusCode := response.Payload().ResponseCode
			report.Request.StatusCode = &statusCode

			// Capture response headers
			for k, v := range response.Headers() {
				if len(v) > 0 {
					report.Request.ResponseHeaders[k] = v[0]
				}
			}
		})
		router.Run()
	})
	if err != nil {
		log.Error("Failed to create page", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
		return report
	}
	log.Debug("Successfully connected to page")

	// Wait for any navigation for redirect(s) to complete
	log.Debug("Waiting navigation to complete for redirects or DOM loading")
	page.WaitNavigation(proto.PageLifecycleEventNameDOMContentLoaded)
	log.Debug("Navigation complete")

	// Wait for the DOM to be stable
	// Important for capturing dynamic content
	log.Debug("Waiting for DOM to stabilize")
	err = page.WaitDOMStable(time.Duration(b.MinDOMStabalizeTimeSeconds)*time.Second, .1)
	if err != nil {
		log.Debug("Failed to wait for page load", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
	}
	log.Debug("DOM stabilized")

	// Capture the screenshot
	log.Debug("Capturing screenshot")
	img, err := page.Screenshot(true, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatPng,
		Quality: gson.Int(100),
	})

	if err != nil {
		log.Debug("Failed to capture screenshot", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
		return report
	}
	log.Debug("Screenshot captured")

	report.Screenshot = &img
	return report
}
