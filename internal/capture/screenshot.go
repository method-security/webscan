package capture

import (
	"context"
	"fmt"
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
		log.Info("Initializing browser")
		b.InitializeBrowser()
	}

	pageCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
	defer cancel()

	var page *rod.Page
	err = rod.Try(func() {
		log.Info("Creating page", svc1log.SafeParam("url", url))
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

		// Wait for any navigation for redirect(s) to complete
		log.Info("Waiting navigation to complete for redirects or DOM loading")
		page.MustNavigate(url)
		log.Info("Navigation complete")

		// Wait for the DOM to be stable
		// Important for capturing dynamic content
		log.Info("Waiting for DOM to stabilize")
		err = page.WaitDOMStable(time.Duration(b.MinDOMStabalizeTimeSeconds)*time.Second, .1)
		if err != nil {
			log.Error("Failed to wait for page load", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
			report.Errors = append(report.Errors, err.Error())
		}
		log.Info("DOM stabilized")

		// Wait for response received event
		log.Info("Waiting for response received event")
		var e = proto.NetworkResponseReceived{}
		wait := page.WaitEvent(&e)
		wait()

		// Process response headers from the event
		log.Info("Processing response headers")
		headers := make(map[string]string)
		for k, v := range e.Response.Headers {
			headers[k] = fmt.Sprint(v)
		}
		report.Request.ResponseHeaders = headers
		report.Request.StatusCode = &e.Response.Status

		// Capture the screenshot
		log.Info("Capturing screenshot")
		img, err := page.Screenshot(true, &proto.PageCaptureScreenshot{
			Format:  proto.PageCaptureScreenshotFormatPng,
			Quality: gson.Int(100),
		})

		if err != nil {
			log.Error("Failed to capture screenshot", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
			report.Errors = append(report.Errors, err.Error())
			return
		}
		log.Info("Screenshot captured")

		report.Screenshot = &img
	})
	if err != nil {
		log.Error("Failed to create page", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
	}
	return report
}
