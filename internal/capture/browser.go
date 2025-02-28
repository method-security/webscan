package capture

import (
	"context"
	"time"

	"encoding/base64"

	webscan "github.com/Method-Security/webscan/generated/go/pagecapture"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	urlutil "github.com/projectdiscovery/utils/url"
)

type BrowserPageCapturer struct {
	PathToBrowser              *string
	Browser                    *rod.Browser
	TimeoutSeconds             int
	MinDOMStabalizeTimeSeconds int
}

func NewBrowserPageCapturer(pathToBrowser *string, timeout int, minDOMStabalizeTime int) *BrowserPageCapturer {
	return &BrowserPageCapturer{
		PathToBrowser:              pathToBrowser,
		Browser:                    nil,
		TimeoutSeconds:             timeout,
		MinDOMStabalizeTimeSeconds: minDOMStabalizeTime,
	}
}

func NewBrowserPageCapturerWithClient(client *cdp.Client, timeout int, minDOMStabalizeTime int) *BrowserPageCapturer {
	return &BrowserPageCapturer{
		PathToBrowser:              nil,
		Browser:                    rod.New().Client(client).MustConnect(),
		TimeoutSeconds:             timeout,
		MinDOMStabalizeTimeSeconds: minDOMStabalizeTime,
	}
}

func (b *BrowserPageCapturer) Capture(ctx context.Context, url string, options *Options) (*webscan.PageCaptureReport, error) {
	log := svc1log.FromContext(ctx)
	report := NewPageCaptureReport(url)

	if b.Browser == nil {
		log.Debug("Initializing browser")
		b.InitializeBrowser()
	}

	pageCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
	defer cancel()

	var page *rod.Page
	err := rod.Try(func() {
		page = b.Browser.MustPage(url).Context(pageCtx)

		// Subscribe to Network.responseReceived events before navigation
		page.EachEvent(func(e *proto.NetworkResponseReceived) {
			if e.Response.URL == url {
				for k, v := range e.Response.Headers {
					report.Request.ResponseHeaders[k] = v.String()
				}
				report.Request.StatusCode = &e.Response.Status
			}
		})()
	})
	if err != nil {
		log.Error("Failed to create page", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
		return report, err
	}
	log.Debug("Successfully connected to page")

	// Wait for any navigation for redirect(s) to complete
	page.WaitNavigation(proto.PageLifecycleEventNameDOMContentLoaded)

	// Wait for the DOM to be stable
	err = page.WaitDOMStable(time.Duration(b.MinDOMStabalizeTimeSeconds)*time.Second, .1)
	if err != nil {
		log.Debug("Failed to wait for page load", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
		return report, err
	}

	htmlContent, err := page.HTML()
	if err != nil {
		log.Error("Failed to evaluate page content", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		report.Errors = append(report.Errors, err.Error())
		return report, err
	}

	encodedBody := base64.StdEncoding.EncodeToString([]byte(htmlContent))
	report.Request.ResponseBody = &encodedBody

	// Parse URL to get path and query parameters
	if parsedURL, err := urlutil.Parse(url); err == nil {
		report.Request.Path = parsedURL.Path
		parsedURL.Query().Iterate(func(key string, value []string) bool {
			report.Request.QueryParams[key] = value[0]
			return true
		})
	}

	return report, nil
}

func (b *BrowserPageCapturer) InitializeBrowser() {
	var browserURL string
	if b.PathToBrowser != nil && *b.PathToBrowser != "" {
		browserURL = launcher.New().Headless(true).Bin(*b.PathToBrowser).MustLaunch()
	} else {
		browserURL = launcher.New().Headless(true).MustLaunch()
	}

	b.Browser = rod.New().ControlURL(browserURL).MustConnect()
}

func (b *BrowserPageCapturer) Close(ctx context.Context) error {
	svc1log.FromContext(ctx).Debug("Closing browser with allowed timeout of 5 seconds")
	if b.Browser != nil {
		svc1log.FromContext(ctx).Debug("Attempting to close browser")
		closeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		closeChan := make(chan error)
		go func() {
			closeChan <- b.Browser.Close()
		}()

		select {
		case err := <-closeChan:
			if err != nil {
				svc1log.FromContext(ctx).Error("Failed to close browser", svc1log.SafeParam("error", err))
				return err
			}
			svc1log.FromContext(ctx).Debug("Successfully closed browser")
		case <-closeCtx.Done():
			svc1log.FromContext(ctx).Warn("Timeout while closing browser, skipping close operation")
		}
	}
	return nil
}
