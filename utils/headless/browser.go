package headless

import (
	"context"
	"fmt"
	"time"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
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

type BrowserOptions struct {
	FollowRedirects bool
	Method          common.HttpMethod
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

func (b *BrowserPageCapturer) Capture(ctx context.Context, url string, options *BrowserOptions) (*common.RequestInfo, error) {
	log := svc1log.FromContext(ctx)

	// Set basic RequestInfo
	baseURL, path, err := utils.SplitTarget(url)
	if err != nil {
		log.Error("Failed to parse URL", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		return nil, err
	}

	// Set default method to GET if not specified
	method := common.HttpMethodGet
	if options != nil && options.Method != "" {
		method = options.Method
	}
	requestInfo := &common.RequestInfo{BaseUrl: baseURL, Path: path, Method: method}

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

		// Track redirect chain
		redirectChain := []string{url}

		// Subscribe to Network.responseReceived events before navigation
		var e = proto.NetworkResponseReceived{}
		wait := page.WaitEvent(&e)

		// Wait for any navigation for redirect(s) to complete
		log.Info("Waiting for navigation to complete")
		if method == common.HttpMethodGet {
			page.MustNavigate(url)
		} else {
			// For non-GET methods, we need to use a different approach
			script := fmt.Sprintf(`
				() => {
					fetch(window.location.href, {
						method: '%s',
						headers: {
							'Content-Type': 'application/json'
						}
					});
				}
			`, method)
			page.MustEvalOnNewDocument(script)
			page.MustNavigate(url)
		}

		log.Info("Waiting for response received event")
		wait()

		log.Info("Processing response received event")
		headers := make(map[string]string)
		for k, v := range e.Response.Headers {
			headers[k] = fmt.Sprint(v)
		}
		requestInfo.ResponseHeaders = headers
		requestInfo.StatusCode = &e.Response.Status
		log.Info("Event URL", svc1log.SafeParam("url", e.Response.URL))

		// Get the final URL and add it to redirect chain if different
		finalURL := page.MustEval(`() => window.location.toString()`).Str()
		if finalURL != url {
			redirectChain = append(redirectChain, finalURL)
		}

		// Remove duplicates while preserving order
		seen := make(map[string]bool)
		uniqueChain := make([]string, 0, len(redirectChain))
		for _, u := range redirectChain {
			if !seen[u] {
				seen[u] = true
				uniqueChain = append(uniqueChain, u)
			}
		}
		requestInfo.RedirectChain = uniqueChain
	})
	if err != nil {
		log.Error("Failed to create page", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		requestInfo.Errors = append(requestInfo.Errors, err.Error())
		return requestInfo, err
	}
	log.Debug("Successfully connected to page")

	log.Info("Evaluating page content")
	htmlContent, err := page.HTML()
	if err != nil {
		log.Error("Failed to evaluate page content", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		requestInfo.Errors = append(requestInfo.Errors, err.Error())
		return requestInfo, err
	}

	requestInfo.ResponseBody = &htmlContent

	log.Info("Parsing URL to get path and query parameters")
	if parsedURL, err := urlutil.Parse(url); err == nil {
		requestInfo.Path = parsedURL.Path
		parsedURL.Query().Iterate(func(key string, value []string) bool {
			requestInfo.QueryParams[key] = value[0]
			return true
		})
	}

	return requestInfo, nil
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
