package headless

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	common "github.com/Method-Security/webscan/generated/go/common"
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
	requestInfo := &common.RequestInfo{}

	if b.Browser == nil {
		log.Info("Initializing browser")
		b.InitializeBrowser()
	}

	pageCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
	defer cancel()

	var page *rod.Page
	err := rod.Try(func() {
		log.Info("Creating page", svc1log.SafeParam("url", url))
		page = b.Browser.MustPage(url).Context(pageCtx)

		// Track redirect chain
		redirectChain := []string{url}
		if options != nil && options.FollowRedirects {
			page.MustEvalOnNewDocument(`
				window.addEventListener('beforeunload', function() {
					window.redirectChain = window.redirectChain || [];
					window.redirectChain.push(window.location.href);
				});
			`)
		}

		// Subscribe to Network.responseReceived events before navigation
		var e = proto.NetworkResponseReceived{}
		wait := page.WaitEvent(&e)

		// Wait for any navigation for redirect(s) to complete
		log.Info("Waiting for navigation to complete")
		if options != nil && !options.FollowRedirects {
			// If not following redirects, use a custom navigation that stops at the first response
			page.MustEvalOnNewDocument(`
				Object.defineProperty(window, 'location', {
					get: function() { return { href: window.location.href }; },
					set: function(url) {
						fetch(url, { redirect: 'manual' })
							.then(response => {
								window.location.href = url;
							})
							.catch(error => {
								console.error('Navigation failed:', error);
							});
					}
				});
			`)
		}
		page.MustNavigate(url)

		log.Info("Waiting for DOM to be stable")
		if err := page.WaitDOMStable(time.Duration(b.MinDOMStabalizeTimeSeconds)*time.Second, .1); err != nil {
			log.Error("Failed waiting for DOM to stabilize", svc1log.SafeParam("error", err))
			requestInfo.Errors = append(requestInfo.Errors, err.Error())
			return
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

		// Get the final URL and redirect chain
		finalURL := page.MustEval(`window.location.href`).Str()
		if finalURL != url {
			redirectChain = append(redirectChain, finalURL)
		}

		// Get any intermediate redirects from the browser if following redirects
		if options != nil && options.FollowRedirects {
			urls := page.MustEval(`(function() {
				const chain = window.redirectChain || [];
				return chain.join(',');
			})()`).Str()

			if urls != "" {
				for _, url := range strings.Split(urls, ",") {
					url = strings.Trim(url, `" `)
					if url != "" {
						redirectChain = append(redirectChain, url)
					}
				}
			}
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

	log.Info("Encoding page content")
	encodedBody := base64.StdEncoding.EncodeToString([]byte(htmlContent))
	requestInfo.ResponseBody = &encodedBody

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
