package headless

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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

	baseURL, path, err := utils.SplitTarget(url)
	if err != nil {
		log.Error("Failed to parse URL", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		return nil, err
	}

	method := common.HttpMethodGet
	if options != nil && options.Method != "" {
		method = options.Method
	}
	requestInfo := &common.RequestInfo{
		BaseUrl:     baseURL,
		Path:        path,
		Method:      method,
		QueryParams: make(map[string]string),
	}

	if b.Browser == nil {
		log.Info("Initializing browser")
		b.InitializeBrowser()
	}

	pageCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
	defer cancel()

	err = rod.Try(func() {
		log.Info("Creating page")
		page := b.Browser.MustPage().Context(pageCtx)

		err = proto.NetworkEnable{}.Call(page)
		if err != nil {
			log.Error("Failed to enable network tracking", svc1log.SafeParam("error", err))
			requestInfo.Errors = append(requestInfo.Errors, err.Error())
			return
		}

		redirectChain := []string{url}

		page.MustEval(`() => {
			window.__redirectHistory = [];
			const originalPushState = history.pushState;
			const originalReplaceState = history.replaceState;
			history.pushState = function() {
				window.__redirectHistory.push(arguments[2]);
				return originalPushState.apply(this, arguments);
			};
			history.replaceState = function() {
				window.__redirectHistory.push(arguments[2]);
				return originalReplaceState.apply(this, arguments);
			};
		}`)

		var responseReceived *proto.NetworkResponseReceived
		waitForResponse := page.EachEvent(func(e *proto.NetworkResponseReceived) bool {
			responseReceived = e
			log.Info("Received response",
				svc1log.SafeParam("url", e.Response.URL),
				svc1log.SafeParam("status", e.Response.Status),
				svc1log.SafeParam("headers", e.Response.Headers))

			if e.Response.Status >= 300 && e.Response.Status < 400 {
				if location, exists := e.Response.Headers["Location"]; exists {
					locationStr := fmt.Sprint(location)
					if locationStr != "" && !isStaticAsset(locationStr) && (len(redirectChain) == 0 || redirectChain[len(redirectChain)-1] != locationStr) {
						redirectChain = append(redirectChain, locationStr)
					}
				}
			}
			return true
		})

		if method == common.HttpMethodGet {
			log.Info("Navigating with GET", svc1log.SafeParam("url", url))
			page.MustNavigate(url)
		} else {
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
			log.Info("Navigating with custom method", svc1log.SafeParam("method", method))
			page.MustEvalOnNewDocument(script)
			page.MustNavigate(url)
		}

		waitForResponse()

		if responseReceived != nil {
			headers := make(map[string]string)
			for k, v := range responseReceived.Response.Headers {
				headers[k] = fmt.Sprint(v)
			}
			requestInfo.ResponseHeaders = headers
			requestInfo.StatusCode = &responseReceived.Response.Status

			if responseReceived.Response.Status >= 300 && responseReceived.Response.Status < 400 &&
				options != nil && !options.FollowRedirects {
				log.Info("Stopping at redirect",
					svc1log.SafeParam("status", responseReceived.Response.Status),
					svc1log.SafeParam("location", headers["Location"]))
				requestInfo.RedirectChain = redirectChain
				return
			}
		}

		jsRedirectsScript := `
			const history = window.__redirectHistory || [];
			if (Array.isArray(history)) {
				const result = [];
				for (let i = 0; i < history.length; i++) {
					if (history[i]) {
						result.push(String(history[i]));
					}
				}
				return JSON.stringify(result);
			}
			return "[]";
		`
		jsRedirectsResult, err := page.Eval(jsRedirectsScript)
		if err == nil && jsRedirectsResult != nil {
			redirectsJSON := jsRedirectsResult.Value.String()
			if redirectsJSON != "" && redirectsJSON != "[]" {
				var redirectURLs []string
				if err := json.Unmarshal([]byte(redirectsJSON), &redirectURLs); err == nil {
					for _, redirectURL := range redirectURLs {
						if redirectURL != "" && !isStaticAsset(redirectURL) && (len(redirectChain) == 0 || redirectChain[len(redirectChain)-1] != redirectURL) {
							redirectChain = append(redirectChain, redirectURL)
						}
					}
				}
			}
		}

		finalURL := page.MustEval(`() => window.location.toString()`).Str()
		if finalURL != "" && (len(redirectChain) == 0 || redirectChain[len(redirectChain)-1] != finalURL) {
			redirectChain = append(redirectChain, finalURL)
		}

		seen := make(map[string]bool)
		uniqueChain := make([]string, 0, len(redirectChain))
		for _, u := range redirectChain {
			if !seen[u] {
				seen[u] = true
				uniqueChain = append(uniqueChain, u)
			}
		}
		requestInfo.RedirectChain = uniqueChain

		if options == nil || options.FollowRedirects {
			log.Info("Waiting for DOM to be stable")
			if err := page.WaitDOMStable(time.Duration(b.MinDOMStabalizeTimeSeconds)*time.Second, .1); err != nil {
				log.Error("Failed waiting for DOM to stabilize", svc1log.SafeParam("error", err))
				requestInfo.Errors = append(requestInfo.Errors, err.Error())
			} else {
				htmlContent, err := page.HTML()
				if err != nil {
					log.Error("Failed to get HTML content", svc1log.SafeParam("error", err))
					requestInfo.Errors = append(requestInfo.Errors, err.Error())
				} else {
					requestInfo.ResponseBody = &htmlContent
				}
			}
		}
	})

	if err != nil {
		log.Error("Failed to create page", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		requestInfo.Errors = append(requestInfo.Errors, err.Error())
		return requestInfo, err
	}

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
		closeCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
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

func isStaticAsset(url string) bool {
	staticExts := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
		".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map",
	}
	lower := strings.ToLower(url)
	for _, ext := range staticExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
