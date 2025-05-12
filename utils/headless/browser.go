package headless

import (
	"context"
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
		BaseUrl: baseURL,
		Path:    path,
		Method:  method,
	}

	if b.Browser == nil {
		log.Info("Initializing browser")
		b.InitializeBrowser()
	}

	pageCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
	defer cancel()

	var redirectChain = []string{url}
	var statusCode int
	var headers = map[string]string{}
	redirectIntercepted := false
	var timestamp time.Time
	var receivedAt time.Time
	var sizeBytes int

	err = rod.Try(func() {
		page := b.Browser.MustPage().Context(pageCtx)

		err := proto.FetchEnable{
			HandleAuthRequests: true,
			Patterns: []*proto.FetchRequestPattern{
				{RequestStage: proto.FetchRequestStageResponse},
			},
		}.Call(page)
		if err != nil {
			log.Error("Failed to enable fetch domain", svc1log.SafeParam("error", err))
			requestInfo.Errors = append(requestInfo.Errors, err.Error())
			return
		}

		go page.EachEvent(func(e *proto.FetchRequestPaused) {
			if e.ResponseStatusCode != nil &&
				*e.ResponseStatusCode >= 300 && *e.ResponseStatusCode < 400 &&
				options != nil && !options.FollowRedirects && !redirectIntercepted {

				redirectIntercepted = true
				statusCode = *e.ResponseStatusCode
				for _, h := range e.ResponseHeaders {
					headers[h.Name] = h.Value
				}
				if location := headers["Location"]; location != "" && !isStaticAsset(location) {
					redirectChain = append(redirectChain, location)
				}
				_ = proto.FetchFailRequest{
					RequestID:   e.RequestID,
					ErrorReason: proto.NetworkErrorReasonAborted,
				}.Call(page)
				return
			}
			_ = proto.FetchContinueRequest{RequestID: e.RequestID}.Call(page)
		})()

		if method == common.HttpMethodGet {
			log.Info("Navigating with GET", svc1log.SafeParam("url", url))
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
		}

		timestamp = time.Now()

		err = page.Navigate(url)
		if err != nil {
			if strings.Contains(err.Error(), "net::ERR_ABORTED") && redirectIntercepted {
				log.Info("Navigation aborted due to blocked redirect", svc1log.SafeParam("url", url))
				requestInfo.StatusCode = &statusCode
				// Convert headers (map[string]string) to map[string][]string, splitting on commas
				headerMap := make(map[string][]string, len(headers))
				for k, v := range headers {
					parts := strings.Split(v, ",")
					for i := range parts {
						parts[i] = strings.TrimSpace(parts[i])
					}
					headerMap[k] = parts
				}
				requestInfo.ResponseHeaders = headerMap
				requestInfo.RedirectChain = redirectChain
				return
			}
			log.Error("Unexpected navigation error", svc1log.SafeParam("error", err))
			requestInfo.Errors = append(requestInfo.Errors, err.Error())
			return
		}

		page.MustWaitLoad()

		// Final URL after following redirects
		finalURL := page.MustEval(`() => window.location.toString()`).Str()
		if finalURL != "" && (len(redirectChain) == 0 || redirectChain[len(redirectChain)-1] != finalURL) {
			redirectChain = append(redirectChain, finalURL)
		}

		status := 200
		requestInfo.StatusCode = &status
		requestInfo.RedirectChain = redirectChain

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
					receivedAt = time.Now()
					sizeBytes = len(htmlContent)
					requestInfo.ResponseBody = &common.Body{
						Kind: "text",
						Text: &common.TextBody{
							Value: htmlContent,
						},
					}
					requestInfo.Timestamp = timestamp
					requestInfo.ReceivedAt = &receivedAt
					requestInfo.SizeBytes = &sizeBytes
				}
			}
		}
	})

	if err != nil {
		log.Error("Failed during headless capture", svc1log.SafeParam("url", url), svc1log.SafeParam("error", err))
		requestInfo.Errors = append(requestInfo.Errors, err.Error())
	}

	log.Info("Parsing URL to get path and query parameters")
	if parsedURL, err := urlutil.Parse(url); err == nil {
		requestInfo.Path = parsedURL.Path
		parsedURL.Query().Iterate(func(key string, value []string) bool {
			requestInfo.Parameters.QueryParams[key] = value[0]
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
