package headless

import (
	"context"
	"fmt"
	"path"
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

// Requester is a struct that captures a page from a browser
type Requester struct {
	PathToBrowser              *string
	Browser                    *rod.Browser
	TimeoutSeconds             int
	MinDOMStabalizeTimeSeconds int
}

func NewRequester(config *common.HeadlessConfig, timeout int) *Requester {
	return &Requester{
		PathToBrowser:              config.PathToBrowser,
		Browser:                    nil,
		TimeoutSeconds:             timeout,
		MinDOMStabalizeTimeSeconds: config.MinDomStabalizeTime,
	}
}

func NewRequesterWithClient(client *cdp.Client, timeout int, minDOMStabalizeTime int) *Requester {
	return &Requester{
		PathToBrowser:              nil,
		Browser:                    rod.New().Client(client).MustConnect(),
		TimeoutSeconds:             timeout,
		MinDOMStabalizeTimeSeconds: minDOMStabalizeTime,
	}
}

// Request captures a page with a Headless Browser
func (b *Requester) Request(ctx context.Context, options common.RequestConfig) (*common.RequestInfo, error) {
	log := svc1log.FromContext(ctx)

	method := common.HttpMethodGet
	if options.Method != "" {
		method = options.Method
	}

	requestInfo := &common.RequestInfo{
		BaseUrl: options.BaseUrl,
		Path:    options.Path,
		Method:  method,
	}

	if b.Browser == nil {
		log.Info("Initializing browser")
		launch := launcher.New().Headless(true)
		if options.Insecure {
			launch = launch.Set("ignore-certificate-errors")
		}
		if b.PathToBrowser != nil && *b.PathToBrowser != "" {
			launch = launch.Bin(*b.PathToBrowser)
		}
		browserURL := launch.MustLaunch()
		b.Browser = rod.New().ControlURL(browserURL).MustConnect()
	}

	pageCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
	defer cancel()

	fullURL := fmt.Sprintf("%s%s", options.BaseUrl, options.Path)
	var redirectChain = []string{fullURL}
	var statusCode int
	var headers = map[string]string{}
	redirectIntercepted := false

	err := rod.Try(func() {
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

		var lastStatusCode int
		var lastResponseURL string
		go page.EachEvent(func(e *proto.FetchRequestPaused) {
			// Always capture headers
			for _, h := range e.ResponseHeaders {
				headers[h.Name] = h.Value
			}

			// Capture status code and URL
			if e.ResponseStatusCode != nil {
				lastStatusCode = *e.ResponseStatusCode
				statusCode = lastStatusCode
				lastResponseURL = e.Request.URL
			}

			// Handle redirects
			if e.ResponseStatusCode != nil && *e.ResponseStatusCode >= 300 && *e.ResponseStatusCode < 400 {
				// Add the current request URL to the chain if it's not already there
				if len(redirectChain) == 0 || redirectChain[len(redirectChain)-1] != e.Request.URL {
					redirectChain = append(redirectChain, e.Request.URL)
				}

				// Add the Location header URL if it exists
				if location := headers["Location"]; location != "" && !isStaticAsset(location) {
					redirectChain = append(redirectChain, location)
				}

				// Only abort if we're not following redirects
				if !options.FollowRedirects && !redirectIntercepted {
					redirectIntercepted = true
					_ = proto.FetchFailRequest{
						RequestID:   e.RequestID,
						ErrorReason: proto.NetworkErrorReasonAborted,
					}.Call(page)
					return
				}
			}

			_ = proto.FetchContinueRequest{RequestID: e.RequestID}.Call(page)
		})()

		if method == common.HttpMethodGet {
			log.Info("Navigating with GET", svc1log.SafeParam("url", fullURL))
		} else {
			// Build headers string
			headersStr := ""
			if options.RequestParams.HeaderParams != nil {
				headersStr = "headers: {"
				for k, v := range options.RequestParams.HeaderParams {
					headersStr += fmt.Sprintf("'%s': '%s',", k, v)
				}
				headersStr += "},"
			}

			// Build body string
			bodyStr := ""
			if options.RequestParams.BodyParams != nil && *options.RequestParams.BodyParams != "" {
				bodyStr = "body: " + *options.RequestParams.BodyParams + ","
			}

			script := fmt.Sprintf(`
				() => {
					fetch(window.location.href, {
						method: '%s',
						%s
						%s
					}).then(response => {
						window._lastResponseStatus = response.status;
						return response.text();
					}).then(text => {
						window._lastResponseBody = text;
					});
				}
			`, method, headersStr, bodyStr)
			log.Info("Navigating with custom method", svc1log.SafeParam("method", method))
			page.MustEvalOnNewDocument(script)
		}

		err = page.Navigate(fullURL)
		if err != nil {
			if strings.Contains(err.Error(), "net::ERR_ABORTED") && redirectIntercepted {
				log.Info("Navigation aborted due to blocked redirect", svc1log.SafeParam("url", fullURL))
				requestInfo.StatusCode = &statusCode
				requestInfo.ResponseHeaders = headers
				requestInfo.RedirectChain = redirectChain
				return
			}
			log.Error("Unexpected navigation error", svc1log.SafeParam("error", err))
			requestInfo.Errors = append(requestInfo.Errors, err.Error())
			return
		}

		// Wait for page load and any potential redirects
		page.MustWaitLoad()
		time.Sleep(time.Duration(b.MinDOMStabalizeTimeSeconds) * time.Second)

		// Get the current URL after all redirects
		currentURL := page.MustEval(`() => window.location.href`).Str()

		// Add the final URL to the chain if it's different from the last one
		if currentURL != "" && currentURL != lastResponseURL {
			redirectChain = append(redirectChain, currentURL)
		}

		// Get the status code from the fetch response or last captured status code
		status := page.MustEval(`() => window._lastResponseStatus || ` + fmt.Sprintf("%d", lastStatusCode)).Int()
		requestInfo.StatusCode = &status
		requestInfo.RedirectChain = redirectChain
		requestInfo.Timestamp = time.Now()
		requestInfo.ResponseHeaders = headers

		// Always get the response body after navigation
		htmlContent, err := page.HTML()
		if err != nil {
			log.Error("Failed to get HTML content", svc1log.SafeParam("error", err))
			requestInfo.Errors = append(requestInfo.Errors, err.Error())
		} else {
			requestInfo.ResponseBody = &htmlContent
		}
	})

	if err != nil {
		log.Error("Failed during headless capture", svc1log.SafeParam("url", fullURL), svc1log.SafeParam("error", err))
		requestInfo.Errors = append(requestInfo.Errors, err.Error())
	}

	if parsedURL, err := urlutil.Parse(fullURL); err == nil {
		requestInfo.Path = parsedURL.Path
		parsedURL.Query().Iterate(func(key string, value []string) bool {
			requestInfo.QueryParams[key] = value[0]
			return true
		})
	}

	return requestInfo, nil
}

func (b *Requester) InitializeBrowser() {
	var browserURL string
	launch := launcher.New().Headless(true)
	if b.PathToBrowser != nil && *b.PathToBrowser != "" {
		launch = launch.Bin(*b.PathToBrowser)
	}
	browserURL = launch.MustLaunch()
	b.Browser = rod.New().ControlURL(browserURL).MustConnect()
}

func (b *Requester) Close(ctx context.Context) error {
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

// isStaticAsset determines whether a given URL points to a common static asset.
// It checks the file extension after stripping any query strings or fragments.
// Supported extensions include common formats like .css, .js, .png, .woff2, etc.
func isStaticAsset(rawURL string) bool {
	staticExts := []string{
		// Images
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".avif", ".ico", ".svg",
		// Fonts
		".woff", ".woff2", ".ttf", ".otf", ".eot", ".sfnt",
		// Stylesheets
		".css", ".scss", ".sass", ".less",
		// Scripts
		".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx",
		// Documents
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		// Media
		".mp3", ".mp4", ".webm", ".ogg", ".wav", ".m4a", ".m4v",
		// Archives
		".zip", ".rar", ".7z", ".tar", ".gz",
		// Data
		".json", ".xml", ".csv", ".map",
		// Other
		".txt", ".md", ".markdown", ".yaml", ".yml", ".toml", ".ini",
	}

	// Strip query string and fragment
	if i := strings.IndexAny(rawURL, "?#"); i != -1 {
		rawURL = rawURL[:i]
	}

	// Get the lowercase file extension
	ext := strings.ToLower(path.Ext(rawURL))

	for _, staticExt := range staticExts {
		if ext == staticExt {
			return true
		}
	}
	return false
}
