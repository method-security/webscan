package headless

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	common "github.com/Method-Security/webscan/generated/go/common"
	rod "github.com/go-rod/rod"
	cdp "github.com/go-rod/rod/lib/cdp"
	launcher "github.com/go-rod/rod/lib/launcher"
	proto "github.com/go-rod/rod/lib/proto"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

type Requester struct {
	Browser                    *rod.Browser
	PathToBrowser              *string
	TimeoutSeconds             int
	MinDOMStabalizeTimeSeconds int
}

func NewRequester(timeout int, config *common.HeadlessConfig) *Requester {
	return &Requester{
		Browser:                    nil,
		PathToBrowser:              config.PathToBrowser,
		TimeoutSeconds:             timeout,
		MinDOMStabalizeTimeSeconds: config.MinDomStabalizeTime,
	}
}

func NewRequesterWithClient(client *cdp.Client, timeout int, minDOMStabalizeTime int) *Requester {
	return &Requester{
		Browser:                    rod.New().Client(client).MustConnect(),
		PathToBrowser:              nil,
		TimeoutSeconds:             timeout,
		MinDOMStabalizeTimeSeconds: minDOMStabalizeTime,
	}
}

func (b *Requester) Request(ctx context.Context, config common.RequestConfig) (*common.RequestInfo, error) {
	log := svc1log.FromContext(ctx)
	requestInfo := &common.RequestInfo{
		BaseUrl:         config.BaseUrl,
		Path:            config.Path,
		Method:          config.Method,
		PathParams:      config.RequestParams.PathParams,
		QueryParams:     config.RequestParams.QueryParams,
		HeaderParams:    config.RequestParams.HeaderParams,
		FormParams:      config.RequestParams.FormParams,
		MultipartParams: config.RequestParams.MultipartParams,
		BodyParams:      config.RequestParams.BodyParams,
	}

	log.Info("Requesting", svc1log.SafeParam("url", config.BaseUrl+config.Path))
	if b.Browser == nil {
		log.Info("Initializing browser")
		launch := launcher.New().Headless(true)
		if config.Insecure {
			launch = launch.Set("ignore-certificate-errors")
		}
		if b.PathToBrowser != nil && *b.PathToBrowser != "" {
			launch = launch.Bin(*b.PathToBrowser)
		}
		browserURL := launch.MustLaunch()
		b.Browser = rod.New().ControlURL(browserURL).MustConnect()
		log.Info("Connected to browser")
	}

	pageCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
	defer cancel()

	fullURL := fmt.Sprintf("%s%s", config.BaseUrl, config.Path)
	redirectChain := []string{fullURL}
	headers := map[string]string{}
	var statusCode int

	err := rod.Try(func() {
		page := b.Browser.MustPage().Context(pageCtx)

		// Enable fetch interception
		err := proto.FetchEnable{
			HandleAuthRequests: true,
			Patterns: []*proto.FetchRequestPattern{
				{RequestStage: proto.FetchRequestStageRequest},
				{RequestStage: proto.FetchRequestStageResponse},
			},
		}.Call(page)
		if err != nil {
			log.Error("Failed to enable fetch domain", svc1log.SafeParam("error", err))
			requestInfo.Errors = append(requestInfo.Errors, err.Error())
			return
		}

		// Create a channel to signal when the request is complete
		requestComplete := make(chan struct{})
		var once sync.Once

		go page.EachEvent(func(e *proto.FetchRequestPaused) {
			log.Info("Fetch request paused. Url grabbed from browser",
				svc1log.SafeParam("url", e.Request.URL))

			// Track status code of the final response
			if e.ResponseStatusCode != nil && *e.ResponseStatusCode > 0 {
				// Only update status code if it's a non-redirect response
				if *e.ResponseStatusCode < 300 {
					statusCode = *e.ResponseStatusCode
					log.Info("Final response status code",
						svc1log.SafeParam("status", strconv.Itoa(statusCode)))
				}
			}

			// Only track headers from non-redirect responses
			if e.ResponseStatusCode != nil && *e.ResponseStatusCode < 300 {
				headers = make(map[string]string) // Reset headers for final response
				for _, h := range e.ResponseHeaders {
					headers[h.Name] = h.Value
				}
			} else if e.ResponseStatusCode != nil && *e.ResponseStatusCode >= 300 && *e.ResponseStatusCode < 400 {
				// Check for Location header in redirects
				var location string
				for _, h := range e.ResponseHeaders {
					if h.Name == "Location" {
						location = h.Value
						break
					}
				}
				if location != "" && !isStaticAsset(location) {
					redirectChain = append(redirectChain, location)
					log.Info("Adding redirect",
						svc1log.SafeParam("location", location))
				}
				if !config.FollowRedirects {
					_ = proto.FetchFailRequest{
						RequestID:   e.RequestID,
						ErrorReason: proto.NetworkErrorReasonAborted,
					}.Call(page)
					once.Do(func() { close(requestComplete) })
					return
				}
			}

			// Continue the request
			_ = proto.FetchContinueRequest{RequestID: e.RequestID}.Call(page)
			if e.ResponseStatusCode != nil && *e.ResponseStatusCode < 300 {
				once.Do(func() { close(requestComplete) })
			}
		})()

		// Make the request
		if config.FollowRedirects {
			log.Info("Following redirect", svc1log.SafeParam("url", fullURL))
			page.MustNavigate(fullURL)
		} else {
			log.Info("Not following redirects")
			script := fmt.Sprintf(`
				() => {
					fetch("%s", {
						method: "%s",
						headers: %s,
						body: %s,
						credentials: "include",
						redirect: "manual"
					}).catch(e => console.error(e));
				}
			`, fullURL, requestInfo.Method,
				marshalHeaders(config.RequestParams.HeaderParams),
				marshalBody(config.RequestParams.BodyParams))

			page.MustEval(script)
		}

		// Wait for the request to complete
		select {
		case <-requestComplete:
		case <-pageCtx.Done():
			requestInfo.Errors = append(requestInfo.Errors, "Request timed out")
			return
		}

		// Get the final URL after any redirects
		finalURL := page.MustEval(`() => window.location.href`).Str()
		if finalURL != fullURL && finalURL != "about:blank" {
			redirectChain = append(redirectChain, finalURL)
		}

		// Wait for DOM stabilization
		log.Info("Waiting for DOM stabilization", svc1log.SafeParam("seconds", strconv.Itoa(b.MinDOMStabalizeTimeSeconds)))
		time.Sleep(time.Duration(b.MinDOMStabalizeTimeSeconds) * time.Second)

		// Ensure page is fully loaded
		page.MustWaitLoad().MustWaitStable()

		log.Info("Final URL", svc1log.SafeParam("url", finalURL))

		// Only get HTML content if we have a successful response
		if statusCode >= 200 && statusCode < 300 {
			htmlContent, err := page.HTML()
			if err != nil {
				log.Error("Failed to get HTML content", svc1log.SafeParam("error", err))
				requestInfo.Errors = append(requestInfo.Errors, err.Error())
			}
			requestInfo.ResponseBody = &htmlContent
		}

		requestInfo.StatusCode = &statusCode
		requestInfo.RedirectChain = redirectChain
		requestInfo.Timestamp = time.Now()
		requestInfo.ResponseHeaders = headers
	})

	if err != nil {
		log.Error("Failed during headless capture", svc1log.SafeParam("url", fullURL), svc1log.SafeParam("error", err))
		requestInfo.Errors = append(requestInfo.Errors, err.Error())
	}

	return requestInfo, nil
}

func (b *Requester) InitializeBrowser() {
	launch := launcher.New().Headless(true)
	if b.PathToBrowser != nil && *b.PathToBrowser != "" {
		launch = launch.Bin(*b.PathToBrowser)
	}
	browserURL := launch.MustLaunch()
	b.Browser = rod.New().ControlURL(browserURL).MustConnect()
}

func (b *Requester) Close(ctx context.Context) error {
	if b.Browser != nil {
		closeCtx, cancel := context.WithTimeout(ctx, time.Duration(b.TimeoutSeconds)*time.Second)
		defer cancel()
		closeChan := make(chan error)
		go func() {
			closeChan <- b.Browser.Close()
		}()

		select {
		case err := <-closeChan:
			return err
		case <-closeCtx.Done():
			return nil
		}
	}
	return nil
}

func isStaticAsset(rawURL string) bool {
	staticExts := []string{
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".avif", ".ico", ".svg",
		".woff", ".woff2", ".ttf", ".otf", ".eot", ".sfnt",
		".css", ".scss", ".sass", ".less",
		".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".mp3", ".mp4", ".webm", ".ogg", ".wav", ".m4a", ".m4v",
		".zip", ".rar", ".7z", ".tar", ".gz",
		".json", ".xml", ".csv", ".map",
		".txt", ".md", ".markdown", ".yaml", ".yml", ".toml", ".ini",
	}

	if i := strings.IndexAny(rawURL, "?#"); i != -1 {
		rawURL = rawURL[:i]
	}

	ext := strings.ToLower(path.Ext(rawURL))
	for _, staticExt := range staticExts {
		if ext == staticExt {
			return true
		}
	}
	return false
}

// Helper functions for marshaling request parameters
func marshalHeaders(headers map[string]string) string {
	if headers == nil {
		return "{}"
	}
	headerStr := "{"
	for k, v := range headers {
		headerStr += fmt.Sprintf("'%s': '%s',", k, v)
	}
	headerStr += "}"
	return headerStr
}

func marshalBody(body *string) string {
	if body == nil || *body == "" {
		return "null"
	}
	return *body
}
