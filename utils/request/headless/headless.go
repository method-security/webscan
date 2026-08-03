package headless

import (
	// Standard
	"context"
	"fmt"
	stdlog "log"
	"os"
	"strings"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	standardhelpers "github.com/Method-Security/webscan/utils/request/standard/helpers"

	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	useragent "github.com/Method-Security/webscan/utils/useragent"

	// External
	rod "github.com/go-rod/rod"
	launcher "github.com/go-rod/rod/lib/launcher"
	proto "github.com/go-rod/rod/lib/proto"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// InitializeBrowser starts a headless browser instance and establishes connection.
// If a browser path is specified and exists, it uses that binary. Otherwise it
// falls back to rod's auto-download, which fetches a compatible Chromium to ~/.cache/rod/browser/.
func (b *Requester) InitializeBrowser(ctx context.Context) error {
	log := svc1log.FromContext(ctx)

	var binPath string
	if b.PathToBrowser != nil && *b.PathToBrowser != "" {
		if _, err := os.Stat(*b.PathToBrowser); err == nil {
			log.Info("Using specified browser binary", svc1log.SafeParam("path", *b.PathToBrowser))
			binPath = *b.PathToBrowser
		} else {
			log.Warn("Specified browser path not found, falling back to rod auto-download",
				svc1log.SafeParam("path", *b.PathToBrowser))
		}
	} else {
		log.Info("No browser path specified, rod will auto-detect or download Chromium")
	}

	// When no valid binary is available, resolve (and possibly download) one
	// ourselves so that download progress goes to stderr instead of stdout.
	// Uses a 5-minute timeout so a first-time Chromium download isn't killed
	// by the per-request timeout carried in ctx.
	if binPath == "" {
		dlCtx, dlCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer dlCancel()

		browser := launcher.NewBrowser()
		browser.Logger = stdlog.New(os.Stderr, "[launcher.Browser]", stdlog.LstdFlags)
		browser.Context = dlCtx

		resolved, err := browser.Get()
		if err != nil {
			return fmt.Errorf("browser resolution failed: %v", err)
		}
		binPath = resolved
	}

	launchCtx, launchCancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer launchCancel()

	launch := launcher.New().Headless(true).Bin(binPath).NoSandbox(true).Context(launchCtx)
	if proxyServer := b.proxyServer(); proxyServer != "" {
		log.Info("Using headless browser proxy", svc1log.SafeParam("proxy", proxyServer))
		launch.Proxy(proxyServer)
	}
	browserURL, err := launch.Launch()
	if err != nil {
		return fmt.Errorf("browser launch failed: %v", err)
	}

	b.Browser = rod.New().ControlURL(browserURL).Context(ctx)
	err = b.Browser.Connect()
	if err != nil {
		return fmt.Errorf("browser connection failed: %v", err)
	}
	b.ownsBrowser = true

	return nil
}

// PageMetadata carries headless-capture metadata that is not part of the wire
// HttpResponse but is useful to downstream callers (e.g. the <title> tag).
type PageMetadata struct {
	HtmlTitle string
}

// SendRequest navigates to a URL using the headless browser and captures the response
func (b *Requester) SendRequest(ctx context.Context, config common.SendHttpRequestConfig) (common.HttpRequestResponse, error) {
	log := svc1log.FromContext(ctx)
	attempts := headlessCaptureAttempts(config.Request.Method)
	var lastReport common.HttpRequestResponse
	var lastErr error

	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			if !sleepBeforeHeadlessRetry(ctx, attempt) {
				break
			}
		}

		report, err := b.sendRequestOnce(ctx, config)
		if err == nil {
			return report, nil
		}

		lastReport = report
		lastErr = err
		if attempt == attempts || !IsTransientHeadlessError(err) || ctx.Err() != nil {
			return report, err
		}

		log.Warn("Retrying transient headless capture failure",
			svc1log.SafeParam("attempt", attempt+1),
			svc1log.SafeParam("maxAttempts", attempts),
			svc1log.SafeParam("error", cleanErrMsg(err)))
		b.restartOwnedBrowser(ctx, cleanErrMsg(err))
	}

	return lastReport, lastErr
}

// SendRequestWithScreenshot performs one headless navigation and captures both
// the HTTP response artifact and a screenshot from the same stabilized page.
// The returned PageMetadata carries fields harvested from the live DOM
// (e.g. <title>) that are not part of the HttpResponse contract.
func (b *Requester) SendRequestWithScreenshot(ctx context.Context, config common.SendHttpRequestConfig) (common.HttpRequestResponse, []byte, PageMetadata, error) {
	return b.sendRequestWithArtifacts(ctx, config, true)
}

// SendRequestWithMetadata performs one headless navigation and returns page
// metadata without paying the screenshot capture cost.
func (b *Requester) SendRequestWithMetadata(ctx context.Context, config common.SendHttpRequestConfig) (common.HttpRequestResponse, PageMetadata, error) {
	report, _, metadata, err := b.sendRequestWithArtifacts(ctx, config, false)
	return report, metadata, err
}

func (b *Requester) sendRequestWithArtifacts(ctx context.Context, config common.SendHttpRequestConfig, captureScreenshot bool) (common.HttpRequestResponse, []byte, PageMetadata, error) {
	log := svc1log.FromContext(ctx)
	attempts := headlessCaptureAttempts(config.Request.Method)
	var lastReport common.HttpRequestResponse
	var lastScreenshot []byte
	var lastMetadata PageMetadata
	var lastErr error

	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			if !sleepBeforeHeadlessRetry(ctx, attempt) {
				break
			}
		}

		report, screenshot, metadata, err := b.sendRequestWithArtifactsOnce(ctx, config, captureScreenshot)
		if err == nil {
			return report, screenshot, metadata, nil
		}

		lastReport = report
		lastScreenshot = screenshot
		lastMetadata = metadata
		lastErr = err
		if attempt == attempts || !IsTransientHeadlessError(err) || ctx.Err() != nil {
			return report, screenshot, metadata, err
		}

		log.Warn("Retrying transient headless capture failure",
			svc1log.SafeParam("attempt", attempt+1),
			svc1log.SafeParam("maxAttempts", attempts),
			svc1log.SafeParam("error", cleanErrMsg(err)))
		b.restartOwnedBrowser(ctx, cleanErrMsg(err))
	}

	return lastReport, lastScreenshot, lastMetadata, lastErr
}

func (b *Requester) sendRequestOnce(ctx context.Context, config common.SendHttpRequestConfig) (common.HttpRequestResponse, error) {
	// Discard PageMetadata for the non-screenshot path.
	report, _, _, err := b.sendRequestWithArtifactsOnce(ctx, config, false)
	return report, err
}

func (b *Requester) sendRequestWithArtifactsOnce(ctx context.Context, config common.SendHttpRequestConfig, captureScreenshot bool) (common.HttpRequestResponse, []byte, PageMetadata, error) {
	// =========================================================================================
	// SETUP
	// =========================================================================================
	log := svc1log.FromContext(ctx)

	report := common.HttpRequestResponse{Request: config.Request}
	var screenshot []byte
	var metadata PageMetadata

	constructedURL, err := standardhelpers.ConstructURL(ctx, config.Request)
	if err != nil {
		return report, screenshot, metadata, fmt.Errorf("URL construction failed: %v", err)
	}
	log.Info("Requesting", svc1log.SafeParam("url", *constructedURL))

	// Initialize browser if not already done
	if b.Browser == nil {
		if err := b.InitializeBrowser(ctx); err != nil {
			return report, screenshot, metadata, fmt.Errorf("browser initialization failed: %v", err) // Do not change, DD Metric is based on this error message
		}
		log.Info("Connected to browser")
	}

	// Configure TLS verification (must run even for pre-initialized browsers)
	if !config.VerifyTls {
		err = b.Browser.IgnoreCertErrors(true)
		if err != nil {
			log.Warn("Failed to disable certificate error checking", svc1log.SafeParam("error", err.Error()))
			return report, screenshot, metadata, fmt.Errorf("failed to disable certificate error checking: %v", err)
		}
		log.Info("Certificate error checking disabled")
	}

	// =========================================================================================
	// REQUEST EXECUTION
	// =========================================================================================
	var (
		once              sync.Once
		requestComplete   = make(chan struct{})
		browsersErr       = make(chan error, 1)
		redirectChain     = []string{*constructedURL}
		redirectChainMu   sync.Mutex
		browserErr        error
		navigationErr     error
		statusCode        int
		capturedHtmlTitle string
	)

	// Set the request sent timestamp
	sentAt := time.Now()
	config.Request.SentAt = sentAt

	if err := rod.Try(func() {
		// Create new page
		page, err := b.Browser.Page(proto.TargetCreateTarget{})
		if err != nil {
			browsersErr <- fmt.Errorf("failed to create page: %v", err)
			return
		}

		defer func() {
			if page != nil {
				_ = page.Close()
			}
		}()

		// Configure page timeout (includes DOM stabilization time)
		pageTimeout := time.Duration(config.Timeout+b.MinDOMStabalizeTimeSeconds) * time.Second
		page = page.Context(ctx).Timeout(pageTimeout)
		log.Info("Set page timeout",
			svc1log.SafeParam("configTimeout", config.Timeout),
			svc1log.SafeParam("domStabilizeTime", b.MinDOMStabalizeTimeSeconds),
			svc1log.SafeParam("totalPageTimeout", int(pageTimeout.Seconds())))

		// Apply user-agent override only when an explicit non-random preset was
		// supplied. We never override on RANDOM/empty because every browser
		// signal beyond the UA string (navigator.platform, client hints, JS
		// runtime) still identifies as Chromium; a mismatched UA string would
		// be an obvious fingerprint tell.
		if config.UserAgent != "" && config.UserAgent != common.UserAgentPresetRandom {
			uaString := useragent.Resolve(config.UserAgent)
			if uaErr := page.SetUserAgent(&proto.NetworkSetUserAgentOverride{UserAgent: uaString}); uaErr != nil {
				log.Warn("Failed to set user-agent override", svc1log.SafeParam("error", uaErr.Error()))
			} else {
				log.Info("Set user-agent override", svc1log.SafeParam("preset", string(config.UserAgent)))
			}
		}

		// Apply caller-supplied request context (headers, cookies, web storage)
		// before navigation so authenticated headless crawls behave like the
		// standard transport. Console capture is started here so messages emitted
		// during page load are recorded.
		applyPageContext(page, *constructedURL, config, log)
		console := startConsoleCapture(page, config, log)

		// Setup request monitoring and navigate
		headerCapture := setupHeaderInterception(page, log)
		handleNavigation(ctx, page, &redirectChain, &redirectChainMu, requestComplete, &once, config.MaxRedirects, browsersErr)

		navigationErr = performNavigation(ctx, page, constructedURL, config)
		if navigationErr != nil {
			log.Info("Unexpected navigation error, but continuing to extract data anyway", svc1log.SafeParam("error", cleanErrMsg(navigationErr)))
		}

		// Wait for navigation completion or timeout
		select {
		case err := <-browsersErr:
			if err != nil {
				log.Error("Redirect error occurred", svc1log.SafeParam("error", err.Error()))
				browserErr = err
			} else {
				log.Error("Redirect error occurred", svc1log.SafeParam("error", "unknown redirect error"))
				browserErr = fmt.Errorf("unknown redirect error")
			}
			return
		case <-requestComplete:
			redirectChainMu.Lock()
			chain := strings.Join(redirectChain, " -> ")
			redirectChainMu.Unlock()
			log.Info("Request complete, redirect chain", svc1log.SafeParam("chain", chain))
			select {
			case err := <-browsersErr:
				if err != nil {
					log.Error("Redirect error occurred", svc1log.SafeParam("error", err.Error()))
					browserErr = err
				}
			default:
			}
		case <-ctx.Done():
			redirectChainMu.Lock()
			chain := strings.Join(redirectChain, " -> ")
			redirectChainMu.Unlock()
			if ctx.Err() == context.DeadlineExceeded {
				logParams := []svc1log.Param{
					svc1log.SafeParam("url", *constructedURL),
					svc1log.SafeParam("timeout", config.Timeout),
					svc1log.SafeParam("redirectChain", chain),
				}
				if navigationErr != nil {
					logParams = append(logParams, svc1log.SafeParam("navigationError", cleanErrMsg(navigationErr)))
				}
				log.Warn("Request timed out", logParams...)
				browserErr = fmt.Errorf("request timeout after %d seconds", config.Timeout)
			} else {
				logParams := []svc1log.Param{
					svc1log.SafeParam("url", *constructedURL),
					svc1log.SafeParam("error", ctx.Err()),
				}
				if navigationErr != nil {
					logParams = append(logParams, svc1log.SafeParam("navigationError", cleanErrMsg(navigationErr)))
				}
				log.Warn("Request cancelled", logParams...)
				browserErr = fmt.Errorf("request cancelled: %v", ctx.Err())
			}
			return
		}

		// =========================================================================================
		// RESPONSE PROCESSING
		// =========================================================================================

		// Wait for page to fully load and for client-side routers/auth flows to
		// settle before reading finalURL or HTML.
		err = waitForPageLoad(page, b.MinDOMStabalizeTimeSeconds, log)
		if err != nil {
			log.Warn("Page stabilization warning", svc1log.SafeParam("error", err.Error()))
		}
		select {
		case err := <-browsersErr:
			if err != nil {
				log.Error("Redirect error occurred during stabilization", svc1log.SafeParam("error", err.Error()))
				browserErr = err
				return
			}
		default:
		}

		// Batch JavaScript evaluations for better performance
		batchJS := `() => {
			return {
				finalURL: window.location.href,
				readyState: document.readyState,
				isErrorPage: window.location.href.startsWith('chrome-error://'),
				statusCode: window.lastResponseStatus || 0,
				performanceStatus: (() => {
					const entries = performance.getEntriesByType('navigation');
					return entries.length > 0 && entries[0].responseStatus ? entries[0].responseStatus : 0;
				})(),
				htmlTitle: document.title || ""
			};
		}`

		batchResult, err := page.Eval(batchJS)
		var finalURL string
		var isErrorPage bool
		var htmlTitle string

		if err != nil {
			log.Warn("Failed to execute batch JavaScript, falling back to individual calls", svc1log.SafeParam("error", err.Error()))
			// Fallback to individual calls
			finalURL, _ = safeEval(page, `() => window.location.href`)
			readyState, err := safeEval(page, `() => document.readyState`)
			if err == nil && readyState == "complete" {
				statusCode = 200
			} else {
				statusCode = getStatusCodeFromPage(page)
				if statusCode == 0 && browserErr == nil && navigationErr == nil {
					statusCode = 200
				}
			}
			isErrorPage = isChromeErrorPage(page)
			htmlTitle, _ = safeEval(page, `() => document.title || ""`)
		} else {
			// Parse batch results
			resultMap := batchResult.Value.Map()
			if resultMap != nil {
				if val, ok := resultMap["finalURL"]; ok {
					finalURL = val.Str()
				}
				if val, ok := resultMap["readyState"]; ok && val.Str() == "complete" {
					statusCode = 200
				}
				if val, ok := resultMap["isErrorPage"]; ok {
					isErrorPage = val.Bool()
				}
				if val, ok := resultMap["statusCode"]; ok && val.Int() > 0 {
					statusCode = val.Int()
				} else if val, ok := resultMap["performanceStatus"]; ok && val.Int() > 0 {
					statusCode = val.Int()
				}
				if statusCode == 0 && browserErr == nil && navigationErr == nil {
					statusCode = 200 // Default for successful navigation
				}
				if val, ok := resultMap["htmlTitle"]; ok {
					htmlTitle = val.Str()
				}
			}
		}

		// Redirect Chain: fold the post-render location (window.location.href)
		// into the chain as the terminal entry. handleNavigation only records
		// HTTP 3xx redirects, so this is what captures client-side/JS/meta-refresh
		// redirects — i.e. where the browser actually ended up, including when it
		// lands on a static asset (e.g. a redirect to a PDF) or bounces back to an
		// earlier URL (A->B->A). Guard against internal browser URLs (about:blank,
		// chrome-error://, ...) so they never become the terminal entry consumers
		// read as the final URL.
		if finalURL != "" && !isInternalBrowserURL(finalURL) {
			redirectChainMu.Lock()
			added, redirectErr := appendRedirectURLLocked(&redirectChain, finalURL, config.MaxRedirects)
			if redirectErr != nil {
				redirectChainMu.Unlock()
				browserErr = redirectErr
				return
			}
			if added {
				chain := strings.Join(redirectChain, " -> ")
				redirectChainMu.Unlock()
				log.Info("Adding final URL to chain", svc1log.SafeParam("url", finalURL))
				log.Info("Updated redirect chain", svc1log.SafeParam("chain", chain))
			} else {
				redirectChainMu.Unlock()
			}
		}
		redirectChainMu.Lock()
		redirectChain = filterRedirectChain(redirectChain)
		responseRedirectChain := append([]string(nil), redirectChain...)
		redirectChainMu.Unlock()

		log.Info("Final URL", svc1log.SafeParam("url", finalURL))

		// Capture htmlTitle for outer scope (returned to caller via PageMetadata).
		capturedHtmlTitle = htmlTitle

		// Check if Chrome error page using batch result
		if isErrorPage {
			log.Warn("Detected Chrome error page, treating as navigation failure")
			if navigationErr != nil {
				browserErr = navigationErr
			} else {
				browserErr = fmt.Errorf("navigation failed: Chrome error page detected")
			}
		}
		if browserErr == nil && navigationErr != nil && statusCode == 0 {
			browserErr = navigationErr
		}

		// Use the latest captured main-document headers after stabilization so
		// headers, finalURL, and HTML describe the same terminal document.
		responseHeaders := getResponseHeaders(ctx, page, headerCapture)

		// Extract response body
		var responseBody []byte
		if browserErr == nil && statusCode >= 200 && statusCode < 300 {
			htmlContent, htmlErr := page.HTML()
			htmlCaptured := false
			if htmlErr != nil {
				errStr := htmlErr.Error()
				if strings.Contains(errStr, "Execution context was destroyed") || strings.Contains(errStr, "-32000") {
					log.Info("Execution context destroyed while getting HTML content (likely due to redirect)")
				} else {
					log.Error("Failed to get HTML content", svc1log.SafeParam("error", htmlErr.Error()))
				}
				responseBody = nil
				responseHeaders = cloneHeadersWithContentType(responseHeaders, "text/html")
			} else {
				htmlCaptured = true
				responseBody = []byte(htmlContent)
				responseHeaders = cloneHeadersWithoutContentEncoding(responseHeaders)
			}
			if shouldLoadStaticResource(htmlContent, *constructedURL, finalURL) {
				resourceURL := finalURL
				if resourceURL == "" || isInternalBrowserURL(resourceURL) {
					resourceURL = *constructedURL
				}
				loadedBody, loadedHeaders, loadedStatusCode, err := loadNetworkResourceBody(page, resourceURL)
				if err == nil && isValidStaticResourceBody(loadedBody) {
					responseBody = loadedBody
					responseHeaders = headersForLoadedStaticResource(responseHeaders, loadedHeaders, loadedBody)
					if loadedStatusCode > 0 {
						statusCode = loadedStatusCode
					}
				} else if err != nil {
					log.Info("Failed to load static resource body, falling back to page HTML", svc1log.SafeParam("error", cleanErrMsg(err)))
					if !htmlCaptured {
						browserErr = fmt.Errorf("failed to capture static resource body: HTML extraction failed (%s); static resource load failed (%s)", cleanErrMsg(htmlErr), cleanErrMsg(err))
						return
					}
					responseHeaders = cloneHeadersWithContentType(responseHeaders, "text/html")
				} else {
					log.Info("Loaded static resource did not validate, falling back to page HTML")
					if !htmlCaptured {
						browserErr = fmt.Errorf("failed to capture static resource body: HTML extraction failed (%s); loaded static resource did not validate as binary", cleanErrMsg(htmlErr))
						return
					}
					responseHeaders = cloneHeadersWithContentType(responseHeaders, "text/html")
				}
			}
		}
		// Build final response
		response := requesthelpers.CreateHTTPResponseFromBytes(
			statusCode,
			responseRedirectChain,
			responseHeaders,
			responseBody,
		)

		// Attach captured console logs and page cookies when requested.
		if console != nil {
			response.ConsoleLogs = console.snapshot()
		}
		if cookies := collectCookies(page, config, log); len(cookies) > 0 {
			response.Cookies = cookies
		}

		report.Response = &response

		if captureScreenshot && browserErr == nil {
			log.Info("Capturing screenshot from existing headless page")
			img, screenshotErr := page.Screenshot(true, &proto.PageCaptureScreenshot{
				Format: proto.PageCaptureScreenshotFormatPng,
			})
			if screenshotErr != nil {
				log.Error("Failed to capture screenshot from existing page", svc1log.SafeParam("url", *constructedURL), svc1log.SafeParam("error", cleanErrMsg(screenshotErr)))
				browserErr = fmt.Errorf("screenshot capture failed: %s", cleanErrMsg(screenshotErr))
			} else {
				screenshot = img
				log.Info("Screenshot captured from existing headless page")
			}
		}
	}); err != nil {
		log.Error("Browser operation failed with panic", svc1log.SafeParam("error", cleanErrMsg(err)))
		if browserErr == nil {
			browserErr = fmt.Errorf("browser operation panicked: %w", err)
		}
	}

	// Handle navigation errors
	var finalErr error
	if browserErr != nil {
		log.Error("Navigation failed", svc1log.SafeParam("url", *constructedURL), svc1log.SafeParam("error", browserErr.Error()))
		finalErr = fmt.Errorf("headless capture failed: %s", cleanErrMsg(browserErr))
	}

	// Check for cross-domain redirect after navigation completes
	redirectChainMu.Lock()
	finalRedirectChain := append([]string(nil), redirectChain...)
	redirectChainMu.Unlock()
	if config.IgnoreCrossDomainRedirects && len(finalRedirectChain) > 1 {
		originalURL := finalRedirectChain[0]
		finalURL := finalRedirectChain[len(finalRedirectChain)-1]
		if isCrossDomainRedirect(originalURL, finalURL) {
			log.Info("Cross-domain redirect detected in redirect chain", svc1log.SafeParam("from", originalURL), svc1log.SafeParam("to", finalURL))
			return common.HttpRequestResponse{Request: config.Request}, screenshot, metadata, fmt.Errorf("cross-domain redirect blocked: %s -> %s", originalURL, finalURL)
		}
	}

	// Surface metadata captured inside the closure scope.
	metadata.HtmlTitle = capturedHtmlTitle

	return report, screenshot, metadata, finalErr
}
