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
	utils "github.com/Method-Security/webscan/utils"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

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
	browserURL, err := launch.Launch()
	if err != nil {
		return fmt.Errorf("browser launch failed: %v", err)
	}

	b.Browser = rod.New().ControlURL(browserURL).Context(ctx)
	err = b.Browser.Connect()
	if err != nil {
		return fmt.Errorf("browser connection failed: %v", err)
	}

	return nil
}

// SendRequest navigates to a URL using the headless browser and captures the response
func (b *Requester) SendRequest(ctx context.Context, config common.SendHttpRequestConfig) (common.HttpRequestResponse, error) {
	// =========================================================================================
	// SETUP
	// =========================================================================================
	log := svc1log.FromContext(ctx)

	report := common.HttpRequestResponse{Request: config.Request}

	constructedURL, err := standardhelpers.ConstructURL(ctx, config.Request)
	if err != nil {
		return report, fmt.Errorf("URL construction failed: %v", err)
	}
	log.Info("Requesting", svc1log.SafeParam("url", *constructedURL))

	// Initialize browser if not already done
	if b.Browser == nil {
		if err := b.InitializeBrowser(ctx); err != nil {
			return report, fmt.Errorf("browser initialization failed: %v", err) // Do not change, DD Metric is based on this error message
		}
		log.Info("Connected to browser")
	}

	// Configure TLS verification (must run even for pre-initialized browsers)
	if !config.VerifyTls {
		err = b.Browser.IgnoreCertErrors(true)
		if err != nil {
			log.Warn("Failed to disable certificate error checking", svc1log.SafeParam("error", err.Error()))
			return report, fmt.Errorf("failed to disable certificate error checking: %v", err)
		}
		log.Info("Certificate error checking disabled")
	}

	// =========================================================================================
	// REQUEST EXECUTION
	// =========================================================================================
	var (
		once            sync.Once
		requestComplete = make(chan struct{})
		browsersErr     = make(chan error, 1)
		redirectChain   = []string{*constructedURL}
		browserErr      error
		statusCode      int
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

		// Setup request monitoring and navigate
		headerCapture := setupHeaderInterception(page)
		handleNavigation(ctx, page, &redirectChain, requestComplete, &once, config.MaxRedirects, config.IgnoreCrossDomainRedirects, browsersErr)

		navErr := performNavigation(ctx, page, constructedURL, config)
		if navErr != nil {
			log.Info("Unexpected navigation error, but continuing to extract data anyway", svc1log.SafeParam("error", cleanErrMsg(navErr)))
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
			log.Info("Request complete, redirect chain", svc1log.SafeParam("chain", strings.Join(redirectChain, " -> ")))
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				log.Warn("Request timed out",
					svc1log.SafeParam("url", *constructedURL),
					svc1log.SafeParam("timeout", config.Timeout),
					svc1log.SafeParam("redirectChain", strings.Join(redirectChain, " -> ")))
				browserErr = fmt.Errorf("request timeout after %d seconds", config.Timeout)
			} else {
				log.Warn("Request cancelled",
					svc1log.SafeParam("url", *constructedURL),
					svc1log.SafeParam("error", ctx.Err()))
				browserErr = fmt.Errorf("request cancelled: %v", ctx.Err())
			}
			return
		}

		// =========================================================================================
		// RESPONSE PROCESSING
		// =========================================================================================

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
				})()
			};
		}`

		batchResult, err := page.Eval(batchJS)
		var finalURL string
		var responseHeaders map[string][]string
		var isErrorPage bool

		if err != nil {
			log.Warn("Failed to execute batch JavaScript, falling back to individual calls", svc1log.SafeParam("error", err.Error()))
			// Fallback to individual calls
			finalURL, _ = safeEval(page, `() => window.location.href`)
			readyState, err := safeEval(page, `() => document.readyState`)
			if err == nil && readyState == "complete" {
				statusCode = 200
			} else {
				statusCode = getStatusCodeFromPage(page)
				if statusCode == 0 && browserErr == nil {
					statusCode = 200
				}
			}
			isErrorPage = isChromeErrorPage(page)
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
				if statusCode == 0 && browserErr == nil {
					statusCode = 200 // Default for successful navigation
				}
			}
		}

		// Always use the reliable headers extraction method
		responseHeaders = getResponseHeaders(ctx, page, headerCapture)

		// Redirect Chain
		if finalURL != "" && !utils.IsStaticAsset(finalURL) {
			exists := false
			for _, url := range redirectChain {
				if url == finalURL {
					exists = true
					break
				}
			}
			if !exists {
				redirectChain = append(redirectChain, finalURL)
				log.Info("Adding final URL to chain", svc1log.SafeParam("url", finalURL))
				log.Info("Updated redirect chain", svc1log.SafeParam("chain", strings.Join(redirectChain, " -> ")))
			}
		}
		redirectChain = filterRedirectChain(redirectChain)

		// Wait for page to fully load (optimized)
		err = waitForPageLoad(page, b.MinDOMStabalizeTimeSeconds, log)
		if err != nil {
			log.Warn("Page stabilization warning", svc1log.SafeParam("error", err.Error()))
		}

		log.Info("Final URL", svc1log.SafeParam("url", finalURL))

		// Check if Chrome error page using batch result
		if isErrorPage {
			log.Warn("Detected Chrome error page, treating as navigation failure")
			browserErr = fmt.Errorf("navigation failed: Chrome error page detected")
		}

		// Extract response body
		var responseBody string
		if statusCode >= 200 && statusCode < 300 {
			htmlContent, err := page.HTML()
			if err != nil {
				errStr := err.Error()
				if strings.Contains(errStr, "Execution context was destroyed") || strings.Contains(errStr, "-32000") {
					log.Info("Execution context destroyed while getting HTML content (likely due to redirect)")
				} else {
					log.Error("Failed to get HTML content", svc1log.SafeParam("error", err.Error()))
				}
				responseBody = ""
			} else {
				responseBody = htmlContent
			}
		}
		// Build final response
		response := requesthelpers.CreateHTTPResponse(
			statusCode,
			redirectChain,
			responseHeaders,
			responseBody,
		)
		report.Response = &response
	}); err != nil {
		log.Error("Browser operation failed with panic", svc1log.SafeParam("error", err.Error()))
		if browserErr == nil {
			browserErr = fmt.Errorf("browser operation panicked: %v", err)
		}
	}

	// Handle navigation errors
	var finalErr error
	if browserErr != nil {
		log.Error("Navigation failed", svc1log.SafeParam("url", *constructedURL), svc1log.SafeParam("error", browserErr.Error()))
		finalErr = fmt.Errorf("headless capture failed: %s", cleanErrMsg(browserErr))
	}

	return report, finalErr
}
