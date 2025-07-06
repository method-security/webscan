package headless

import (
	// Standard
	"context"
	"fmt"
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

// InitializeBrowser starts a headless browser instance and establishes connection
func (b *Requester) InitializeBrowser(ctx context.Context) error {
	launch := launcher.New().Headless(true)
	if b.PathToBrowser != nil && *b.PathToBrowser != "" {
		launch = launch.Bin(*b.PathToBrowser)
	}

	browserURL, err := launch.Context(ctx).Launch()
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
			return report, fmt.Errorf("browser initialization failed: %v", err)
		}

		// Configure TLS verification
		if !config.VerifyTls {
			err = b.Browser.IgnoreCertErrors(true)
			if err != nil {
				log.Warn("Failed to disable certificate error checking", svc1log.SafeParam("error", err.Error()))
				return report, fmt.Errorf("failed to disable certificate error checking: %v", err)
			} else {
				log.Info("Certificate error checking disabled")
			}
		}
		log.Info("Connected to browser")
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

	rod.Try(func() {
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
		setupHeaderInterception(page)
		handleNavigation(page, &redirectChain, requestComplete, &once, log, config.MaxRedirects, browsersErr)

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

		// Final Url
		finalURL, err := safeEval(page, `() => window.location.href`)
		if err != nil {
			log.Warn("Failed to get final URL", svc1log.SafeParam("error", err.Error()))
			finalURL = ""
		}

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

		// Wait for page to fully load
		err = waitForPageLoad(page, b.MinDOMStabalizeTimeSeconds, log)
		if err != nil {
			log.Warn("Page stabilization warning", svc1log.SafeParam("error", err.Error()))
		}

		log.Info("Final URL", svc1log.SafeParam("url", finalURL))

		// Check if Chrome error page - treat as navigation failure
		if isChromeErrorPage(page) {
			log.Warn("Detected Chrome error page, treating as navigation failure")
			browserErr = fmt.Errorf("navigation failed: Chrome error page detected")
			return
		}

		// Status Code
		readyState, err := safeEval(page, `() => document.readyState`)
		if err == nil && readyState == "complete" {
			statusCode = 200
		} else {
			statusCode = getStatusCodeFromPage(page)
			if statusCode == 0 && browserErr == nil {
				statusCode = 200 // Default for successful navigation
			}
		}

		// Extract response headers and body
		responseHeaders := getResponseHeaders(page, log)
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
	})

	// Handle navigation errors
	var finalErr error
	if browserErr != nil {
		log.Error("Navigation failed", svc1log.SafeParam("url", *constructedURL), svc1log.SafeParam("error", browserErr.Error()))
		finalErr = fmt.Errorf("headless capture failed: %s", cleanErrMsg(browserErr))
	}

	return report, finalErr
}
