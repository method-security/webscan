package discoverpage

import (
	// Standard
	"context"
	"fmt"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"
	"github.com/Method-Security/webscan/utils"

	// Internal
	internalcommon "github.com/Method-Security/webscan/internal/common"
	discoverpagehelpers "github.com/Method-Security/webscan/internal/discover/page/helpers"

	//Utils
	headless "github.com/Method-Security/webscan/utils/request/headless"
	browserbase "github.com/Method-Security/webscan/utils/request/headless/browserbase"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func getHTTPRequestConfig(baseURL string, path string, queryParams map[string]string, config discover.DiscoverPageConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params: &common.HttpRequestParams{
			Query:   queryParams,
			Headers: requesthelpers.BuildAuthHeaders(config.Headers, config.Cookies),
		},
	}
	// Capture console logs and page cookies on browser-backed captures to mirror
	// the rendered-page output contract; the standard transport ignores both flags.
	captureBrowserArtifacts := config.RequestMethod == common.RequestMethodHeadless || config.RequestMethod == common.RequestMethodBrowserbase
	return common.SendHttpRequestConfig{
		Request:                    &request,
		MaxRedirects:               config.MaxRedirects,
		VerifyTls:                  config.VerifyTls,
		Timeout:                    config.Timeout,
		IgnoreCrossDomainRedirects: config.IgnoreCrossDomainRedirects,
		UserAgent:                  config.UserAgent,
		RequestMethod:              config.RequestMethod,
		HeadlessConfig:             config.HeadlessConfig,
		BrowserbaseConfig:          config.BrowserbaseConfig,
		BrowserbaseSecrets:         browserbaseSecrets,
		Cookies:                    config.Cookies,
		LocalStorage:               config.LocalStorage,
		SessionStorage:             config.SessionStorage,
		CaptureConsoleLogs:         &captureBrowserArtifacts,
		CaptureCookies:             &captureBrowserArtifacts,
	}
}

// PerformPageCapture determines whether to perform a screenshot or HTML capture based on the takeScreenshot parameter
func PerformPageCapture(
	ctx context.Context,
	config discover.DiscoverPageConfig,
	browserbaseSecrets *common.BrowserbaseRequestSecrets,
) *discover.DiscoverPageReport {
	log := svc1log.FromContext(ctx)

	// Initialize report
	result := discover.DiscoverPageResult{}
	errors := []string{}
	report := discover.DiscoverPageReport{Config: &config, Result: &result}

	// Split target
	baseURL, path, queryParams, err := requesthelpers.SplitTargetURL(config.Target)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return &report
	}

	// Get request config
	requestConfig := getHTTPRequestConfig(baseURL, path, queryParams, config, browserbaseSecrets)
	requesthelpers.ApplyProxySettings(ctx, &requestConfig)

	// Perform HTML capture
	log.Info("Performing HTML capture", svc1log.SafeParam("target", config.Target))
	var httpRequestResponse *common.HttpRequestResponse
	if config.RequestMethod == common.RequestMethodHeadless {
		if config.Screenshot {
			log.Info("Performing combined HEADLESS screenshot and HTML capture", svc1log.SafeParam("target", config.Target))
		} else {
			log.Info("Performing HEADLESS HTML capture with metadata", svc1log.SafeParam("target", config.Target))
		}
		requestCtx, requestCancel := context.WithTimeout(ctx, time.Duration(requestConfig.Timeout)*time.Second)
		defer requestCancel()

		requester := headless.NewRequester(config.Timeout, config.HeadlessConfig)
		requester.SetProxyConfigFromRequest(requestConfig)
		var response common.HttpRequestResponse
		var img []byte
		var metadata headless.PageMetadata
		var err error
		if config.Screenshot {
			response, img, metadata, err = requester.SendRequestWithScreenshot(requestCtx, requestConfig)
		} else {
			response, metadata, err = requester.SendRequestWithMetadata(requestCtx, requestConfig)
		}
		httpRequestResponse = &response
		if len(img) > 0 {
			result.Screenshot = &img
			// Perceptual hash (gowitness parity, AITF-139) — best-effort.
			if phash, phashErr := discoverpagehelpers.ComputeScreenshotPerceptualHash(img); phashErr == nil {
				result.ScreenshotPerceptualHash = &phash
			} else {
				log.Warn("Failed to compute screenshot perceptual hash", svc1log.SafeParam("error", phashErr.Error()))
			}
		}
		if metadata.HtmlTitle != "" {
			title := metadata.HtmlTitle
			result.HtmlTitle = &title
		}
		if err != nil {
			errors = append(errors, err.Error())
			if response.Response == nil {
				report.Errors = errors
				return &report
			}
		}
	} else if config.RequestMethod == common.RequestMethodBrowserbase {
		log.Info("Performing BROWSERBASE HTML capture with metadata", svc1log.SafeParam("target", config.Target))
		if requesthelpers.HasProxyConfig(requestConfig) {
			errors = append(errors, "browserbase capture does not support --http-proxy or --socks-proxy; use Browserbase proxy options instead")
			report.Errors = errors
			return &report
		}
		requestCtx, requestCancel := context.WithTimeout(ctx, time.Duration(requestConfig.Timeout)*time.Second)
		defer requestCancel()

		client := browserbase.NewBrowserbaseClient(config.BrowserbaseConfig, browserbaseSecrets)
		requester := browserbase.NewBrowserbaseRequester(ctx, *client, config.Timeout, config.HeadlessConfig.MinDomStabalizeTime)
		if requester == nil {
			errors = append(errors, "failed to create browserbase capturer")
			report.Errors = errors
			return &report
		}
		defer func() {
			if closeErr := requester.Close(ctx); closeErr != nil {
				log.Warn("Failed to close browserbase session", svc1log.SafeParam("error", closeErr.Error()))
			}
		}()

		response, metadata, err := requester.SendRequestWithMetadata(requestCtx, requestConfig)
		httpRequestResponse = &response
		if metadata.HtmlTitle != "" {
			title := metadata.HtmlTitle
			result.HtmlTitle = &title
		}
		if err != nil {
			errors = append(errors, err.Error())
			if response.Response == nil {
				report.Errors = errors
				return &report
			}
		}
	} else {
		var err error
		httpRequestResponse, err = discoverpagehelpers.PerformHTMLPageCapture(ctx, &requestConfig)
		if err != nil {
			errors = append(errors, err.Error())
			report.Errors = errors
			return &report
		}
	}

	if result.HtmlTitle == nil && httpRequestResponse != nil && httpRequestResponse.Response != nil && httpRequestResponse.Response.ResponseBody != nil {
		if bodyStr := requesthelpers.GetResponseBodyStringFromBodyStruct(httpRequestResponse.Response.ResponseBody); bodyStr != nil {
			if htmlTitle := discoverpagehelpers.ExtractHTMLTitle(*bodyStr); htmlTitle != "" {
				result.HtmlTitle = &htmlTitle
			}
		}
	}

	// Check if response code is in the allowed list
	log.Info("Checking response code", svc1log.SafeParam("target", config.Target))
	validCodes, err := utils.ParseResponseCodes(config.ResponseCodes)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return &report
	}

	// Check if response is valid and add request if status code is allowed
	if httpRequestResponse != nil && httpRequestResponse.Response != nil && httpRequestResponse.Response.StatusCode != nil {
		if _, exists := validCodes[*httpRequestResponse.Response.StatusCode]; !exists {
			log.Info("Page returned a response code not in the allowed list, skipping",
				svc1log.SafeParam("target", config.Target),
				svc1log.SafeParam("status_code", *httpRequestResponse.Response.StatusCode))
			errors = append(errors, fmt.Sprintf("page %s returned status code %d which is not in the allowed response codes", config.Target, *httpRequestResponse.Response.StatusCode))
		} else {
			result.Request = httpRequestResponse
			result.WafDetection = internalcommon.DetectWaf(httpRequestResponse)
		}
	}

	// Set final errors and return report
	report.Errors = errors
	return &report
}
