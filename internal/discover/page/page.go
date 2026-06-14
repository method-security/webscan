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
	discoverpagehelpers "github.com/Method-Security/webscan/internal/discover/page/helpers"
	//Utils
	headless "github.com/Method-Security/webscan/utils/request/headless"
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
	// Capture console logs and page cookies on headless captures to mirror the
	// rendered-page output contract; the standard transport ignores both flags.
	captureBrowserArtifacts := config.RequestMethod == common.RequestMethodHeadless
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
	sensitiveContentFingerprints *discover.SensitiveContentFingerprints,
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

	// Perform HTML capture
	log.Info("Performing HTML capture", svc1log.SafeParam("target", config.Target))
	var httpRequestResponse *common.HttpRequestResponse
	if config.Screenshot && config.RequestMethod == common.RequestMethodHeadless {
		log.Info("Performing combined HEADLESS screenshot and HTML capture", svc1log.SafeParam("target", config.Target))
		requestCtx, requestCancel := context.WithTimeout(ctx, time.Duration(requestConfig.Timeout)*time.Second)
		defer requestCancel()

		requester := headless.NewRequester(config.Timeout, config.HeadlessConfig)
		response, img, err := requester.SendRequestWithScreenshot(requestCtx, requestConfig)
		httpRequestResponse = &response
		if len(img) > 0 {
			result.Screenshot = &img
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

			// If sensitive content detection is enabled, extract sensitive content from response body
			if config.SensitiveContentDetection && httpRequestResponse.Response.ResponseBody != nil {
				log.Info("Extracting sensitive contents from response body", svc1log.SafeParam("target", config.Target))
				// Use helper function to get response body content
				responseContentPtr := requesthelpers.GetResponseBodyStringFromBodyStruct(httpRequestResponse.Response.ResponseBody)

				if responseContentPtr != nil {
					discoveredSensitiveContents, errs := discoverpagehelpers.ExtractSensitiveContentsFromWebContent(ctx, *responseContentPtr, sensitiveContentFingerprints)
					errors = append(errors, errs...)
					result.SensitiveContents = discoveredSensitiveContents
				}
			}
		}
	}

	// Set final errors and return report
	report.Errors = errors
	return &report
}
