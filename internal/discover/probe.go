package general

import (
	// Standard
	"context"
	"fmt"
	"strings"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/generated/go/discover"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

func createSendHTTPRequestConfig(ctx context.Context, baseURL, path string, queryParams map[string]string, config *discover.DiscoverProbeConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params: &common.HttpRequestParams{
			Query: queryParams,
		},
	}

	sendConfig := common.SendHttpRequestConfig{
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
	}

	// Add proxy settings from context
	requesthelpers.ApplyProxySettings(ctx, &sendConfig)

	return sendConfig
}

// sendRequestWithProtocol attempts to connect to a target using the specified protocol
func sendRequestWithProtocol(ctx context.Context, target string, protocol string, config *discover.DiscoverProbeConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) (*common.HttpRequestResponse, error) {
	sanitizedTarget := requesthelpers.RemoveScheme(target)
	fullURL := protocol + "://" + sanitizedTarget

	baseURL, path, queryParams, err := requesthelpers.SplitTargetURL(fullURL)
	if err != nil {
		return nil, fmt.Errorf("invalid address %s: %v", fullURL, err)
	}

	requestConfig := createSendHTTPRequestConfig(ctx, baseURL, path, queryParams, config, browserbaseSecrets)
	httpRequestResponse, err := request.SendRequest(ctx, requestConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to probe %s - %s", fullURL, err)
	}

	return httpRequestResponse, nil
}

// sendRequests attempts to connect to a target using the specified protocol(s)
// If a specific protocol is set in config, only that protocol is used
// Otherwise, attempts both HTTPS and HTTP protocols for backward compatibility
func sendRequests(ctx context.Context, target string, config *discover.DiscoverProbeConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) ([]*common.HttpRequestResponse, []string) {
	httpRequestResponses := []*common.HttpRequestResponse{}
	var httpResponse, httpsResponse *common.HttpRequestResponse
	var httpErr, httpsErr error

	// Check if a specific protocol is configured
	if config.Protocol != nil {
		switch *config.Protocol {
		case common.WebProtocolHttp:
			// Only try HTTP
			if response, err := sendRequestWithProtocol(ctx, target, "http", config, browserbaseSecrets); err != nil {
				httpErr = err
			} else {
				httpResponse = response
			}
		case common.WebProtocolHttps:
			// Only try HTTPS
			if response, err := sendRequestWithProtocol(ctx, target, "https", config, browserbaseSecrets); err != nil {
				httpsErr = err
			} else {
				httpsResponse = response
			}
		}
	} else {
		// No specific protocol set - maintain existing behavior (try both)
		// Try HTTP request
		if response, err := sendRequestWithProtocol(ctx, target, "http", config, browserbaseSecrets); err != nil {
			httpErr = err
		} else {
			httpResponse = response
		}

		// Try HTTPS request
		if response, err := sendRequestWithProtocol(ctx, target, "https", config, browserbaseSecrets); err != nil {
			httpsErr = err
		} else {
			httpsResponse = response
		}
	}

	var protocolMismatchErr error
	if detectMissMatchedProtocols(ctx, httpResponse) {
		protocolMismatchErr = fmt.Errorf("failed to probe http://%s - response indicates plain HTTP was sent to an HTTPS port", requesthelpers.RemoveScheme(target))
		httpErr = protocolMismatchErr
		httpResponse = nil
	}
	if detectMissMatchedProtocols(ctx, httpsResponse) {
		protocolMismatchErr = fmt.Errorf("failed to probe https://%s - response indicates HTTPS was sent to an HTTP port", requesthelpers.RemoveScheme(target))
		httpsErr = protocolMismatchErr
		httpsResponse = nil
	}

	if httpResponse != nil {
		httpRequestResponses = append(httpRequestResponses, httpResponse)
	}
	if httpsResponse != nil {
		httpRequestResponses = append(httpRequestResponses, httpsResponse)
	}

	// Return errors based on what was attempted
	var errors []string
	if config.Protocol != nil {
		// If specific protocol was set, only return its error if it failed
		if *config.Protocol == common.WebProtocolHttp && httpErr != nil {
			errors = append(errors, httpErr.Error())
		} else if *config.Protocol == common.WebProtocolHttps && httpsErr != nil {
			errors = append(errors, httpsErr.Error())
		}
	} else {
		// If no specific protocol was set, only return errors if both requests failed
		if httpErr != nil && httpsErr != nil {
			errors = append(errors, httpErr.Error(), httpsErr.Error())
		} else if protocolMismatchErr != nil {
			errors = append(errors, protocolMismatchErr.Error())
		}
	}

	return httpRequestResponses, errors
}

// PerformWebProbe performs web probing for the given config and returns a DiscoverProbeReport.
func PerformWebProbe(ctx context.Context, config *discover.DiscoverProbeConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) (*discover.DiscoverProbeReport, error) {
	// Initialize report
	result := discover.DiscoverProbeResult{}
	report := &discover.DiscoverProbeReport{Config: config, Result: &result}
	errors := []string{}

	// Single loop to process all targets
	allResponses := []*common.HttpRequestResponse{}
	for i, target := range config.Targets {
		responses, errs := sendRequests(ctx, target, config, browserbaseSecrets)
		if len(errs) > 0 {
			errors = append(errors, errs...)
		}
		allResponses = append(allResponses, responses...)

		if config.Sleep > 0 && i < len(config.Targets)-1 {
			delay := utils.CalculateDelayWithJitter(config.Sleep, config.Jitter)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				result.Targets = allResponses
				report.Errors = errors
				return report, nil
			}
		}
	}

	result.Targets = allResponses
	report.Errors = errors
	return report, nil
}

var mismatchedProtocolResponsePatterns = []string{
	"the plain http request was sent to https port",
	"plain http request was sent to https port",
	"client sent an http request to an https server",
	"speaking plain http to an ssl-enabled server port",
	"incorrect protocol on port",
}

func detectMissMatchedProtocols(_ context.Context, response *common.HttpRequestResponse) bool {
	if response == nil || response.Response == nil || response.Response.StatusCode == nil || response.Response.ResponseBody == nil {
		return false
	}

	body := requesthelpers.GetResponseBodyStringFromBodyStruct(response.Response.ResponseBody)
	if body == nil {
		return false
	}

	lowerBody := strings.ToLower(*body)
	for _, pattern := range mismatchedProtocolResponsePatterns {
		if strings.Contains(lowerBody, pattern) {
			return true
		}
	}

	return false
}
