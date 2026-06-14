package discoverrequest

import (
	// Standard
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"

	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	standardhelpers "github.com/Method-Security/webscan/utils/request/standard/helpers"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// buildHTTPRequest constructs a common.HttpRequest from the DiscoverRequestConfig.
func buildHTTPRequest(config discover.DiscoverRequestConfig) (*common.HttpRequest, error) {
	baseURL, path, queryParams, err := requesthelpers.SplitTargetURL(config.Target)
	if err != nil {
		return nil, err
	}

	// Build headers map
	var headers map[string][]string
	if config.Headers != nil {
		headers = make(map[string][]string, len(config.Headers))
		for k, v := range config.Headers {
			headers[k] = []string{v}
		}
	}

	// Build body based on priority: JSON > Text > Form
	var body *common.Body
	switch {
	case config.JsonBody != nil && *config.JsonBody != "":
		mimeType := "application/json"
		body = &common.Body{
			Kind: "json",
			Json: &common.JsonBody{
				Data:     *config.JsonBody,
				MimeType: &mimeType,
			},
		}
	case config.TextBody != nil && *config.TextBody != "":
		mimeType := "text/plain"
		body = &common.Body{
			Kind: "text",
			Text: &common.TextBody{
				Value:    *config.TextBody,
				MimeType: &mimeType,
			},
		}
	case len(config.FormData) > 0:
		mimeType := "application/x-www-form-urlencoded"
		body = &common.Body{
			Kind: "form",
			Form: &common.FormBody{
				Fields:   config.FormData,
				MimeType: &mimeType,
			},
		}
	}

	params := &common.HttpRequestParams{
		Query:   queryParams,
		Headers: headers,
		Body:    body,
	}

	request := &common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  config.HttpMethod,
		Params:  params,
	}

	return request, nil
}

// extractTLSCertificates converts x509 certificates to the Fern TlsCertificate type.
func extractTLSCertificates(certs []*x509.Certificate) []*discover.TlsCertificate {
	if len(certs) == 0 {
		return nil
	}

	tlsCerts := make([]*discover.TlsCertificate, 0, len(certs))
	for _, cert := range certs {
		sans := make([]string, 0)
		for _, dnsName := range cert.DNSNames {
			sans = append(sans, dnsName)
		}
		for _, ip := range cert.IPAddresses {
			sans = append(sans, ip.String())
		}

		serialStr := cert.SerialNumber.String()
		subject := cert.Subject.String()
		issuer := cert.Issuer.String()

		tlsCert := &discover.TlsCertificate{
			Subject:      subject,
			Issuer:       issuer,
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			SerialNumber: &serialStr,
		}
		if len(sans) > 0 {
			tlsCert.Sans = sans
		}
		tlsCerts = append(tlsCerts, tlsCert)
	}
	return tlsCerts
}

// PerformRequest sends an HTTP request based on the provided config and returns a DiscoverRequestReport.
func PerformRequest(ctx context.Context, config discover.DiscoverRequestConfig) *discover.DiscoverRequestReport {
	log := svc1log.FromContext(ctx)

	// Initialize report
	result := discover.DiscoverRequestResult{}
	errors := []string{}
	report := discover.DiscoverRequestReport{Config: &config, Result: &result}
	addSignalLog := func(level string, format string, args ...interface{}) {
		errors = append(errors, fmt.Sprintf("%s: %s", level, fmt.Sprintf(format, args...)))
	}

	// Build HTTP request
	log.Info("Building HTTP request", svc1log.SafeParam("target", config.Target))
	addSignalLog("info", "building HTTP request for target %s", config.Target)
	request, err := buildHTTPRequest(config)
	if err != nil {
		addSignalLog("error", "failed to build HTTP request: %s", err.Error())
		report.Errors = errors
		return &report
	}
	addSignalLog("info", "built HTTP request with method %s", config.HttpMethod)

	// Determine effective max redirects
	maxRedirects := config.MaxRedirects
	if !config.FollowRedirects {
		maxRedirects = 0
	}
	addSignalLog("info", "configured request timeout=%d verifyTls=%t maxRedirects=%d", config.Timeout, config.VerifyTls, maxRedirects)

	// Build SendHttpRequestConfig
	sendConfig := common.SendHttpRequestConfig{
		Request:                    request,
		MaxRedirects:               maxRedirects,
		VerifyTls:                  config.VerifyTls,
		Timeout:                    config.Timeout,
		IgnoreCrossDomainRedirects: config.IgnoreCrossDomainRedirects,
		UserAgent:                  config.UserAgent,
		RequestMethod:              common.RequestMethodStandard,
	}

	// Construct URL
	constructedURL, err := standardhelpers.ConstructURL(ctx, request)
	if err != nil {
		addSignalLog("error", "failed to construct URL: %s", err.Error())
		report.Errors = errors
		return &report
	}
	addSignalLog("info", "constructed request URL %s", *constructedURL)

	// Prepare request body
	constructedReqReader, err := standardhelpers.PrepareRequestBody(ctx, request)
	if err != nil {
		addSignalLog("error", "failed to prepare request body: %s", err.Error())
		report.Errors = errors
		return &report
	}
	if request.Params != nil && request.Params.Body != nil {
		addSignalLog("info", "prepared request body of type %s", request.Params.Body.Kind)
	} else {
		addSignalLog("info", "prepared request without a body")
	}

	// Build headers map for the raw HTTP call
	var rawHeaders map[string][]string
	if request.Params != nil {
		rawHeaders = request.Params.Headers
	}
	constructedHeaders := requesthelpers.FlattenHeaders(rawHeaders)
	addSignalLog("info", "prepared %d request headers", len(constructedHeaders))

	// Record sent time
	sentAt := time.Now()
	request.SentAt = sentAt
	addSignalLog("info", "request sent at %s", sentAt.Format(time.RFC3339Nano))

	// Send HTTP request (directly to access TLS state)
	log.Info("Sending HTTP request", svc1log.SafeParam("url", *constructedURL))
	addSignalLog("info", "sending HTTP request to %s", *constructedURL)
	resp, redirectChain, err := standardhelpers.SendHTTPRequest(ctx, *constructedURL, constructedHeaders, constructedReqReader, sendConfig)
	if err != nil {
		addSignalLog("error", "HTTP request failed: %s", err.Error())
		report.Errors = errors
		return &report
	}
	addSignalLog("info", "received response with status code %d and %d redirects", resp.StatusCode, len(redirectChain))
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn("Failed to close response body", svc1log.SafeParam("error", closeErr))
			addSignalLog("warn", "failed to close response body: %s", closeErr.Error())
			report.Errors = errors
		}
	}()

	// Extract TLS certificates if available
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		tlsCerts := extractTLSCertificates(resp.TLS.PeerCertificates)
		result.TlsCertificates = tlsCerts
		addSignalLog("info", "extracted %d TLS certificates", len(tlsCerts))
	} else {
		addSignalLog("info", "no TLS certificates available on response")
	}

	// Read and marshal response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		addSignalLog("error", "failed to read response body: %s", err.Error())
		report.Errors = errors
		return &report
	}
	addSignalLog("info", "read response body with %d bytes", len(bodyBytes))

	// Build the HttpResponse
	httpResponse := requesthelpers.CreateHTTPResponseFromBytes(resp.StatusCode, redirectChain, resp.Header, bodyBytes)
	addSignalLog("info", "created HTTP response signal object")

	// Build HttpRequestResponse
	httpRequestResponse := &common.HttpRequestResponse{
		Request:  request,
		Response: &httpResponse,
	}
	result.Request = httpRequestResponse

	addSignalLog("info", "completed HTTP request")
	report.Errors = errors
	return &report
}
