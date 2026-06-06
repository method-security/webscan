package discoverrequest

import (
	// Standard
	"context"
	"crypto/x509"
	"io"
	"strings"
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
	case config.FormData != nil && len(config.FormData) > 0:
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
		SentAt:  time.Now(),
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

	// Build HTTP request
	log.Info("Building HTTP request", svc1log.SafeParam("target", config.Target))
	request, err := buildHTTPRequest(config)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return &report
	}

	// Determine effective max redirects
	maxRedirects := config.MaxRedirects
	if !config.FollowRedirects {
		maxRedirects = 0
	}

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
		errors = append(errors, err.Error())
		report.Errors = errors
		return &report
	}

	// Prepare request body
	constructedReqReader, err := standardhelpers.PrepareRequestBody(ctx, request)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return &report
	}

	// Build headers map for the raw HTTP call
	constructedHeaders := make(map[string]string)
	if request.Params != nil && request.Params.Headers != nil {
		for k, v := range request.Params.Headers {
			if len(v) > 0 {
				constructedHeaders[k] = strings.Join(v, ",")
			}
		}
	}

	// Record sent time
	sentAt := time.Now()
	request.SentAt = sentAt

	// Send HTTP request (directly to access TLS state)
	log.Info("Sending HTTP request", svc1log.SafeParam("url", *constructedURL))
	resp, redirectChain, err := standardhelpers.SendHTTPRequest(ctx, *constructedURL, constructedHeaders, constructedReqReader, sendConfig)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return &report
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn("Failed to close response body", svc1log.SafeParam("error", closeErr))
		}
	}()

	// Extract TLS certificates if available
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		tlsCerts := extractTLSCertificates(resp.TLS.PeerCertificates)
		result.TlsCertificates = tlsCerts
	}

	// Read and marshal response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return &report
	}

	// Build the HttpResponse
	httpResponse := requesthelpers.CreateHTTPResponseFromBytes(resp.StatusCode, redirectChain, resp.Header, bodyBytes)

	// Build HttpRequestResponse
	httpRequestResponse := &common.HttpRequestResponse{
		Request:  request,
		Response: &httpResponse,
	}
	result.Request = httpRequestResponse

	report.Errors = errors
	return &report
}
