package capture

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go/pagecapture"
	urlutil "github.com/projectdiscovery/utils/url"
)

type RequestPageCapturer struct {
	Client http.Client
}

func NewRequestPageCapturer(insecure bool, timeout int) *RequestPageCapturer {
	return &RequestPageCapturer{
		Client: http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: insecure,
				},
			},
			Timeout: time.Duration(timeout) * time.Second,
		},
	}
}

func (r *RequestPageCapturer) Capture(ctx context.Context, url string, options *Options) (*webscan.PageCaptureReport, error) {
	report := NewPageCaptureReport(url)

	resp, err := r.Client.Get(url)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = cerr
		}
	}()

	report.Request.StatusCode = &resp.StatusCode
	for k, v := range resp.Header {
		report.Request.ResponseHeaders[k] = v[0]
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
	} else {
		encodedBody := base64.StdEncoding.EncodeToString(body)
		report.Request.ResponseBody = &encodedBody
	}

	// Parse URL to get path and query parameters
	if parsedURL, err := urlutil.Parse(url); err == nil {
		report.Request.Path = parsedURL.Path
		parsedURL.Query().Iterate(func(key string, value []string) bool {
			report.Request.QueryParams[key] = value[0]
			return true
		})
	}

	return report, nil
}

func (r *RequestPageCapturer) Close(ctx context.Context) error {
	return nil
}
