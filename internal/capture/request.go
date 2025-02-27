package capture

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"time"
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

func (r *RequestPageCapturer) Capture(ctx context.Context, url string, options *Options) (*Result, error) {
	result := NewCaptureResult(url)
	resp, err := r.Client.Get(url)

	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			err = cerr
		}
	}()

	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result, err
	}
	result.StatusCode = &resp.StatusCode
	result.Headers = map[string]string{}
	for k, v := range resp.Header {
		result.Headers[k] = v[0]
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
	} else {
		result.Content = body
	}

	return result, nil
}

func (r *RequestPageCapturer) Close(ctx context.Context) error {
	return nil
}
