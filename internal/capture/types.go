package capture

import (
	"context"
	"encoding/base64"

	webscan "github.com/Method-Security/webscan/generated/go/pagecapture"
)

type Options struct{}
type Result struct {
	Content    []byte   `json:"content,omitempty" yaml:"content,omitempty"`
	StatusCode *int     `json:"statusCode,omitempty" yaml:"statusCode,omitempty"`
	URL        string   `json:"url,omitempty" yaml:"url,omitempty"`
	Errors     []string `json:"errors,omitempty" yaml:"errors,omitempty"`
}

type PageCapturer interface {
	Capture(ctx context.Context, url string, options *Options) (*Result, error)
	Close(ctx context.Context) error
}

func NewCaptureResult(URL string) *Result {
	return &Result{
		StatusCode: nil,
		URL:        URL,
		Errors:     []string{},
	}
}

func (r *Result) ToPageCaptureReport() webscan.PageCaptureReport {
	report := webscan.PageCaptureReport{
		Target:      r.URL,
		Errors:      r.Errors,
		HtmlEncoded: nil,
	}

	if r.Content != nil {
		encodedBodyString := base64.StdEncoding.EncodeToString(r.Content)
		report.HtmlEncoded = &encodedBodyString
	}

	return report
}
