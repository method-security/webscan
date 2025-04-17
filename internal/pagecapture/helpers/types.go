package pagecapture

import (
	"time"

	common "github.com/Method-Security/webscan/generated/go/common"
	pagecapturefern "github.com/Method-Security/webscan/generated/go/pagecapture"
)

type Options struct{}

func NewPageCaptureReport(url string) *pagecapturefern.PageCaptureHtmlReport {
	report := &pagecapturefern.PageCaptureHtmlReport{
		Request: &common.RequestInfo{
			BaseUrl:         url,
			Path:            "",
			Method:          "GET",
			PathParams:      map[string]string{},
			QueryParams:     map[string]string{},
			HeaderParams:    map[string]string{},
			BodyParams:      nil,
			FormParams:      map[string]string{},
			MultipartParams: map[string]string{},
			ResponseHeaders: map[string]string{},
			Errors:          []string{},
			Timestamp:       time.Now(),
		},
	}
	return report
}

func NewPageScreenshotReport(url string) *pagecapturefern.PageCaptureScreenshotReport {
	report := &pagecapturefern.PageCaptureScreenshotReport{
		Request: &common.RequestInfo{
			BaseUrl:         url,
			Path:            "",
			Method:          "GET",
			PathParams:      map[string]string{},
			QueryParams:     map[string]string{},
			HeaderParams:    map[string]string{},
			BodyParams:      nil,
			FormParams:      map[string]string{},
			MultipartParams: map[string]string{},
			ResponseHeaders: map[string]string{},
			Errors:          []string{},
			Timestamp:       time.Now(),
		},
	}
	return report
}
