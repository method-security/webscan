package webserver

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

func PerformHeaderGrab(ctx context.Context, targets []string, timeout int) (*webscan.HeaderGrabReport, error) {
	report := &webscan.HeaderGrabReport{}
	errors := []string{}

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	headerGrabInfos := []*webscan.HeaderGrabInfo{}
	for _, target := range targets {
		headerGrabInfo := webscan.HeaderGrabInfo{
			Target:    target,
			Timestamp: time.Now(),
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		headerGrabInfo.Request = &webscan.HeaderRequestInfo{
			Method: webscan.HttpMethodGet,
			Url:    target,
		}

		resp, err := client.Do(req)
		if err != nil {
			errorMsg := err.Error()
			headerGrabInfo.Response = &webscan.HeaderResponseInfo{
				Error: &errorMsg,
			}
			headerGrabInfos = append(headerGrabInfos, &headerGrabInfo)
			continue
		}

		headers := map[string]string{}
		for key, values := range resp.Header {
			headers[key] = values[0]
		}
		headerGrabInfo.Response = &webscan.HeaderResponseInfo{
			StatusCode: &resp.StatusCode,
			Headers:    headers,
		}

		err = resp.Body.Close()
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		headerGrabInfos = append(headerGrabInfos, &headerGrabInfo)
	}

	report.Targets = headerGrabInfos
	report.Errors = errors

	return report, nil
}
