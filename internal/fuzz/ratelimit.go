package fuzz

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

// PerformRateLimitFuzz performs rate limit detection on target URLs within a specified timespan
func PerformRateLimitFuzz(ctx context.Context, inputTargets []string, config *webscan.FuzzRateLimitConfig) (*webscan.FuzzRateLimitReport, error) {
	report := &webscan.FuzzRateLimitReport{Config: config}

	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Calculate the interval between requests based on the timespan
	requestInterval := time.Duration(config.Timespan) * time.Second / time.Duration(config.MaxRequests)

	// Process each target sequentially
	for _, target := range inputTargets {
		targetInfo := &webscan.RateLimitAttempt{
			Target:         target,
			StartTimestamp: time.Now(),
		}

		// Track if a 200 OK response was previously detected for this target
		var hasSeen200 bool

		for i := 1; i <= config.MaxRequests; i++ {
			req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
			if err != nil {
				report.Errors = append(report.Errors, err.Error())
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				report.Errors = append(report.Errors, err.Error())
				continue
			}

			if rateLimitDetected(resp, hasSeen200) {
				headers := make(map[string]string)
				bodyStr := ""

				// Extract headers and body
				for key, values := range resp.Header {
					if len(values) > 0 {
						headers[key] = values[0]
					}
				}

				body, err := io.ReadAll(resp.Body)
				if err == nil {
					bodyStr = string(body)
				}

				err = resp.Body.Close()
				if err != nil {
					report.Errors = append(report.Errors, err.Error())
					continue
				}

				targetInfo.Detected = &webscan.RateLimitDetectedInfo{
					RequestNumber:   i,
					Timestamp:       time.Now(),
					ResponseCode:    &resp.StatusCode,
					ResponseHeaders: headers,
					ResponseBody:    &bodyStr,
				}
				break
			}

			// Mark if a 200 OK response was seen
			if resp.StatusCode == http.StatusOK {
				hasSeen200 = true
			}

			// Enforce the calculated request interval
			if requestInterval > 0 {
				time.Sleep(requestInterval)
			}

			err = resp.Body.Close()
			if err != nil {
				report.Errors = append(report.Errors, err.Error())
				continue
			}
		}

		targetInfo.EndTimestamp = time.Now()
		report.Targets = append(report.Targets, targetInfo)
	}

	return report, nil
}

// rateLimitDetected checks if a response explicitly indicates that a request was rate-limited
// or if a 403 response is returned after a 200 response was previously seen.
func rateLimitDetected(resp *http.Response, hasSeen200 bool) bool {
	if resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if resp.Header.Get("X-Retry-After") != "" || resp.Header.Get("X-RateLimit-Remaining") == "0" {
		return true
	}

	if resp.StatusCode == http.StatusForbidden && hasSeen200 {
		return true
	}

	// Check for specific header names and values
	for key, values := range resp.Header {
		if (strings.Contains(key, "Retry-After") && len(values) > 0 && values[0] != "") ||
			(strings.Contains(key, "RateLimit-Remaining") && len(values) > 0 && values[0] == "0") {
			return true
		}
	}

	return false
}
