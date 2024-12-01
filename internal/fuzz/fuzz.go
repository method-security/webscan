package fuzz

import (
	"context"
	"crypto/tls"
	"errors"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go"
)

func PerformPathFuzz(ctx context.Context, config *webscan.FuzzPathConfig) (*webscan.FuzzPathReport, error) {
	resources := webscan.FuzzPathReport{}
	var allErrors []string

	// Initialize Client
	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Create valid codes dict
	validCodes, err := parseResponseCodes(config.ResponseCodes)
	if err != nil {
		return nil, errors.New("invalid response code range")
	}

	// Loop through targets
	var targets []*webscan.TargetInfo
	for _, target := range config.Targets {
		targetInfo := webscan.TargetInfo{Target: target, RequestCount: len(config.Paths) * config.Retries, StartTimestamp: time.Now()}

		// Get baseline
		baselineSize, baselineWords, err := baseLine(target)
		if err != nil {
			allErrors = append(allErrors, err.Error())
			continue
		}

		// Loop through paths
		var fuzzAttempts []*webscan.FuzzAttemptInfo
		for _, path := range config.Paths {
			for i := 0; i < config.Retries; i++ {
				// Request
				url := strings.TrimRight(target, "/") + "/" + strings.TrimLeft(path, "/")
				fuzzAttemptInfo := webscan.FuzzAttemptInfo{
					Path:      path,
					Timestamp: time.Now(),
				}
				fuzzAttemptInfo.Request = &webscan.RequestInfo{
					Method: webscan.HttpMethodGet,
					Url:    url,
				}
				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					allErrors = append(allErrors, err.Error())
					continue
				}
				resp, err := client.Do(req)

				// Response
				var responseInfo *webscan.ResponseInfo
				var isValid bool
				if err != nil {
					responseErr := err.Error()
					responseInfo = &webscan.ResponseInfo{
						Error: &responseErr,
					}
				} else {
					bodyBytes, _ := ioutil.ReadAll(resp.Body)
					body := string(bodyBytes)

					statusCode := resp.StatusCode
					responseInfo = &webscan.ResponseInfo{
						StatusCode: &statusCode,
						Body:       &body,
					}

					isValid = AnalyzeResponse(responseInfo, validCodes, config.IgnoreBaseContent, baselineSize, baselineWords)

					err = resp.Body.Close()
					if err != nil {
						allErrors = append(allErrors, err.Error())
					}
				}

				// Marshal data
				if !config.SuccessfulOnly || isValid {
					fuzzAttemptInfo.Response = responseInfo
					fuzzAttemptInfo.Finding = &isValid
					fuzzAttempts = append(fuzzAttempts, &fuzzAttemptInfo)
				}

				// Sleep if configured
				if config.Sleep > 0 {
					time.Sleep(time.Duration(config.Sleep) * time.Millisecond)
				}
			}
		}
		targetInfo.FuzzAttempts = fuzzAttempts
		targetInfo.EndTimestamp = time.Now()
		targets = append(targets, &targetInfo)
	}

	resources.Targets = targets
	resources.Errors = allErrors
	return &resources, nil
}

func AnalyzeResponse(response *webscan.ResponseInfo, validCodes map[int]bool, ignoreBaseContent bool, baselineSize, baselineWords int) bool {
	if response.StatusCode == nil || !validCodes[*response.StatusCode] {
		return false
	}

	// Checks for web backend redirect
	bodySize := len(*response.Body)
	wordCount := len(strings.Fields(*response.Body))
	if ignoreBaseContent {
		if bodySize == baselineSize && wordCount == baselineWords {
			return false
		}
	}
	return true
}

func baseLine(baseTarget string) (int, int, error) {
	resp, err := http.Get(baseTarget)
	if err != nil {
		return 0, 0, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, 0, err
	}

	bodySize := len(body)
	wordCount := len(strings.Fields(string(body)))

	err = resp.Body.Close()
	if err != nil {
		return 0, 0, err
	}

	return bodySize, wordCount, nil
}

// parseResponseCodes parses a comma-separated or range-based string of response codes
// (e.g., "200,301,404-410") and returns a map of valid codes.
func parseResponseCodes(responseCodes string) (map[int]bool, error) {
	validCodes := make(map[int]bool)
	for _, part := range strings.Split(responseCodes, ",") {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			start, err1 := strconv.Atoi(rangeParts[0])
			end, err2 := strconv.Atoi(rangeParts[1])
			if err1 != nil || err2 != nil || start > end {
				return nil, errors.New("invalid response code range")
			}
			for i := start; i <= end; i++ {
				validCodes[i] = true
			}
		} else {
			code, err := strconv.Atoi(part)
			if err != nil {
				return nil, errors.New("invalid response code")
			}
			validCodes[code] = true
		}
	}
	return validCodes, nil
}
