package webapplication

import (
	"context"
	"fmt"
	"time"

	common "github.com/Method-Security/webscan/generated/go/common"
	webscan "github.com/Method-Security/webscan/generated/go/webserver"
	"github.com/Method-Security/webscan/utils"
	"github.com/Method-Security/webscan/utils/headless"
)

func PerformWebserverProbe(ctx context.Context, config *webscan.WebserverProbeConfig) (*webscan.WebserverProbeReport, error) {
	report := &webscan.WebserverProbeReport{Config: config}
	errors := []string{}

	// Toggle on method selected
	if config.Strategy == webscan.WebserverProbeStrategyBrowser {
		request, err := performBrowserProbe(ctx, config.Targets, time.Duration(config.Timeout)*time.Second, config.BrowserPath, *config.MinDomStabalizeTime)
		if err != nil {
			errors = append(errors, err...)
		}
		report.Targets = request
	} else if config.Strategy == webscan.WebserverProbeStrategyRequest {
		request, err := performRequestProbe(config.Targets, time.Duration(config.Timeout)*time.Second)
		if err != nil {
			errors = append(errors, err...)
		}
		report.Targets = request
	}

	report.Errors = errors
	return report, nil
}

// tryHTTPSThenHTTP attempts to connect to a target using HTTPS first, falling back to HTTP if HTTPS fails
func tryHTTPSThenHTTP(target string, probeFunc func(string) (*common.RequestInfo, error)) (*common.RequestInfo, error) {
	// Try HTTPS first
	targetURL := "https://" + target
	result, err := probeFunc(targetURL)
	if err != nil {
		// If HTTPS fails, try HTTP
		targetURL = "http://" + target
		result, err = probeFunc(targetURL)
	}
	return result, err
}

func performRequestProbe(targets []string, timeout time.Duration) ([]*common.RequestInfo, []string) {
	errors := []string{}
	requests := []*common.RequestInfo{}

	for _, target := range targets {
		baseURL, path, err := utils.SplitTarget(target)
		if err != nil {
			errors = append(errors, "invalid address "+target)
			continue
		}
		probeFunc := func(url string) (*common.RequestInfo, error) {
			request := utils.PerformRequestScan(utils.RequestOptions{
				BaseURL:         baseURL,
				Path:            path,
				Method:          common.HttpMethodGet,
				Params:          common.RequestParams{},
				Timeout:         int(timeout.Seconds()),
				FollowRedirects: true,
				Insecure:        true,
			})
			if request.StatusCode != nil && *request.StatusCode >= 400 {
				return &request, fmt.Errorf("request failed with status %d", *request.StatusCode)
			}
			return &request, nil
		}

		result, err := tryHTTPSThenHTTP(target, probeFunc)
		if err != nil {
			errors = append(errors, "invalid address "+target)
			continue
		}
		requests = append(requests, result)
	}

	return requests, errors
}

func performBrowserProbe(ctx context.Context, targets []string, timeout time.Duration, browserPath *string, minDOMStabalizeTime int) ([]*common.RequestInfo, []string) {
	errors := []string{}
	requests := []*common.RequestInfo{}

	for _, target := range targets {
		capturer := headless.NewBrowserPageCapturer(browserPath, int(timeout.Seconds()), minDOMStabalizeTime)
		defer func() {
			_ = capturer.Close(ctx)
		}()

		probeFunc := func(url string) (*common.RequestInfo, error) {
			return capturer.Capture(ctx, url, &headless.BrowserOptions{FollowRedirects: true})
		}

		result, err := tryHTTPSThenHTTP(target, probeFunc)
		if err != nil {
			errors = append(errors, "invalid address "+target)
			continue
		}
		requests = append(requests, result)
	}

	return requests, errors
}
