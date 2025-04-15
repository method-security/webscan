package webapplication

import (
	"context"
	"fmt"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go/webserver"
	pagecapture "github.com/Method-Security/webscan/internal/pagecapture/helpers"
	"github.com/projectdiscovery/httpx/runner"
)

func performWebserverProbe(ctx context.Context, targets []string, timeout time.Duration, strategy webscan.WebserverProbeStrategy, browserPath *string, minDOMStabalizeTime *int) ([]*webscan.WebserverProbeUrlDetails, []string, error) {
	// Toggle on method selected
	if strategy == webscan.WebserverProbeStrategyBrowser {
		return performBrowserProbe(ctx, targets, timeout, browserPath, *minDOMStabalizeTime)
	}
	return performHttpxProbe(ctx, targets, timeout)
}

func performHttpxProbe(ctx context.Context, targets []string, timeout time.Duration) ([]*webscan.WebserverProbeUrlDetails, []string, error) {
	errors := []string{}
	urls := []*webscan.WebserverProbeUrlDetails{}

	// Create a new context with timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	options := runner.Options{
		Methods:         "GET",
		InputTargetHost: targets,
		RandomAgent:     true,
		FollowRedirects: true,
		NoFallback:      true,
		Debug:           true,
		OnResult: func(r runner.Result) {
			// If there's an HTTP response (even from a WAF), append the URL
			if r.Err != nil {
				errors = append(errors, r.Err.Error())
			}
			urlDetails := webscan.WebserverProbeUrlDetails{
				Url:    r.URL,
				Status: &r.StatusCode,
				Title:  &r.Title,
			}
			urls = append(urls, &urlDetails)
		},
	}

	// Validate HTTPX options
	if err := options.ValidateOptions(); err != nil {
		return urls, errors, err
	}

	// Initialize HTTPX
	httpxRunner, err := runner.New(&options)
	if err != nil {
		fmt.Printf("Failed to initialize HTTPX: %v\n", err)
		return urls, errors, err
	}
	defer httpxRunner.Close()

	// Run the enumeration with a goroutine and select for timeout
	done := make(chan struct{})

	go func() {
		fmt.Println("Running HTTPX Enumeration...")
		httpxRunner.RunEnumeration()
		close(done)
	}()
	select {
	case <-ctx.Done():
		fmt.Println("CTX Timeout reached before completion")
		return urls, errors, ctx.Err()
	case <-done:
		fmt.Println("Httpx scan completed successfully")
		return urls, errors, nil
	}
}

func performBrowserProbe(ctx context.Context, targets []string, timeout time.Duration, browserPath *string, minDOMStabalizeTime int) ([]*webscan.WebserverProbeUrlDetails, []string, error) {
	errors := []string{}
	urls := []*webscan.WebserverProbeUrlDetails{}

	for _, target := range targets {
		capturer := pagecapture.NewBrowserPageCapturer(browserPath, int(timeout.Seconds()), minDOMStabalizeTime)

		// Try HTTPS first
		targetURL := "https://" + target
		result, err := capturer.Capture(ctx, targetURL, &pagecapture.Options{})
		if err != nil {
			// If HTTPS fails, try HTTP
			targetURL = "http://" + target
			result, err = capturer.Capture(ctx, targetURL, &pagecapture.Options{})
			if err != nil {
				errors = append(errors, "invalid address "+target)
				continue
			}
		}

		urlDetails := &webscan.WebserverProbeUrlDetails{
			Url:    targetURL,
			Status: result.Request.StatusCode,
		}

		urls = append(urls, urlDetails)

		_ = capturer.Close(ctx)
	}

	return urls, errors, nil
}

// PerformWebserverProbe performs a server probe against the provided targets, returning a ProbeReport with the
// results of the probe.
func PerformWebserverProbe(ctx context.Context, config *webscan.WebserverProbeConfig) *webscan.WebserverProbeReport {

	urls, errors, err := performWebserverProbe(ctx, config.Targets, time.Duration(config.Timeout)*time.Second,
		config.Strategy, config.BrowserPath, config.MinDomStabalizeTime)
	if err != nil {
		errors = append(errors, err.Error())
	}
	report := webscan.WebserverProbeReport{
		Targets: config.Targets,
		Urls:    urls,
		Errors:  errors,
	}
	return &report
}
