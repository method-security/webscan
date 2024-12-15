package webapplication

import (
	"context"
	"time"

	webscan "github.com/Method-Security/webscan/generated/go/webserver"
	"github.com/projectdiscovery/httpx/runner"
)

func performWebserverProbe(ctx context.Context, targets []string, timeout time.Duration) ([]*webscan.WebserverProbeUrlDetails, []string, error) {
	errors := []string{}
	urls := []*webscan.WebserverProbeUrlDetails{}

	// Create a new context with timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	options := runner.Options{
		Methods:         "GET",
		InputTargetHost: targets,
		OnResult: func(r runner.Result) {
			// handle error
			if r.Err != nil {
				errors = append(errors, r.Err.Error())
			}
			urlDetails := webscan.WebserverProbeUrlDetails{
				Url:    r.URL,
				Status: r.StatusCode,
				Title:  r.Title,
			}
			urls = append(urls, &urlDetails)
		},
	}

	if err := options.ValidateOptions(); err != nil {
		return urls, errors, err
	}

	httpxRunner, err := runner.New(&options)
	if err != nil {
		return urls, errors, err
	}
	defer httpxRunner.Close()

	// Run the enumeration with a goroutine and select for timeout
	done := make(chan struct{})

	go func() {
		httpxRunner.RunEnumeration()
		close(done)
	}()

	select {
	case <-ctx.Done():
		// Timeout reached
		return urls, errors, ctx.Err()
	case <-done:
		// Enumeration completed successfully
		return urls, errors, nil
	}
}

// PerformWebserverProbe performs a server probe against the provided targets, returning a ProbeReport with the
// results of the probe.
func PerformWebserverProbe(ctx context.Context, config *webscan.WebserverProbeConfig) *webscan.WebserverProbeReport {
	urls, errors, err := performWebserverProbe(ctx, config.Targets, time.Duration(config.Timeout)*time.Second)
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
