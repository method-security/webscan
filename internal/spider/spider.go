// Package spider implements the logic for the `webscan spider` command. This command is used to crawl a list of URLs and
// report back the links found on each page, as well as any errors encountered during the crawl.
package spider

import (
	"context"
	"math"

	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
)

// LinkDetails provides the details of a single link found during a web spider operation.
type LinkDetails struct {
	Link   string `json:"link" yaml:"link"`
	Status int    `json:"status" yaml:"status"`
}

// A WebSpiderReport represents a holistic report of all the links that were found during a web spider operation, including
// non-fatal errors that occurred during the operation.
type WebSpiderReport struct {
	Targets []string      `json:"targets" yaml:"targets"`
	Links   []LinkDetails `json:"links" yaml:"links"`
	Errors  []string      `json:"errors" yaml:"errors"`
}

func performWebSpider(targets []string) ([]LinkDetails, []string, error) {
	errors := []string{}
	links := []LinkDetails{}

	options := &types.Options{
		MaxDepth:     3,             // Maximum depth to crawl
		FieldScope:   "rdn",         // Crawling Scope Field
		BodyReadSize: math.MaxInt,   // Maximum response size to read
		Timeout:      10,            // Timeout is the time to wait for request in seconds
		Concurrency:  10,            // Concurrency is the number of concurrent crawling goroutines
		Parallelism:  10,            // Parallelism is the number of urls processing goroutines
		Delay:        0,             // Delay is the delay between each crawl requests in seconds
		RateLimit:    150,           // Maximum requests to send per second
		Strategy:     "depth-first", // Visit strategy (depth-first, breadth-first)
		OnResult: func(result output.Result) { // Callback function to execute for result
			linkDetails := LinkDetails{
				Link:   result.Request.URL,
				Status: result.Response.StatusCode,
			}
			links = append(links, linkDetails)
		},
	}

	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		return links, errors, err
	}

	crawler, err := standard.New(crawlerOptions)
	if err != nil {
		return links, errors, err
	}

	for _, target := range targets {
		err := crawler.Crawl(target)
		if err != nil {
			errors = append(errors, err.Error())
		}
	}

	return links, errors, nil

}

// PerformWebSpider performs a web spider operation against the provided targets, returning a WebSpiderReport with the
// results of the spider.
func PerformWebSpider(ctx context.Context, targets []string) WebSpiderReport {
	// 1. Perform web spider
	links, errors, err := performWebSpider(targets)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// 2. Create report
	report := WebSpiderReport{
		Targets: targets,
		Links:   links,
		Errors:  errors,
	}
	return report
}
