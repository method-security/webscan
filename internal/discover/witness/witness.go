package discoverwitness

import (
	// Standard
	"context"
	"fmt"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"

	// Internal
	discoverpage "github.com/Method-Security/webscan/internal/discover/page"
	witnesshelpers "github.com/Method-Security/webscan/internal/discover/witness/helpers"

	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	useragent "github.com/Method-Security/webscan/utils/useragent"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// pageConfigFromWitnessConfig converts a DiscoverWitnessConfig to a DiscoverPageConfig for a specific target.
func pageConfigFromWitnessConfig(target string, config discover.DiscoverWitnessConfig) discover.DiscoverPageConfig {
	return discover.DiscoverPageConfig{
		Target:                     target,
		ResponseCodes:              config.ResponseCodes,
		Screenshot:                 config.Screenshot,
		MaxRedirects:               config.MaxRedirects,
		VerifyTls:                  config.VerifyTls,
		Timeout:                    config.Timeout,
		IgnoreCrossDomainRedirects: config.IgnoreCrossDomainRedirects,
		UserAgent:                  config.UserAgent,
		RequestMethod:              config.RequestMethod,
		HeadlessConfig:             config.HeadlessConfig,
		BrowserbaseConfig:          config.BrowserbaseConfig,
		Headers:                    config.Headers,
		Cookies:                    config.Cookies,
		LocalStorage:               config.LocalStorage,
		SessionStorage:             config.SessionStorage,
	}
}

// processTarget runs the page capture + wappalyzer fingerprinting for a single target.
func processTarget(
	ctx context.Context,
	target string,
	config discover.DiscoverWitnessConfig,
	browserbaseSecrets *common.BrowserbaseRequestSecrets,
) (*discover.DiscoverWitnessResult, []string) {
	log := svc1log.FromContext(ctx)
	result := &discover.DiscoverWitnessResult{}
	var targetErrors []string

	// Run page capture via the existing DiscoverPage substrate
	pageConfig := pageConfigFromWitnessConfig(target, config)
	pageReport := discoverpage.PerformPageCapture(ctx, pageConfig, browserbaseSecrets)

	// Copy page errors
	targetErrors = append(targetErrors, pageReport.Errors...)

	if pageReport.Result == nil || pageReport.Result.Request == nil || pageReport.Result.Request.Response == nil {
		return result, targetErrors
	}

	result.Request = pageReport.Result.Request
	result.Screenshot = pageReport.Result.Screenshot
	result.ScreenshotPerceptualHash = pageReport.Result.ScreenshotPerceptualHash
	result.Target = &target

	// Run Wappalyzer fingerprinting over the captured response
	resp := result.Request.Response
	headers := resp.ResponseHeaders
	if headers == nil {
		headers = make(map[string][]string)
	}

	// Extract body bytes for Wappalyzer
	var bodyBytes []byte
	if resp.ResponseBody != nil {
		if bodyStr := requesthelpers.GetResponseBodyStringFromBodyStruct(resp.ResponseBody); bodyStr != nil {
			bodyBytes = []byte(*bodyStr)
		}
	}

	finalURL := target
	if len(resp.RedirectChain) > 0 {
		finalURL = resp.RedirectChain[len(resp.RedirectChain)-1]
	}
	faviconURL := witnesshelpers.ExtractFaviconURL(string(bodyBytes), finalURL)
	if faviconURL != "" {
		resolvedUA := useragent.Resolve(config.UserAgent)
		if faviconBytes, faviconHash, faviconErr := witnesshelpers.FetchFavicon(ctx, faviconURL, config.Timeout, config.VerifyTls, resolvedUA); faviconErr == nil && len(faviconBytes) > 0 {
			result.Favicon = &discover.DiscoverWitnessFavicon{
				Url:    faviconURL,
				Binary: faviconBytes,
				Hash:   faviconHash,
			}
		}
	}

	log.Info("Running Wappalyzer fingerprinting", svc1log.SafeParam("target", target))
	techs, wapErr := witnesshelpers.Fingerprint(headers, bodyBytes)
	if wapErr != nil {
		log.Warn("Wappalyzer fingerprinting failed", svc1log.SafeParam("target", target), svc1log.SafeParam("error", wapErr.Error()))
		targetErrors = append(targetErrors, fmt.Sprintf("wappalyzer: %s", wapErr.Error()))
	} else if techs != nil && (len(techs.ClientSide) > 0 || len(techs.ServerSide) > 0 || len(techs.Other) > 0) {
		result.Technologies = techs
	}

	return result, targetErrors
}

// PerformWitnessCapture performs a single-pass witness scan for one target.
func PerformWitnessCapture(ctx context.Context, config discover.DiscoverWitnessConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) *discover.DiscoverWitnessReport {
	log := svc1log.FromContext(ctx)

	report := &discover.DiscoverWitnessReport{
		Config: &config,
		Result: &discover.DiscoverWitnessResult{},
	}

	if config.Target == "" {
		report.Errors = []string{"witness: no target provided"}
		return report
	}

	log.Info("Starting witness scan", svc1log.SafeParam("target", config.Target))
	capturedResult, targetErrors := processTarget(ctx, config.Target, config, browserbaseSecrets)
	report.Result = capturedResult
	report.Errors = targetErrors
	return report
}
