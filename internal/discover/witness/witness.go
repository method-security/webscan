package discoverwitness

import (
	// Standard
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	nucleicommon "github.com/Method-Security/webscan/generated/go/common/nuclei"
	discover "github.com/Method-Security/webscan/generated/go/discover"

	// Internal
	discoverpage "github.com/Method-Security/webscan/internal/discover/page"
	discoverpagehelpers "github.com/Method-Security/webscan/internal/discover/page/helpers"
	discoverrequest "github.com/Method-Security/webscan/internal/discover/request"
	witnesshelpers "github.com/Method-Security/webscan/internal/discover/witness/helpers"

	// Utils
	nucleiutils "github.com/Method-Security/webscan/utils/nuclei"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// loadTargets returns the list of URLs to scan from either a single target or a targets file.
func loadTargets(target *string, targetsFile *string) ([]string, error) {
	if target != nil && *target != "" {
		return []string{*target}, nil
	}
	if targetsFile != nil && *targetsFile != "" {
		f, err := os.Open(*targetsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open targets file %q: %w", *targetsFile, err)
		}
		defer func() { _ = f.Close() }()

		var targets []string
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading targets file: %w", err)
		}
		return targets, nil
	}
	return nil, fmt.Errorf("either --target or --targets-file must be provided")
}

// pageConfigFromWitnessConfig converts a DiscoverWitnessConfig to a DiscoverPageConfig for a specific target.
func pageConfigFromWitnessConfig(target string, config discover.DiscoverWitnessConfig) discover.DiscoverPageConfig {
	return discover.DiscoverPageConfig{
		Target:                           target,
		SensitiveContentDetection:        config.SensitiveContentDetection,
		SensitiveContentFingerprintsPath: config.SensitiveContentFingerprintsPath,
		ResponseCodes:                    config.ResponseCodes,
		Screenshot:                       config.Screenshot,
		MaxRedirects:                     config.MaxRedirects,
		VerifyTls:                        config.VerifyTls,
		Timeout:                          config.Timeout,
		IgnoreCrossDomainRedirects:       config.IgnoreCrossDomainRedirects,
		UserAgent:                        config.UserAgent,
		RequestMethod:                    config.RequestMethod,
		HeadlessConfig:                   config.HeadlessConfig,
		BrowserbaseConfig:                config.BrowserbaseConfig,
		Headers:                          config.Headers,
		Cookies:                          config.Cookies,
		LocalStorage:                     config.LocalStorage,
		SessionStorage:                   config.SessionStorage,
	}
}

// runNucleiForTargets runs Nuclei fingerprinting for the given targets and returns
// per-target attempt slices. Returns nil map when no template paths are configured.
func runNucleiForTargets(ctx context.Context, targets []string, config discover.DiscoverWitnessConfig) (map[string][]*discover.ApplicationFingerprintAttempt, error) {
	if len(config.NucleiTemplatePaths) == 0 {
		return nil, nil
	}

	nucleiConfig := nucleicommon.NucleiConfig{
		Targets:       targets,
		TemplatePaths: config.NucleiTemplatePaths,
		RunMode:       nucleicommon.NucleiRunModeScan,
		Timeout:       config.Timeout,
		Threads:       config.NucleiThreads,
		VerboseLogs:   false,
		UserAgent:     config.UserAgent,
	}

	nucleiReport, err := nucleiutils.RunNucleiEngine(ctx, nucleiConfig)
	if err != nil {
		return nil, err
	}

	// Build per-target attempt map from raw nuclei results
	perTarget := make(map[string][]*discover.ApplicationFingerprintAttempt)
	for _, nucleiTarget := range nucleiReport {
		if len(nucleiTarget.Attempts) == 0 {
			continue
		}
		seenTemplateIds := make(map[string]bool)
		for _, attempt := range nucleiTarget.Attempts {
			if attempt.Finding == nil || seenTemplateIds[attempt.TemplateId] {
				continue
			}
			seenTemplateIds[attempt.TemplateId] = true
			converted := convertNucleiAttempt(attempt)
			if converted != nil {
				perTarget[nucleiTarget.Target] = append(perTarget[nucleiTarget.Target], converted)
			}
		}
	}
	return perTarget, nil
}

// convertNucleiAttempt converts a nuclei attempt to an ApplicationFingerprintAttempt.
func convertNucleiAttempt(nucleiAttempt *nucleicommon.NucleiAttemptInfo) *discover.ApplicationFingerprintAttempt {
	if nucleiAttempt == nil || nucleiAttempt.TemplateId == "" {
		return nil
	}
	if nucleiAttempt.Finding == nil {
		return nil
	}

	var resourceType discover.ApplicationResourceType
	var moduleName string
	var subModule *string
	var detectionState *discover.ApplicationDetectionState
	var cpe *string

	if nucleiAttempt.Finding.Metadata != nil {
		if appTypeStr, ok := nucleiAttempt.Finding.Metadata["method-application-type"]; ok {
			if appType, err := discover.NewApplicationResourceTypeFromString(appTypeStr); err == nil {
				resourceType = appType
			}
		}
		if modStr, ok := nucleiAttempt.Finding.Metadata["method-module-name"]; ok {
			moduleName = strings.ToUpper(modStr)
		}
		if subModStr, ok := nucleiAttempt.Finding.Metadata["method-sub-module-name"]; ok {
			s := subModStr
			subModule = &s
		}
		if dsStr, ok := nucleiAttempt.Finding.Metadata["method-detection-state"]; ok {
			if ds, err := discover.NewApplicationDetectionStateFromString(dsStr); err == nil {
				detectionState = &ds
			}
		}
		if cpeStr, ok := nucleiAttempt.Finding.Metadata["cpe"]; ok {
			c := cpeStr
			cpe = &c
		}
	}

	return &discover.ApplicationFingerprintAttempt{
		ResourceType:   resourceType,
		Module:         moduleName,
		SubModule:      subModule,
		DetectionState: detectionState,
		Cpe:            cpe,
		Finding:        true,
		Request:        nucleiAttempt.HttpRequestResponse,
	}
}

// extractTLSFromTarget performs a lightweight standard HTTP request to extract TLS certificates.
func extractTLSFromTarget(ctx context.Context, target string, config discover.DiscoverWitnessConfig) []*discover.TlsCertificate {
	if !strings.HasPrefix(strings.ToLower(target), "https://") {
		return nil
	}

	log := svc1log.FromContext(ctx)
	log.Info("Extracting TLS certificates via standard request", svc1log.SafeParam("target", target))

	requestConfig := discover.DiscoverRequestConfig{
		Target:                     target,
		HttpMethod:                 common.HttpMethodGet,
		MaxRedirects:               config.MaxRedirects,
		FollowRedirects:            true,
		VerifyTls:                  config.VerifyTls,
		Timeout:                    config.Timeout,
		UserAgent:                  config.UserAgent,
		IgnoreCrossDomainRedirects: config.IgnoreCrossDomainRedirects,
	}

	requestReport := discoverrequest.PerformRequest(ctx, requestConfig)
	if requestReport != nil && requestReport.Result != nil {
		return requestReport.Result.TlsCertificates
	}
	return nil
}

// processTarget runs the page capture + wappalyzer fingerprinting for a single target.
func processTarget(
	ctx context.Context,
	target string,
	config discover.DiscoverWitnessConfig,
	sensitiveContentFingerprints *discover.SensitiveContentFingerprints,
	nucleiResults map[string][]*discover.ApplicationFingerprintAttempt,
	browserbaseSecrets *common.BrowserbaseRequestSecrets,
) *discover.DiscoverWitnessTargetResult {
	log := svc1log.FromContext(ctx)
	result := &discover.DiscoverWitnessTargetResult{
		Target:       target,
		Technologies: []*discover.DetectedTechnology{},
	}
	var targetErrors []string

	// Run page capture via the existing DiscoverPage substrate
	pageConfig := pageConfigFromWitnessConfig(target, config)
	pageReport := discoverpage.PerformPageCapture(ctx, pageConfig, sensitiveContentFingerprints, browserbaseSecrets)

	// Copy page errors
	targetErrors = append(targetErrors, pageReport.Errors...)

	if pageReport.Result != nil {
		pr := pageReport.Result
		result.Request = pr.Request
		result.Screenshot = pr.Screenshot
		result.ScreenshotPerceptualHash = pr.ScreenshotPerceptualHash
		result.Favicon = pr.Favicon
		result.FaviconHash = pr.FaviconHash
		result.HtmlTitle = pr.HtmlTitle
		result.SensitiveContents = pr.SensitiveContents

		// Run Wappalyzer fingerprinting over the captured response
		if pr.Request != nil && pr.Request.Response != nil {
			resp := pr.Request.Response
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

			log.Info("Running Wappalyzer fingerprinting", svc1log.SafeParam("target", target))
			techs, wapErr := witnesshelpers.Fingerprint(headers, bodyBytes)
			if wapErr != nil {
				log.Warn("Wappalyzer fingerprinting failed", svc1log.SafeParam("target", target), svc1log.SafeParam("error", wapErr.Error()))
				targetErrors = append(targetErrors, fmt.Sprintf("wappalyzer: %s", wapErr.Error()))
			} else {
				result.Technologies = techs
			}
		}

		// Extract TLS certificates — use the final URL (post-redirect) so a target
		// that started as http:// but redirected to https:// still gets its TLS
		// cert extracted, and a target that started https:// but ended http://
		// is skipped naturally.
		tlsTarget := target
		if pageReport.Result != nil && pageReport.Result.Request != nil &&
			pageReport.Result.Request.Response != nil &&
			pageReport.Result.Request.Response.FinalUrl != nil &&
			*pageReport.Result.Request.Response.FinalUrl != "" {
			tlsTarget = *pageReport.Result.Request.Response.FinalUrl
		}
		tlsCerts := extractTLSFromTarget(ctx, tlsTarget, config)
		if len(tlsCerts) > 0 {
			result.TlsCertificates = tlsCerts
		}
	}

	// Attach nuclei fingerprints for this target if available
	if nucleiResults != nil {
		if attempts, ok := nucleiResults[target]; ok {
			result.NucleiFingerprints = attempts
		}
	}

	if len(targetErrors) > 0 {
		result.Errors = targetErrors
	}
	return result
}

// RunWitness orchestrates the single-pass witness scan across all targets.
func RunWitness(ctx context.Context, config discover.DiscoverWitnessConfig, browserbaseSecrets *common.BrowserbaseRequestSecrets) (*discover.DiscoverWitnessReport, error) {
	log := svc1log.FromContext(ctx)

	report := &discover.DiscoverWitnessReport{
		Config:  &config,
		Results: []*discover.DiscoverWitnessTargetResult{},
	}
	var reportErrors []string

	// Load targets
	targets, err := loadTargets(config.Target, config.TargetsFile)
	if err != nil {
		reportErrors = append(reportErrors, err.Error())
		report.Errors = reportErrors
		return report, err
	}

	log.Info("Starting witness scan", svc1log.SafeParam("targetCount", len(targets)))

	// Load sensitive content fingerprints (if needed)
	var sensitiveContentFingerprints *discover.SensitiveContentFingerprints
	if config.SensitiveContentDetection {
		sensitiveContentFingerprints, err = discoverpagehelpers.LoadSensitiveConentFingerprints(ctx, config.SensitiveContentFingerprintsPath)
		if err != nil {
			reportErrors = append(reportErrors, fmt.Sprintf("failed to load sensitive content fingerprints: %s", err.Error()))
			report.Errors = reportErrors
			return report, err
		}
	}

	// Run Nuclei across all targets (if template paths are set)
	nucleiResults, nucleiErr := runNucleiForTargets(ctx, targets, config)
	if nucleiErr != nil {
		log.Warn("Nuclei fingerprinting failed", svc1log.SafeParam("error", nucleiErr.Error()))
		reportErrors = append(reportErrors, fmt.Sprintf("nuclei: %s", nucleiErr.Error()))
	}

	// Process each target
	results := make([]*discover.DiscoverWitnessTargetResult, 0, len(targets))
	for _, target := range targets {
		log.Info("Processing target", svc1log.SafeParam("target", target))
		targetResult := processTarget(ctx, target, config, sensitiveContentFingerprints, nucleiResults, browserbaseSecrets)
		results = append(results, targetResult)
	}

	report.Results = results
	if len(reportErrors) > 0 {
		report.Errors = reportErrors
	}
	return report, nil
}
