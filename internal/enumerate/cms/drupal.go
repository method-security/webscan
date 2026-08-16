package cms

import (
	// Standard
	"context"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	enumeratecmsdrupalfern "github.com/Method-Security/webscan/generated/go/enumerate/cms/drupal"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

// Module search paths
var drupalModulePaths = []string{
	"/modules/contrib/",
	"/modules/",
	"/sites/all/modules/contrib/",
	"/sites/default/modules/",
}

// Package-level compiled regexes
var (
	drupalMetaGeneratorRegex = regexp.MustCompile(`(?i)<meta\s+name=["']Generator["']\s+content=["']([^"']+)["']`)
	drupalVersionRegex       = regexp.MustCompile(`Drupal\s+(\d+(?:\.\d+)*)`)
	drupalContribModuleRegex = regexp.MustCompile(`/modules/contrib/([^/'"]+)/`)
	drupalCustomModuleRegex  = regexp.MustCompile(`/modules/custom/([^/'"]+)/`)
	drupalCSSReferenceRegex  = regexp.MustCompile(`href=['"]([^'"]*modules/contrib/([^/'"]+)/[^'"]*\.css[^'"]*?)['"]`)
	drupalJSReferenceRegex   = regexp.MustCompile(`src=['"]([^'"]*modules/contrib/([^/'"]+)/[^'"]*\.js[^'"]*?)['"]`)
)

// GetEnumerateDrupalModuleEmbeddedPath returns the embedded config path for the given module file size.
func GetEnumerateDrupalModuleEmbeddedPath(modulesFileSize enumeratecmsdrupalfern.ModulesFileSize) string {
	wordlistPaths := map[enumeratecmsdrupalfern.ModulesFileSize]string{
		enumeratecmsdrupalfern.ModulesFileSizeSmall: "enumerate/cms/drupal/modules_small.txt",
		enumeratecmsdrupalfern.ModulesFileSizeLarge: "enumerate/cms/drupal/modules_large.txt",
	}
	return wordlistPaths[modulesFileSize]
}

func createDrupalSendHTTPRequestConfig(baseURL, path string, method common.HttpMethod, maxRedirects int, config *enumeratecmsdrupalfern.EnumerateDrupalModulesConfig) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  method,
		Params:  &common.HttpRequestParams{},
	}
	return common.SendHttpRequestConfig{
		Request:                    &request,
		MaxRedirects:               maxRedirects,
		VerifyTls:                  config.VerifyTls,
		Timeout:                    config.Timeout,
		IgnoreCrossDomainRedirects: true,
		UserAgent:                  config.UserAgent,
		RequestMethod:              common.RequestMethodStandard,
		HeadlessConfig:             nil,
		BrowserbaseConfig:          nil,
		BrowserbaseSecrets:         nil,
	}
}

// PerformAppEnumerateCMSDrupalModules attempts to find modules installed on Drupal sites.
func PerformAppEnumerateCMSDrupalModules(ctx context.Context, config enumeratecmsdrupalfern.EnumerateDrupalModulesConfig) enumeratecmsdrupalfern.EnumerateDrupalModulesReport {
	report := enumeratecmsdrupalfern.EnumerateDrupalModulesReport{Config: &config, Result: &enumeratecmsdrupalfern.EnumerateDrupalModulesResult{}}

	// Create channels for collecting results and errors
	resultsChan := make(chan *enumeratecmsdrupalfern.DrupalModulesTarget, len(config.Targets))
	errorsChan := make(chan []string, len(config.Targets))

	// Create a wait group to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Determine number of concurrent goroutines
	maxGoroutines := runtime.GOMAXPROCS(0)
	if config.Threads > 0 {
		maxGoroutines = config.Threads
	}

	// Create a semaphore to limit concurrent goroutines
	semaphore := make(chan struct{}, maxGoroutines)

	// Process each target concurrently
	for _, target := range config.Targets {
		wg.Add(1)

		semaphore <- struct{}{}

		go func(target string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			result, errs := scanDrupalTarget(ctx, target, &config)
			resultsChan <- &result
			if len(errs) > 0 {
				errorsChan <- errs
			}
		}(target)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
		close(errorsChan)
	}()

	// Collect results and errors
	targetResults := []*enumeratecmsdrupalfern.DrupalModulesTarget{}
	errors := []string{}

	for result := range resultsChan {
		targetResults = append(targetResults, result)
	}

	for errs := range errorsChan {
		errors = append(errors, errs...)
	}

	report.Errors = errors
	report.Result.Targets = targetResults
	return report
}

// scanDrupalTarget scans a single Drupal site for modules
func scanDrupalTarget(ctx context.Context, url string, config *enumeratecmsdrupalfern.EnumerateDrupalModulesConfig) (enumeratecmsdrupalfern.DrupalModulesTarget, []string) {
	result := enumeratecmsdrupalfern.DrupalModulesTarget{
		Target:  url,
		Modules: []*enumeratecmsdrupalfern.DrupalModuleDetails{},
	}
	errors := []string{}

	// Send initial request to verify target is reachable
	baseURL, path, _, err := requesthelpers.SplitTargetURL(url)
	if err != nil {
		errors = append(errors, err.Error())
		return result, errors
	}

	requestConfig := createDrupalSendHTTPRequestConfig(baseURL, path, common.HttpMethodGet, cmsInitialMaxRedirects, config)
	accessRequest, err := request.SendRequest(ctx, requestConfig)
	if err != nil {
		errors = append(errors, err.Error())
		return result, errors
	}

	if statusCode := getResponseStatusCode(accessRequest); statusCode != 200 {
		return result, []string{fmt.Sprintf("non-200 status code from site: %d", statusCode)}
	}
	canonicalURL := canonicalTargetURL(url, accessRequest)
	baseURL, path, _, err = requesthelpers.SplitTargetURL(canonicalURL)
	if err != nil {
		errors = append(errors, err.Error())
		return result, errors
	}

	// Detect Drupal core version from response headers and body
	result.DrupalVersion = checkDrupalVersion(accessRequest)

	// 1. Brute-force module existence via LICENSE.txt (HEAD, full wordlist)
	licenseModules, errs := checkDrupalModuleLicense(ctx, baseURL, path, config)
	errors = append(errors, errs...)

	// 2. Brute-force module existence via README.md/README.txt (GET, full wordlist)
	readmeModules, errs := checkDrupalModuleReadme(ctx, baseURL, path, config)
	errors = append(errors, errs...)

	// 3. Brute-force module existence via info.yml (HEAD, full wordlist)
	infoYmlModules, errs := checkDrupalModuleInfoYml(ctx, baseURL, path, config)
	errors = append(errors, errs...)

	// Merge brute-force results to get full discovered set for changelog enrichment
	discoveredMap := make(map[string]*enumeratecmsdrupalfern.DrupalModuleDetails)
	mergeDrupalModules(discoveredMap, licenseModules)
	mergeDrupalModules(discoveredMap, readmeModules)
	mergeDrupalModules(discoveredMap, infoYmlModules)
	discoveredModules := make([]*enumeratecmsdrupalfern.DrupalModuleDetails, 0, len(discoveredMap))
	for _, m := range discoveredMap {
		discoveredModules = append(discoveredModules, m)
	}

	// 4. Check CHANGELOG.txt for version info on discovered modules (GET, discovered only)
	changelogModules, errs := checkDrupalModuleChangelogs(ctx, baseURL, path, config, discoveredModules)
	errors = append(errors, errs...)

	// 5. Passive detection from homepage HTML
	// Merge priority: changelog > readme > license > info.yml > passive
	modulesMap := make(map[string]*enumeratecmsdrupalfern.DrupalModuleDetails)
	mergeDrupalModules(modulesMap, changelogModules)
	mergeDrupalModules(modulesMap, readmeModules)
	mergeDrupalModules(modulesMap, licenseModules)
	mergeDrupalModules(modulesMap, infoYmlModules)

	responseBody := requesthelpers.GetResponseBodyStringFromBodyStruct(accessRequest.Response.ResponseBody)
	if responseBody == nil {
		errors = append(errors, fmt.Sprintf("no response body found for url: %s", url))
	} else {
		mergeDrupalModules(modulesMap, checkDrupalModulesInHTML(responseBody))
		mergeDrupalModules(modulesMap, checkDrupalAssetReferences(responseBody, drupalCSSReferenceRegex, enumeratecmsdrupalfern.DetectionSourceCssReference))
		mergeDrupalModules(modulesMap, checkDrupalAssetReferences(responseBody, drupalJSReferenceRegex, enumeratecmsdrupalfern.DetectionSourceJsReference))
	}

	// Convert map to slice
	result.Modules = make([]*enumeratecmsdrupalfern.DrupalModuleDetails, 0, len(modulesMap))
	for _, module := range modulesMap {
		result.Modules = append(result.Modules, module)
	}

	return result, errors
}

// checkDrupalVersion extracts Drupal core version from X-Generator header and meta tag
func checkDrupalVersion(accessRequest *common.HttpRequestResponse) *string {
	if accessRequest.Response == nil {
		return nil
	}

	// Check X-Generator header
	if accessRequest.Response.ResponseHeaders != nil {
		generator := requesthelpers.GetHeaderValueFromHeaderMap(accessRequest.Response.ResponseHeaders, "X-Generator")
		if generator != nil {
			if version := parseDrupalVersion(*generator); version != nil {
				return version
			}
		}
	}

	// Check meta generator tag in HTML body
	if accessRequest.Response.ResponseBody == nil {
		return nil
	}
	responseBody := requesthelpers.GetResponseBodyStringFromBodyStruct(accessRequest.Response.ResponseBody)
	if responseBody == nil {
		return nil
	}
	if match := drupalMetaGeneratorRegex.FindStringSubmatch(*responseBody); len(match) > 1 {
		return parseDrupalVersion(match[1])
	}

	return nil
}

// parseDrupalVersion extracts version from a string like "Drupal 11 (https://www.drupal.org)" or "Drupal 10.2.3"
func parseDrupalVersion(generator string) *string {
	match := drupalVersionRegex.FindStringSubmatch(generator)
	if len(match) > 1 {
		return &match[1]
	}
	return nil
}

// getResponseStatusCode returns the HTTP status code from a response, or 0 if unavailable.
func getResponseStatusCode(resp *common.HttpRequestResponse) int {
	if resp.Response == nil || resp.Response.StatusCode == nil {
		return 0
	}
	return *resp.Response.StatusCode
}

// checkDrupalModuleInfoYml brute-forces module existence by requesting each module's
// info.yml file across known Drupal module paths. Servers typically block direct access
// to .yml files, so a 403 indicates the file (and therefore the module) exists, while
// a 404 means it doesn't. A 200 is also treated as a match in case the server allows access.
func checkDrupalModuleInfoYml(ctx context.Context, baseURL, basePath string, config *enumeratecmsdrupalfern.EnumerateDrupalModulesConfig) ([]*enumeratecmsdrupalfern.DrupalModuleDetails, []string) {
	var modulesList []*enumeratecmsdrupalfern.DrupalModuleDetails
	var errors []string
	found := make(map[string]bool)

	for _, module := range config.Modules {
		if found[module] {
			continue
		}
		for _, modulePath := range drupalModulePaths {
			infoYmlPath := fmt.Sprintf("%s%s%s/%s.info.yml", basePath, modulePath, module, module)
			requestConfig := createDrupalSendHTTPRequestConfig(baseURL, infoYmlPath, common.HttpMethodHead, 0, config)
			resp, err := request.SendRequest(ctx, requestConfig)
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}

			if config.Sleep > 0 {
				delay := utils.CalculateDelayWithJitter(config.Sleep, config.Jitter)
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return modulesList, errors
				}
			}

			statusCode := getResponseStatusCode(resp)
			if statusCode != 403 && statusCode != 200 {
				continue
			}
			modulesList = append(modulesList, &enumeratecmsdrupalfern.DrupalModuleDetails{
				Name:   module,
				Source: []enumeratecmsdrupalfern.DetectionSource{enumeratecmsdrupalfern.DetectionSourceInfoYml},
			})
			found[module] = true
			break // Found in this path, skip remaining paths
		}
	}

	return modulesList, errors
}

// checkDrupalModuleChangelogs fetches CHANGELOG.txt for discovered modules to extract version info
func checkDrupalModuleChangelogs(ctx context.Context, baseURL, basePath string, config *enumeratecmsdrupalfern.EnumerateDrupalModulesConfig, discoveredModules []*enumeratecmsdrupalfern.DrupalModuleDetails) ([]*enumeratecmsdrupalfern.DrupalModuleDetails, []string) {
	var modulesList []*enumeratecmsdrupalfern.DrupalModuleDetails
	var errors []string

	for _, module := range discoveredModules {
		for _, modulePath := range drupalModulePaths {
			changelogPath := fmt.Sprintf("%s%s%s/CHANGELOG.txt", basePath, modulePath, module.Name)
			requestConfig := createDrupalSendHTTPRequestConfig(baseURL, changelogPath, common.HttpMethodGet, 0, config)
			resp, err := request.SendRequest(ctx, requestConfig)
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}

			if config.Sleep > 0 {
				delay := utils.CalculateDelayWithJitter(config.Sleep, config.Jitter)
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return modulesList, errors
				}
			}

			if getResponseStatusCode(resp) != 200 {
				continue
			}
			responseBody := requesthelpers.GetResponseBodyStringFromBodyStruct(resp.Response.ResponseBody)
			if responseBody == nil || *responseBody == "" {
				continue
			}
			version := parseDrupalModuleChangelog(*responseBody, module.Name)
			if version == nil {
				continue
			}
			modulesList = append(modulesList, &enumeratecmsdrupalfern.DrupalModuleDetails{
				Name:    module.Name,
				Version: version,
				Source:  []enumeratecmsdrupalfern.DetectionSource{enumeratecmsdrupalfern.DetectionSourceChangelog},
			})
			break
		}
	}

	return modulesList, errors
}

// checkDrupalModuleLicense brute-forces module existence by requesting each module's
// LICENSE.txt file across known Drupal module paths using HEAD requests.
// A 200 confirms the module exists.
func checkDrupalModuleLicense(ctx context.Context, baseURL, basePath string, config *enumeratecmsdrupalfern.EnumerateDrupalModulesConfig) ([]*enumeratecmsdrupalfern.DrupalModuleDetails, []string) {
	var modulesList []*enumeratecmsdrupalfern.DrupalModuleDetails
	var errors []string
	found := make(map[string]bool)

	for _, module := range config.Modules {
		if found[module] {
			continue
		}
		for _, modulePath := range drupalModulePaths {
			licensePath := fmt.Sprintf("%s%s%s/LICENSE.txt", basePath, modulePath, module)
			requestConfig := createDrupalSendHTTPRequestConfig(baseURL, licensePath, common.HttpMethodHead, 0, config)
			resp, err := request.SendRequest(ctx, requestConfig)
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}

			if config.Sleep > 0 {
				delay := utils.CalculateDelayWithJitter(config.Sleep, config.Jitter)
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return modulesList, errors
				}
			}

			if getResponseStatusCode(resp) != 200 {
				continue
			}
			modulesList = append(modulesList, &enumeratecmsdrupalfern.DrupalModuleDetails{
				Name:   module,
				Source: []enumeratecmsdrupalfern.DetectionSource{enumeratecmsdrupalfern.DetectionSourceLicense},
			})
			found[module] = true
			break
		}
	}

	return modulesList, errors
}

// checkDrupalModuleReadme brute-forces module existence by requesting each module's
// README.md or README.txt file across known Drupal module paths using GET requests.
// A 200 confirms the module exists; the response body is stored as the description.
func checkDrupalModuleReadme(ctx context.Context, baseURL, basePath string, config *enumeratecmsdrupalfern.EnumerateDrupalModulesConfig) ([]*enumeratecmsdrupalfern.DrupalModuleDetails, []string) {
	var modulesList []*enumeratecmsdrupalfern.DrupalModuleDetails
	var errors []string
	found := make(map[string]bool)
	readmeFiles := []string{"README.md", "README.txt"}

	for _, module := range config.Modules {
		if found[module] {
			continue
		}
		for _, modulePath := range drupalModulePaths {
			if found[module] {
				break
			}
			for _, readmeFile := range readmeFiles {
				readmePath := fmt.Sprintf("%s%s%s/%s", basePath, modulePath, module, readmeFile)
				requestConfig := createDrupalSendHTTPRequestConfig(baseURL, readmePath, common.HttpMethodGet, 0, config)
				resp, err := request.SendRequest(ctx, requestConfig)
				if err != nil {
					errors = append(errors, err.Error())
					continue
				}

				if config.Sleep > 0 {
					delay := utils.CalculateDelayWithJitter(config.Sleep, config.Jitter)
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						return modulesList, errors
					}
				}

				if getResponseStatusCode(resp) != 200 {
					continue
				}
				responseBody := requesthelpers.GetResponseBodyStringFromBodyStruct(resp.Response.ResponseBody)
				if responseBody == nil || *responseBody == "" {
					continue
				}
				modulesList = append(modulesList, &enumeratecmsdrupalfern.DrupalModuleDetails{
					Name:        module,
					Description: responseBody,
					Source:      []enumeratecmsdrupalfern.DetectionSource{enumeratecmsdrupalfern.DetectionSourceReadme},
				})
				found[module] = true
				break
			}
		}
	}

	return modulesList, errors
}

// parseDrupalModuleChangelog extracts version from CHANGELOG.txt first line
// Pattern: "{ModuleName} X.Y.Z, YYYY-MM-DD" or "{ModuleName} X.Y.Z"
func parseDrupalModuleChangelog(changelog, moduleName string) *string {
	firstLine := strings.SplitN(changelog, "\n", 2)[0]
	// Match version pattern: module name followed by version number
	versionRegex := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(moduleName) + `\s+(\d+\.\d+[\d.]*)`)
	match := versionRegex.FindStringSubmatch(firstLine)
	if len(match) > 1 {
		return &match[1]
	}
	return nil
}

// checkDrupalModulesInHTML scans HTML for module references in /modules/contrib/ and /modules/custom/ paths
func checkDrupalModulesInHTML(responseBody *string) []*enumeratecmsdrupalfern.DrupalModuleDetails {
	modules := []*enumeratecmsdrupalfern.DrupalModuleDetails{}

	patterns := []*regexp.Regexp{
		drupalContribModuleRegex,
		drupalCustomModuleRegex,
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(*responseBody, -1)
		for _, match := range matches {
			if len(match) > 1 {
				modules = append(modules, &enumeratecmsdrupalfern.DrupalModuleDetails{
					Name:   match[1],
					Source: []enumeratecmsdrupalfern.DetectionSource{enumeratecmsdrupalfern.DetectionSourceHtml},
				})
			}
		}
	}

	return modules
}

// checkDrupalAssetReferences looks for module-specific asset files (CSS/JS) in HTML
func checkDrupalAssetReferences(responseBody *string, regex *regexp.Regexp, source enumeratecmsdrupalfern.DetectionSource) []*enumeratecmsdrupalfern.DrupalModuleDetails {
	modules := []*enumeratecmsdrupalfern.DrupalModuleDetails{}

	matches := regex.FindAllStringSubmatch(*responseBody, -1)

	for _, match := range matches {
		if len(match) > 2 {
			modules = append(modules, &enumeratecmsdrupalfern.DrupalModuleDetails{
				Name:   match[2],
				Source: []enumeratecmsdrupalfern.DetectionSource{source},
			})
		}
	}

	return modules
}

// hasNonEmptyString returns true if the pointer is non-nil and non-empty.
func hasNonEmptyString(s *string) bool {
	return s != nil && *s != ""
}

// mergeDrupalModules merges a list of modules into an existing map, handling duplicates
func mergeDrupalModules(modules map[string]*enumeratecmsdrupalfern.DrupalModuleDetails, moduleList []*enumeratecmsdrupalfern.DrupalModuleDetails) {
	for _, module := range moduleList {
		existing, exists := modules[module.Name]
		if !exists {
			modules[module.Name] = module
			continue
		}

		// Merge sources without duplicates
		sourceSet := make(map[enumeratecmsdrupalfern.DetectionSource]bool, len(existing.Source)+len(module.Source))
		for _, src := range existing.Source {
			sourceSet[src] = true
		}
		for _, src := range module.Source {
			sourceSet[src] = true
		}
		existing.Source = make([]enumeratecmsdrupalfern.DetectionSource, 0, len(sourceSet))
		for src := range sourceSet {
			existing.Source = append(existing.Source, src)
		}

		if !hasNonEmptyString(existing.Version) && hasNonEmptyString(module.Version) {
			existing.Version = module.Version
		}
		if !hasNonEmptyString(existing.Description) && hasNonEmptyString(module.Description) {
			existing.Description = module.Description
		}
	}
}
