package cms

import (
	// Standard
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	enumeratecmswordpressfern "github.com/Method-Security/webscan/generated/go/enumerate/cms/wordpress"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

// GetEnumerateWordpressPluginEmbeddedPath returns the embedded config path for the given plugin file size.
func GetEnumerateWordpressPluginEmbeddedPath(PluginsFileSize enumeratecmswordpressfern.PluginsFileSize) string {
	wordlistPaths := map[enumeratecmswordpressfern.PluginsFileSize]string{
		enumeratecmswordpressfern.PluginsFileSizeSmall: "enumerate/cms/wordpress/plugins_small.txt",
		enumeratecmswordpressfern.PluginsFileSizeLarge: "enumerate/cms/wordpress/plugins_large.txt",
	}
	return wordlistPaths[PluginsFileSize]
}

func createSendHTTPRequestConfig(baseURL, path string, config *enumeratecmswordpressfern.EnumerateWordpressPluginsConfig) common.SendHttpRequestConfig {
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params:  &common.HttpRequestParams{},
	}
	return common.SendHttpRequestConfig{
		Request:            &request,
		MaxRedirects:       0,
		VerifyTls:          config.VerifyTls,
		Timeout:            config.Timeout,
		RequestMethod:      common.RequestMethodStandard,
		HeadlessConfig:     nil,
		BrowserbaseConfig:  nil,
		BrowserbaseSecrets: nil,
	}
}

// PerformAppEnumerateCMSWordpressPlugins attempts to find plugins installed on WordPress sites.
// It returns a report containing the results for each target and any errors encountered.
func PerformAppEnumerateCMSWordpressPlugins(ctx context.Context, config enumeratecmswordpressfern.EnumerateWordpressPluginsConfig) enumeratecmswordpressfern.EnumerateWordpressPluginsReport {
	report := enumeratecmswordpressfern.EnumerateWordpressPluginsReport{Config: &config, Result: &enumeratecmswordpressfern.EnumerateWordpressPluginsResult{}}

	// Create channels for collecting results and errors
	resultsChan := make(chan *enumeratecmswordpressfern.WordpressPluginsTarget, len(config.Targets))
	errorsChan := make(chan []string, len(config.Targets))

	// Create a wait group to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Determine number of concurrent goroutines
	maxGoroutines := runtime.GOMAXPROCS(0) // Default to number of CPUs
	if config.Threads > 0 {
		maxGoroutines = config.Threads
	}

	// Create a semaphore to limit concurrent goroutines
	semaphore := make(chan struct{}, maxGoroutines)

	// Process each target concurrently
	for _, target := range config.Targets {
		wg.Add(1)

		// Acquire semaphore (blocks if maxGoroutines are running)
		semaphore <- struct{}{}

		go func(target string) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release semaphore when done

			result, errs := scanTarget(ctx, target, &config)
			resultsChan <- &result
			if len(errs) > 0 {
				errorsChan <- errs
			}
		}(target)
	}

	// Start a goroutine to close channels after all workers are done
	go func() {
		wg.Wait()
		close(resultsChan)
		close(errorsChan)
	}()

	// Collect results and errors
	targetResults := []*enumeratecmswordpressfern.WordpressPluginsTarget{}
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

// scanTarget scans a single WordPress site for plugins
func scanTarget(ctx context.Context, url string, config *enumeratecmswordpressfern.EnumerateWordpressPluginsConfig) (enumeratecmswordpressfern.WordpressPluginsTarget, []string) {
	result := enumeratecmswordpressfern.WordpressPluginsTarget{
		Target:  url,
		Plugins: []*enumeratecmswordpressfern.WordpressPluginDetails{},
	}
	errors := []string{}

	// Send initial request
	baseURL, path, _, err := requesthelpers.SplitTargetURL(url)
	if err != nil {
		errors = append(errors, err.Error())
		return result, errors
	}

	requestConfig := createSendHTTPRequestConfig(baseURL, path, config)
	accessRequest, err := request.SendRequest(ctx, requestConfig)
	if err != nil {
		errors = append(errors, err.Error())
		return result, errors
	}

	if accessRequest.Response != nil && accessRequest.Response.StatusCode != nil && *accessRequest.Response.StatusCode != 200 {
		return result, []string{fmt.Sprintf("non-200 status code from site: %d", *accessRequest.Response.StatusCode)}
	}

	// Run different detection methods
	// Path based + Bruteforce Plugin Detection
	apiPlugins, errs := checkWordPressAPI(ctx, url, config)
	if len(errs) > 0 {
		errors = append(errors, errs...)
	}
	readmePlugins, errs := checkReadmeFiles(ctx, url, config)
	if len(errs) > 0 {
		errors = append(errors, errs...)
	}
	// Base response body detection methods
	responseBody := requesthelpers.GetResponseBodyStringFromBodyStruct(accessRequest.Response.ResponseBody)
	htmlPlugins := []*enumeratecmswordpressfern.WordpressPluginDetails{}
	registeredPlugins := []*enumeratecmswordpressfern.WordpressPluginDetails{}
	cssPlugins := []*enumeratecmswordpressfern.WordpressPluginDetails{}
	if responseBody != nil {
		htmlPlugins = checkHTMLForPlugins(responseBody)
		registeredPlugins = checkRegisteredPlugins(responseBody)
		cssPlugins = checkCSSReferences(responseBody)
	} else {
		errors = append(errors, fmt.Sprintf("no response body found for url: %s", url))
	}

	// Combine results with proper deduplication
	pluginsMap := make(map[string]*enumeratecmswordpressfern.WordpressPluginDetails)

	// Merge and Deduplicate plugins from all sources
	mergePlugins(pluginsMap, readmePlugins) // Prioritize data from readme.txt as its the densest source
	mergePlugins(pluginsMap, apiPlugins)
	mergePlugins(pluginsMap, htmlPlugins)
	mergePlugins(pluginsMap, registeredPlugins)
	mergePlugins(pluginsMap, cssPlugins)

	// Convert map to slice
	result.Plugins = make([]*enumeratecmswordpressfern.WordpressPluginDetails, 0, len(pluginsMap))
	for _, plugin := range pluginsMap {
		result.Plugins = append(result.Plugins, plugin)
	}

	return result, errors
}

// mergePlugins merges a list of plugins into an existing map, handling duplicates properly
func mergePlugins(plugins map[string]*enumeratecmswordpressfern.WordpressPluginDetails, pluginList []*enumeratecmswordpressfern.WordpressPluginDetails) {
	for _, plugin := range pluginList {
		if existing, exists := plugins[plugin.Name]; exists {
			// Merge sources without duplicates
			sourceMap := make(map[enumeratecmswordpressfern.DetectionSource]bool)

			// Add existing sources to map
			for _, src := range existing.Source {
				sourceMap[src] = true
			}

			// Add new sources to map if not already present
			for _, src := range plugin.Source {
				sourceMap[src] = true
			}

			// Rebuild source list from map
			existing.Source = make([]enumeratecmswordpressfern.DetectionSource, 0, len(sourceMap))
			for src := range sourceMap {
				existing.Source = append(existing.Source, src)
			}

			// Only update version if current is empty and new one isn't
			if (existing.Version == nil || *existing.Version == "") &&
				plugin.Version != nil && *plugin.Version != "" {
				existing.Version = plugin.Version
			}

			// Only update description if current is empty and new one isn't
			if (existing.Description == nil || *existing.Description == "") &&
				plugin.Description != nil && *plugin.Description != "" {
				existing.Description = plugin.Description
			}
		} else {
			// New plugin, add to map
			plugins[plugin.Name] = plugin
		}
	}
}

// checkWordPressAPI checks the /wp-json endpoint for exposed plugin data
func checkWordPressAPI(ctx context.Context, url string, config *enumeratecmswordpressfern.EnumerateWordpressPluginsConfig) ([]*enumeratecmswordpressfern.WordpressPluginDetails, []string) {
	pluginsList := []*enumeratecmswordpressfern.WordpressPluginDetails{}
	errors := []string{}

	// Check main REST API endpoint
	baseURL, path, _, err := requesthelpers.SplitTargetURL(url)
	if err != nil {
		errors = append(errors, err.Error())
		return pluginsList, errors
	}
	apiPath := fmt.Sprintf("%s/wp-json", path)
	requestConfig := createSendHTTPRequestConfig(baseURL, apiPath, config)
	apiRequest, err := request.SendRequest(ctx, requestConfig)
	if err != nil {
		errors = append(errors, err.Error())
		return pluginsList, errors
	}

	if apiRequest.Response != nil && apiRequest.Response.StatusCode != nil && *apiRequest.Response.StatusCode != 200 {
		errors = append(errors, fmt.Sprintf("none successful response from site: %d", *apiRequest.Response.StatusCode))
		return pluginsList, errors
	}

	var apiResponse enumeratecmswordpressfern.WordpressApiResponse
	responseBody := requesthelpers.GetResponseBodyStringFromBodyStruct(apiRequest.Response.ResponseBody)
	if responseBody == nil {
		errors = append(errors, "no response body found")
		return pluginsList, errors
	}
	if err := json.Unmarshal([]byte(*responseBody), &apiResponse); err == nil {
		// Look for plugin namespaces (they often start with plugin-specific prefixes)
		for _, namespace := range apiResponse.Namespaces {
			// Plugins typically register their REST API namespaces in the format 'plugin-name/v1' or 'plugin-name/version-number',
			// where 'plugin-name' is the unique identifier for the plugin, and the segment after the slash indicates the API version.
			// See if plugin is in list
			parts := strings.Split(namespace, "/")
			potentiallyCommonPlugin := parts[0]

			// Only add plugin if it's in the list of plugins to check to prevent false positives
			if !slices.Contains(config.Plugins, potentiallyCommonPlugin) {
				continue
			}

			// Extract version if available
			var version *string
			if len(parts) > 1 {
				version = &parts[1]
			}

			// Add plugin to list
			pluginsList = append(pluginsList, &enumeratecmswordpressfern.WordpressPluginDetails{
				Name:    potentiallyCommonPlugin,
				Version: version,
				Source:  []enumeratecmswordpressfern.DetectionSource{enumeratecmswordpressfern.DetectionSourceRestApiDirect},
			})

		}

		// Check routes for plugin endpoints
		fetchedFromRoute := false
		for route := range apiResponse.Routes {
			if strings.Contains(route, "/wp/v2/plugins") {
				// Try to fetch plugin list directly if available
				pluginsFromRoutes := fetchPluginsFromAPI(ctx, url, "/wp-json/wp/v2/plugins", config)
				pluginsList = append(pluginsList, pluginsFromRoutes...)
				fetchedFromRoute = true
				break
			}
		}

		// Fallback: also try the plugins endpoint even if not listed in routes
		if !fetchedFromRoute {
			pluginsList = append(pluginsList, fetchPluginsFromAPI(ctx, url, "/wp-json/wp/v2/plugins", config)...)
		}
	}

	return pluginsList, errors
}

// fetchPluginsFromAPI tries to get plugin info directly from the API
func fetchPluginsFromAPI(ctx context.Context, baseURL string, path string, config *enumeratecmswordpressfern.EnumerateWordpressPluginsConfig) []*enumeratecmswordpressfern.WordpressPluginDetails {
	// Initialize Plugin List
	plugins := []*enumeratecmswordpressfern.WordpressPluginDetails{}

	// Send Request
	apiRequestConfig := createSendHTTPRequestConfig(baseURL, path, config)
	apiRequest, err := request.SendRequest(ctx, apiRequestConfig)
	if err != nil || apiRequest.Response != nil && apiRequest.Response.StatusCode != nil && *apiRequest.Response.StatusCode != 200 {
		return plugins
	}

	// Try to parse as JSON array of plugins
	var pluginList []map[string]interface{}
	responseBody := requesthelpers.GetResponseBodyStringFromBodyStruct(apiRequest.Response.ResponseBody)
	if responseBody == nil {
		return plugins
	}
	if err := json.Unmarshal([]byte(*responseBody), &pluginList); err == nil {
		for _, pluginData := range pluginList {
			name, _ := pluginData["name"].(string)
			version, _ := pluginData["version"].(string)
			description, _ := pluginData["description"].(string)
			plugin := &enumeratecmswordpressfern.WordpressPluginDetails{
				Name:        name,
				Version:     &version,
				Description: &description,
				Source:      []enumeratecmswordpressfern.DetectionSource{enumeratecmswordpressfern.DetectionSourceRestApiDirect},
			}
			plugins = append(plugins, plugin)
		}
	}

	return plugins
}

// checkHTMLForPlugins scans the HTML for common plugin paths
func checkHTMLForPlugins(baseResponseBody *string) []*enumeratecmswordpressfern.WordpressPluginDetails {
	// Initialize Plugin List
	plugins := []*enumeratecmswordpressfern.WordpressPluginDetails{}

	// Different regex patterns to find plugin references
	patterns := []struct {
		regex     *regexp.Regexp
		nameGroup int
	}{
		{
			// wp-content/plugins/{plugin-name}/
			regex:     regexp.MustCompile(`/wp-content/plugins/([^/'"]+)/?`),
			nameGroup: 1,
		},
		{
			// wp-content/plugins/{plugin-name}/js/script.js?ver=3.2.1
			regex:     regexp.MustCompile(`/wp-content/plugins/([^/'"]+)/[^?]+((?:\?|&amp;)ver=([0-9.]+))`),
			nameGroup: 1,
		},
	}

	// Loop through patterns and extract plugins
	// Regex Info:
	// match[0] = full match
	// match[1] = plugin name
	// match[2] = version
	for _, pattern := range patterns {
		matches := pattern.regex.FindAllStringSubmatch(*baseResponseBody, -1)
		for _, match := range matches {
			if len(match) > pattern.nameGroup {
				// Extract plugin name
				name := match[pattern.nameGroup]

				// Extract version if available
				var version *string
				if len(match) > 2 && strings.Contains(match[2], "ver=") {
					verParts := strings.Split(match[2], "ver=")
					if len(verParts) > 1 {
						version = &strings.Split(verParts[1], "&")[0]
					}
				}

				// Add plugin to map
				plugins = append(plugins, &enumeratecmswordpressfern.WordpressPluginDetails{
					Name:    name,
					Version: version,
					Source:  []enumeratecmswordpressfern.DetectionSource{enumeratecmswordpressfern.DetectionSourceHtml},
				})
			}
		}
	}

	return plugins
}

// checkReadmeFiles tests for known plugin files
func checkReadmeFiles(ctx context.Context, url string, config *enumeratecmswordpressfern.EnumerateWordpressPluginsConfig) ([]*enumeratecmswordpressfern.WordpressPluginDetails, []string) {
	// Initialize Plugin List
	pluginsList := []*enumeratecmswordpressfern.WordpressPluginDetails{}
	errors := []string{}

	// Loop through plugins and check for readme.txt
	for i, plugin := range config.Plugins {
		baseURL, path, _, err := requesthelpers.SplitTargetURL(url)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		readmePath := fmt.Sprintf("%s/wp-content/plugins/%s/readme.txt", path, plugin)
		requestConfig := createSendHTTPRequestConfig(baseURL, readmePath, config)
		readmeRequest, err := request.SendRequest(ctx, requestConfig)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		// Apply stealth delay between requests
		if config.Sleep > 0 && i < len(config.Plugins)-1 {
			delay := utils.CalculateDelayWithJitter(config.Sleep, config.Jitter)
			time.Sleep(delay)
		}
		if readmeRequest.Response != nil && readmeRequest.Response.StatusCode != nil && *readmeRequest.Response.StatusCode != 200 {
			continue
		}

		// If readme.txt is empty, it's not a real plugin
		if requesthelpers.GetResponseBodyStringFromBodyStruct(readmeRequest.Response.ResponseBody) == nil || *requesthelpers.GetResponseBodyStringFromBodyStruct(readmeRequest.Response.ResponseBody) == "" {
			continue
		}

		// Try to extract version from readme.txt
		versionRegex := regexp.MustCompile(`(?i)stable tag:\s*([0-9.]+)`)
		versionMatch := versionRegex.FindStringSubmatch(*requesthelpers.GetResponseBodyStringFromBodyStruct(readmeRequest.Response.ResponseBody))
		var version *string

		// Regex Info:
		// versionMatch[0] = full match
		// versionMatch[1] = version
		if len(versionMatch) > 1 {
			version = &versionMatch[1]
		}

		// Extract description if available
		var description *string
		if requesthelpers.GetResponseBodyStringFromBodyStruct(readmeRequest.Response.ResponseBody) != nil && *requesthelpers.GetResponseBodyStringFromBodyStruct(readmeRequest.Response.ResponseBody) != "" {
			description = requesthelpers.GetResponseBodyStringFromBodyStruct(readmeRequest.Response.ResponseBody)
		}

		// Add plugin to list
		pluginsList = append(pluginsList, &enumeratecmswordpressfern.WordpressPluginDetails{
			Name:        plugin,
			Version:     version,
			Description: description,
			Source:      []enumeratecmswordpressfern.DetectionSource{enumeratecmswordpressfern.DetectionSourceReadmeTxt},
		})
	}

	return pluginsList, errors
}

// checkRegisteredPlugins checks for plugin registration in the page source
func checkRegisteredPlugins(baseResponseBody *string) []*enumeratecmswordpressfern.WordpressPluginDetails {
	// Initialize Plugin List
	plugins := []*enumeratecmswordpressfern.WordpressPluginDetails{}

	// Look for wp_register_script, wp_enqueue_script, etc. with plugin names
	regex := regexp.MustCompile(`/wp-content/plugins/([^/'"]+)/`)
	matches := regex.FindAllStringSubmatch(*baseResponseBody, -1)

	// Regex Info:
	// match[0] = full match
	// match[1] = plugin name
	for _, match := range matches {
		if len(match) > 1 {
			plugins = append(plugins, &enumeratecmswordpressfern.WordpressPluginDetails{
				Name:   match[1],
				Source: []enumeratecmswordpressfern.DetectionSource{enumeratecmswordpressfern.DetectionSourceRegisteredScript},
			})
		}
	}

	return plugins
}

// checkCSSReferences looks for plugin-specific CSS files
func checkCSSReferences(baseResponseBody *string) []*enumeratecmswordpressfern.WordpressPluginDetails {
	// Initialize Plugin List
	plugins := []*enumeratecmswordpressfern.WordpressPluginDetails{}

	// Look for CSS links with plugin references
	regex := regexp.MustCompile(`href=['"]([^'"]*wp-content/plugins/([^/'"]+)/[^'"]*\.css[^'"]*?)['"]`)
	matches := regex.FindAllStringSubmatch(*baseResponseBody, -1)

	// Regex Info:
	// match[0] = full match
	// match[1] = css path
	// match[2] = plugin name
	for _, match := range matches {
		if len(match) > 2 {
			cssPath := match[1]
			pluginName := match[2]

			// Extract version if available
			var version *string
			if strings.Contains(cssPath, "ver=") {
				versionRegex := regexp.MustCompile(`ver=([0-9.]+)`)
				versionMatch := versionRegex.FindStringSubmatch(cssPath)

				// Regex Info:
				// versionMatch[0] = full match
				// versionMatch[1] = version
				if len(versionMatch) > 1 {
					version = &versionMatch[1]
				}
			}

			// Add plugin to list
			plugins = append(plugins, &enumeratecmswordpressfern.WordpressPluginDetails{
				Name:    pluginName,
				Version: version,
				Source:  []enumeratecmswordpressfern.DetectionSource{enumeratecmswordpressfern.DetectionSourceCssReference},
			})
		}
	}

	return plugins
}
