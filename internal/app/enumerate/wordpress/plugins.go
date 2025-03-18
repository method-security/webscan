package enumerate

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"sync"

	enumerateWordpressFern "github.com/Method-Security/webscan/generated/go/app/enumerate/wordpress"
	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

// WordPressAPIResponse represents a simplified structure of the WordPress API response
type WordPressAPIResponse struct {
	Namespaces []string               `json:"namespaces"`
	Routes     map[string]interface{} `json:"routes"`
}

// PerformAppEnumerateWordpressPlugins attempts to find plugins installed on WordPress sites
func PerformAppEnumerateWordpressPlugins(ctx context.Context, config *enumerateWordpressFern.AppEnumerateWordpressPluginsConfig) enumerateWordpressFern.AppEnumerateWordpressPluginsReport {
	report := enumerateWordpressFern.AppEnumerateWordpressPluginsReport{Config: config}

	// Create channels for collecting results and errors
	resultsChan := make(chan *enumerateWordpressFern.AppEnumerateWordpressPluginsTargetInfo, len(config.Targets))
	errorsChan := make(chan []string, len(config.Targets))

	// Create a wait group to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Determine number of concurrent goroutines
	maxGoroutines := runtime.GOMAXPROCS(0) // Default to number of CPUs
	if config.Threads != nil {
		maxGoroutines = *config.Threads
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

			result, errs := scanTarget(target, config.Plugins, config.Timeout)
			resultsChan <- &result
			if len(errs) > 0 {
				errorsChan <- errs
			}
		}(target)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(resultsChan)
	close(errorsChan)

	// Collect results and errors
	targetResults := []*enumerateWordpressFern.AppEnumerateWordpressPluginsTargetInfo{}
	errors := []string{}

	for result := range resultsChan {
		targetResults = append(targetResults, result)
	}

	for errs := range errorsChan {
		errors = append(errors, errs...)
	}

	report.Errors = errors
	report.Targets = targetResults
	return report
}

// scanTarget scans a single WordPress site for plugins
func scanTarget(url string, plugins []string, timeout int) (enumerateWordpressFern.AppEnumerateWordpressPluginsTargetInfo, []string) {
	result := enumerateWordpressFern.AppEnumerateWordpressPluginsTargetInfo{
		Target:  url,
		Plugins: []*enumerateWordpressFern.WordpressPlugin{},
	}
	errors := []string{}

	// See if target is accessible
	accessRequest := utils.PerformRequestScan(url, "", common.HttpMethodGet, common.RequestParams{}, timeout)
	if accessRequest.Errors != nil {
		return result, accessRequest.Errors
	}

	if *accessRequest.StatusCode != 200 {
		return result, []string{fmt.Sprintf("non-200 status code from site: %d", *accessRequest.StatusCode)}
	}

	// Run different detection methods
	// Path based + Bruteforce Plugin Detection
	apiPlugins, errs := checkWordPressAPI(url, plugins, timeout)
	if len(errs) > 0 {
		errors = append(errors, errs...)
	}
	readmePlugins, errs := checkReadmeFiles(url, plugins, timeout)
	if len(errs) > 0 {
		errors = append(errors, errs...)
	}
	// Base response body detection methods
	htmlPlugins := checkHTMLForPlugins(accessRequest.ResponseBody)
	registeredPlugins := checkRegisteredPlugins(accessRequest.ResponseBody)
	cssPlugins := checkCSSReferences(accessRequest.ResponseBody)

	// Combine results with proper deduplication
	pluginsMap := make(map[string]*enumerateWordpressFern.WordpressPlugin)

	// Merge and Deduplicate plugins from all sources
	mergePlugins(pluginsMap, readmePlugins) // Prioritize data from readme.txt as its the densest source
	mergePlugins(pluginsMap, apiPlugins)
	mergePlugins(pluginsMap, htmlPlugins)
	mergePlugins(pluginsMap, registeredPlugins)
	mergePlugins(pluginsMap, cssPlugins)

	// Convert map to slice
	result.Plugins = make([]*enumerateWordpressFern.WordpressPlugin, 0, len(pluginsMap))
	for _, plugin := range pluginsMap {
		result.Plugins = append(result.Plugins, plugin)
	}

	return result, errors
}

// mergePlugins merges a list of plugins into an existing map, handling duplicates properly
func mergePlugins(plugins map[string]*enumerateWordpressFern.WordpressPlugin, pluginList []*enumerateWordpressFern.WordpressPlugin) {
	for _, plugin := range pluginList {
		if existing, exists := plugins[plugin.Name]; exists {
			// Merge sources without duplicates
			sourceMap := make(map[enumerateWordpressFern.DetectionSource]bool)

			// Add existing sources to map
			for _, src := range existing.Source {
				sourceMap[src] = true
			}

			// Add new sources to map if not already present
			for _, src := range plugin.Source {
				sourceMap[src] = true
			}

			// Rebuild source list from map
			existing.Source = make([]enumerateWordpressFern.DetectionSource, 0, len(sourceMap))
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
func checkWordPressAPI(url string, plugins []string, timeout int) ([]*enumerateWordpressFern.WordpressPlugin, []string) {
	pluginsList := []*enumerateWordpressFern.WordpressPlugin{}
	errors := []string{}

	// Check main REST API endpoint
	apiRequest := utils.PerformRequestScan(url, "/wp-json", common.HttpMethodGet, common.RequestParams{}, timeout)
	if apiRequest.Errors != nil {
		errors = append(errors, apiRequest.Errors...)
		return pluginsList, errors
	}

	if *apiRequest.StatusCode != 200 {
		errors = append(errors, fmt.Sprintf("none successful response from site: %d", *apiRequest.StatusCode))
		return pluginsList, errors
	}

	var apiResponse WordPressAPIResponse
	if err := json.Unmarshal([]byte(*apiRequest.ResponseBody), &apiResponse); err == nil {
		// Look for plugin namespaces (they often start with plugin-specific prefixes)
		for _, namespace := range apiResponse.Namespaces {
			// Plugins typically register their REST API namespaces in the format 'plugin-name/v1' or 'plugin-name/version-number',
			// where 'plugin-name' is the unique identifier for the plugin, and the segment after the slash indicates the API version.
			// See if plugin is in list
			parts := strings.Split(namespace, "/")
			potentiallyCommonPlugin := parts[0]

			// Only add plugin if it's in the list of plugins to check to prevent false positives
			if !containsString(plugins, potentiallyCommonPlugin) {
				continue
			}

			// Extract version if available
			var version *string
			if len(parts) > 1 {
				version = &parts[1]
			}

			// Add plugin to list
			pluginsList = append(pluginsList, &enumerateWordpressFern.WordpressPlugin{
				Name:    potentiallyCommonPlugin,
				Version: version,
				Source:  []enumerateWordpressFern.DetectionSource{enumerateWordpressFern.DetectionSourceRestApiDirect},
			})

		}

		// Check routes for plugin endpoints
		for route := range apiResponse.Routes {
			if strings.Contains(route, "/wp/v2/plugins") {
				// Try to fetch plugin list directly if available
				pluginsFromRoutes := fetchPluginsFromAPI(url, "/wp-json/wp/v2/plugins")
				pluginsList = append(pluginsList, pluginsFromRoutes...)
				break
			}
		}
	}

	// Also check the older /wp-json/wp/v2/ endpoint
	pluginsList = append(pluginsList, fetchPluginsFromAPI(url, "/wp-json/wp/v2/plugins")...)

	return pluginsList, errors
}

// fetchPluginsFromAPI tries to get plugin info directly from the API
func fetchPluginsFromAPI(baseURL string, path string) []*enumerateWordpressFern.WordpressPlugin {
	plugins := []*enumerateWordpressFern.WordpressPlugin{}

	apiRequest := utils.PerformRequestScan(baseURL, path, common.HttpMethodGet, common.RequestParams{}, 10)
	if apiRequest.Errors != nil || *apiRequest.StatusCode != 200 {
		return plugins
	}

	// Try to parse as JSON array of plugins
	var pluginList []map[string]interface{}
	if err := json.Unmarshal([]byte(*apiRequest.ResponseBody), &pluginList); err == nil {
		for _, pluginData := range pluginList {
			name, _ := pluginData["name"].(string)
			version, _ := pluginData["version"].(string)
			description, _ := pluginData["description"].(string)
			plugin := &enumerateWordpressFern.WordpressPlugin{
				Name:        name,
				Version:     &version,
				Description: &description,
				Source:      []enumerateWordpressFern.DetectionSource{enumerateWordpressFern.DetectionSourceRestApiDirect},
			}
			plugins = append(plugins, plugin)
		}
	}

	return plugins
}

// checkHTMLForPlugins scans the HTML for common plugin paths
func checkHTMLForPlugins(baseResponseBody *string) []*enumerateWordpressFern.WordpressPlugin {
	plugins := []*enumerateWordpressFern.WordpressPlugin{}

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
				plugins = append(plugins, &enumerateWordpressFern.WordpressPlugin{
					Name:    name,
					Version: version,
					Source:  []enumerateWordpressFern.DetectionSource{enumerateWordpressFern.DetectionSourceHtml},
				})
			}
		}
	}

	return plugins
}

// checkReadmeFiles tests for known plugin files
func checkReadmeFiles(url string, plugins []string, timeout int) ([]*enumerateWordpressFern.WordpressPlugin, []string) {
	pluginsList := []*enumerateWordpressFern.WordpressPlugin{}
	errors := []string{}

	// Loop through plugins and check for readme.txt
	for _, plugin := range plugins {
		path := fmt.Sprintf("/wp-content/plugins/%s/readme.txt", plugin)
		readmeRequest := utils.PerformRequestScan(url, path, common.HttpMethodGet, common.RequestParams{}, timeout)
		if readmeRequest.Errors != nil {
			errors = append(errors, readmeRequest.Errors...)
			continue
		}
		if readmeRequest.StatusCode != nil && *readmeRequest.StatusCode != 200 {
			continue
		}

		// Try to extract version from readme.txt
		versionRegex := regexp.MustCompile(`(?i)stable tag:\s*([0-9.]+)`)
		versionMatch := versionRegex.FindStringSubmatch(*readmeRequest.ResponseBody)
		var version *string

		// Regex Info:
		// versionMatch[0] = full match
		// versionMatch[1] = version
		if len(versionMatch) > 1 {
			version = &versionMatch[1]
		}

		// Extract description if available
		var description *string
		if readmeRequest.ResponseBody != nil && *readmeRequest.ResponseBody != "" {
			description = readmeRequest.ResponseBody
		}

		// Add plugin to list
		pluginsList = append(pluginsList, &enumerateWordpressFern.WordpressPlugin{
			Name:        plugin,
			Version:     version,
			Description: description,
			Source:      []enumerateWordpressFern.DetectionSource{enumerateWordpressFern.DetectionSourceReadmeTxt},
		})
	}

	return pluginsList, errors
}

// checkRegisteredPlugins checks for plugin registration in the page source
func checkRegisteredPlugins(baseResponseBody *string) []*enumerateWordpressFern.WordpressPlugin {
	plugins := []*enumerateWordpressFern.WordpressPlugin{}

	// Look for wp_register_script, wp_enqueue_script, etc. with plugin names
	regex := regexp.MustCompile(`/wp-content/plugins/([^/'"]+)/`)
	matches := regex.FindAllStringSubmatch(*baseResponseBody, -1)

	// Regex Info:
	// match[0] = full match
	// match[1] = plugin name
	for _, match := range matches {
		if len(match) > 1 {
			plugins = append(plugins, &enumerateWordpressFern.WordpressPlugin{
				Name:   match[1],
				Source: []enumerateWordpressFern.DetectionSource{enumerateWordpressFern.DetectionSourceRegisteredScript},
			})
		}
	}

	return plugins
}

// checkCSSReferences looks for plugin-specific CSS files
func checkCSSReferences(baseResponseBody *string) []*enumerateWordpressFern.WordpressPlugin {
	plugins := []*enumerateWordpressFern.WordpressPlugin{}

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
			plugins = append(plugins, &enumerateWordpressFern.WordpressPlugin{
				Name:    pluginName,
				Version: version,
				Source:  []enumerateWordpressFern.DetectionSource{enumerateWordpressFern.DetectionSourceCssReference},
			})
		}
	}

	return plugins
}

// containsString checks if a string is present in a slice of strings
func containsString(slice []string, str string) bool {
	for _, item := range slice {
		if item == str {
			return true
		}
	}
	return false
}
