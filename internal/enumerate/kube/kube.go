package kube

import (
	// Standard
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"time"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	enumeratekubefern "github.com/Method-Security/webscan/generated/go/enumerate/kube"

	// Utils
	utils "github.com/Method-Security/webscan/utils"
	request "github.com/Method-Security/webscan/utils/request"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

// kubePathSpec associates a Kubernetes API path with its security sensitivity classification.
type kubePathSpec struct {
	path        string
	sensitivity enumeratekubefern.KubeEndpointSensitivity
}

// commonKubepaths lists the Kubernetes API paths to probe along with their sensitivity.
// STANDARD paths are routine discovery/health endpoints; SENSITIVE paths indicate
// a misconfiguration when reachable anonymously.
var commonKubepaths = []kubePathSpec{
	// STANDARD: discovery / health
	{"/", enumeratekubefern.KubeEndpointSensitivityStandard},
	{"/api", enumeratekubefern.KubeEndpointSensitivityStandard},
	{"/api/v1", enumeratekubefern.KubeEndpointSensitivityStandard},
	{"/apis", enumeratekubefern.KubeEndpointSensitivityStandard},
	{"/version", enumeratekubefern.KubeEndpointSensitivityStandard},
	{"/healthz", enumeratekubefern.KubeEndpointSensitivityStandard},
	{"/livez", enumeratekubefern.KubeEndpointSensitivityStandard},
	{"/readyz", enumeratekubefern.KubeEndpointSensitivityStandard},
	{"/openapi/v2", enumeratekubefern.KubeEndpointSensitivityStandard},
	// SENSITIVE: anonymous access to these endpoints indicates a misconfiguration
	{"/metrics", enumeratekubefern.KubeEndpointSensitivitySensitive},
	{"/api/v1/nodes", enumeratekubefern.KubeEndpointSensitivitySensitive},
	{"/api/v1/pods", enumeratekubefern.KubeEndpointSensitivitySensitive},
	{"/api/v1/services", enumeratekubefern.KubeEndpointSensitivitySensitive},
	{"/api/v1/namespaces", enumeratekubefern.KubeEndpointSensitivitySensitive},
	{"/api/v1/secrets", enumeratekubefern.KubeEndpointSensitivitySensitive},
	{"/api/v1/configmaps", enumeratekubefern.KubeEndpointSensitivitySensitive},
	{"/apis/apps/v1/deployments", enumeratekubefern.KubeEndpointSensitivitySensitive},
	{"/apis/networking.k8s.io/v1/ingresses", enumeratekubefern.KubeEndpointSensitivitySensitive},
	{"/api/v1/persistentvolumes", enumeratekubefern.KubeEndpointSensitivitySensitive},
}

// kubeVersionPayload is used to parse the /version endpoint JSON response body.
type kubeVersionPayload struct {
	GitVersion string `json:"gitVersion"`
	Platform   string `json:"platform"`
}

func createSendHTTPRequestConfig(baseURL, path string, verifyTLS bool, timeout int, userAgent common.UserAgentPreset) common.SendHttpRequestConfig {
	req := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params:  &common.HttpRequestParams{},
	}
	return common.SendHttpRequestConfig{
		Request:            &req,
		MaxRedirects:       0,
		VerifyTls:          verifyTLS,
		Timeout:            timeout,
		UserAgent:          userAgent,
		RequestMethod:      common.RequestMethodStandard,
		HeadlessConfig:     nil,
		BrowserbaseConfig:  nil,
		BrowserbaseSecrets: nil,
	}
}

// extractVersionInfo attempts to parse the /version endpoint response body and return
// a KubeVersionInfo. Returns nil on any parse failure — parse failures are expected on
// non-Kubernetes targets and are NOT propagated to report.Errors.
func extractVersionInfo(results []*enumeratekubefern.KubeEndpointResult) *enumeratekubefern.KubeVersionInfo {
	for _, r := range results {
		if r == nil || r.Request == nil || r.Request.Response == nil {
			continue
		}
		if r.Request.Request.Path == "" {
			continue
		}
		// Match only the /version path
		pathSuffix := "/version"
		path := r.Request.Request.Path
		if len(path) < len(pathSuffix) || path[len(path)-len(pathSuffix):] != pathSuffix {
			continue
		}
		statusCode := r.Request.Response.StatusCode
		if statusCode == nil || *statusCode != 200 {
			continue
		}
		if r.Request.Response.ResponseBody == nil {
			continue
		}
		body := r.Request.Response.ResponseBody
		// Extract the JSON string from the Body union (text or json kind)
		var rawJSON string
		switch body.GetKind() {
		case "text":
			if body.Text != nil {
				rawJSON = body.Text.Value
			}
		case "json":
			if body.Json != nil {
				rawJSON = body.Json.Data
			}
		default:
			continue
		}
		if rawJSON == "" {
			continue
		}
		var payload kubeVersionPayload
		if err := json.Unmarshal([]byte(rawJSON), &payload); err != nil {
			return nil
		}
		info := &enumeratekubefern.KubeVersionInfo{}
		if payload.GitVersion != "" {
			info.GitVersion = &payload.GitVersion
		}
		if payload.Platform != "" {
			info.Platform = &payload.Platform
		}
		return info
	}
	return nil
}

// PerformAppEnumerateKube performs enumeration of common Kubernetes endpoints and returns an EnumerateKubeReport.
//
// Concurrency model:
//   - Stealth mode (config.Sleep > 0): probes are sent sequentially with sleep/jitter between
//     requests, preserving the operator-requested delay contract. Errors are collected and
//     scanning continues (collect-and-continue) so partial results are always returned.
//   - Fast mode (config.Sleep == 0): all probes are fanned out concurrently using one goroutine
//     per path (19 paths — small N, bounded in practice). Results are written into a fixed-size
//     slice indexed by path order so the final list is deterministic. A per-request error does
//     NOT abort the whole scan; it is appended to report.Errors and that slot is left nil.
func PerformAppEnumerateKube(ctx context.Context, config *enumeratekubefern.EnumerateKubeConfig) *enumeratekubefern.EnumerateKubeReport {
	// Initialize report
	report := &enumeratekubefern.EnumerateKubeReport{Config: config, Result: &enumeratekubefern.EnumerateKubeResult{}}
	var errors []string

	// Split target URL into base URL and path
	baseURL, parsedTargetPath, _, err := requesthelpers.SplitTargetURL(config.Target)
	if err != nil {
		errors = append(errors, err.Error())
		report.Errors = errors
		return report
	}

	// Pre-allocate a result slot for each path so we can write concurrently by index.
	results := make([]*enumeratekubefern.KubeEndpointResult, len(commonKubepaths))

	if config.Sleep > 0 {
		// Stealth mode: sequential with sleep/jitter between requests.
		// Collect-and-continue: a per-request error is logged but does not abort the scan.
		for i, spec := range commonKubepaths {
			// Check context cancellation before each request.
			select {
			case <-ctx.Done():
				report.Result.Target = config.Target
				report.Result.Requests = collectResults(results)
				report.Errors = errors
				return report
			default:
			}

			reqConfig := createSendHTTPRequestConfig(
				baseURL,
				fmt.Sprintf("%s%s", parsedTargetPath, spec.path),
				config.VerifyTls,
				config.Timeout,
				config.UserAgent,
			)
			resp, reqErr := request.SendRequest(ctx, reqConfig)
			if reqErr != nil {
				errors = append(errors, reqErr.Error())
			} else {
				results[i] = &enumeratekubefern.KubeEndpointResult{
					Request:     resp,
					Sensitivity: spec.sensitivity,
				}
			}

			// Apply stealth delay between requests (not after the last one).
			if i < len(commonKubepaths)-1 {
				delay := utils.CalculateDelayWithJitter(config.Sleep, config.Jitter)
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					report.Result.Target = config.Target
					report.Result.Requests = collectResults(results)
					report.Errors = errors
					return report
				}
			}
		}
	} else {
		// Fast mode: fan out all probes concurrently — one goroutine per path.
		// We use GOMAXPROCS as a soft guideline but do not throttle since N=19 is small.
		// Results are written into results[i] (one slot per path index) to preserve order.
		_ = runtime.GOMAXPROCS(0) // document intent; no semaphore needed at N=19

		var mu sync.Mutex
		var wg sync.WaitGroup

		for i, spec := range commonKubepaths {
			// Check context before launching goroutine.
			select {
			case <-ctx.Done():
				wg.Wait()
				report.Result.Target = config.Target
				report.Result.Requests = collectResults(results)
				report.Errors = errors
				return report
			default:
			}

			wg.Add(1)
			go func(idx int, ps kubePathSpec) {
				defer wg.Done()
				reqConfig := createSendHTTPRequestConfig(
					baseURL,
					fmt.Sprintf("%s%s", parsedTargetPath, ps.path),
					config.VerifyTls,
					config.Timeout,
					config.UserAgent,
				)
				resp, reqErr := request.SendRequest(ctx, reqConfig)
				if reqErr != nil {
					mu.Lock()
					errors = append(errors, reqErr.Error())
					mu.Unlock()
					return
				}
				results[idx] = &enumeratekubefern.KubeEndpointResult{
					Request:     resp,
					Sensitivity: ps.sensitivity,
				}
			}(i, spec)
		}
		wg.Wait()
	}

	// Collect non-nil results in path order.
	collectedResults := collectResults(results)

	// Extract version info from /version 200 response if available.
	// Parse failures are silently ignored (expected on non-Kubernetes targets).
	versionInfo := extractVersionInfo(collectedResults)

	// Populate and return report.
	report.Result.Target = config.Target
	report.Result.Requests = collectedResults
	report.Result.VersionInfo = versionInfo
	report.Errors = errors
	return report
}

// collectResults filters nil slots (failed requests) from a fixed-size results slice,
// preserving the original path ordering for all successful probes.
func collectResults(results []*enumeratekubefern.KubeEndpointResult) []*enumeratekubefern.KubeEndpointResult {
	out := make([]*enumeratekubefern.KubeEndpointResult, 0, len(results))
	for _, r := range results {
		if r != nil {
			out = append(out, r)
		}
	}
	return out
}
