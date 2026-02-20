package docker

import (
	// Standard
	"context"
	"encoding/json"
	"fmt"
	"strings"

	// Generated
	common "github.com/Method-Security/webscan/generated/go/common"
	enumeratedockerfern "github.com/Method-Security/webscan/generated/go/enumerate/containerregistry"

	// Utils
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
	standard "github.com/Method-Security/webscan/utils/request/standard"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func createSendHTTPRequestConfig(baseURL, path string, queryParams map[string]string, verifyTLS bool, timeout int, acceptHeaders []string) common.SendHttpRequestConfig {
	// Base Headers
	headers := map[string][]string{
		"Accept": {"application/json"},
	}
	if len(acceptHeaders) > 0 {
		headers["Accept"] = acceptHeaders
	}

	// Create Request
	request := common.HttpRequest{
		BaseUrl: baseURL,
		Path:    path,
		Method:  common.HttpMethodGet,
		Params: &common.HttpRequestParams{
			Query:   queryParams,
			Headers: headers,
		},
	}
	return common.SendHttpRequestConfig{
		Request:            &request,
		MaxRedirects:       0,
		VerifyTls:          verifyTLS,
		Timeout:            timeout,
		RequestMethod:      common.RequestMethodStandard,
		HeadlessConfig:     nil,
		BrowserbaseConfig:  nil,
		BrowserbaseSecrets: nil,
	}
}

// enumerateRepositories gets the list of repositories from the registry
func enumerateRepositories(ctx context.Context, targetURL string, verifyTLS bool, timeout int) ([]string, []*common.HttpRequestResponse, error) {
	log := svc1log.FromContext(ctx)
	var requests []*common.HttpRequestResponse

	catalogURL := strings.TrimSuffix(targetURL, "/") + "/v2/_catalog"

	baseURL, path, queryParams, err := requesthelpers.SplitTargetURL(catalogURL)
	if err != nil {
		log.Error("Failed to parse catalog URL", svc1log.SafeParam("error", err.Error()))
		return nil, requests, err
	}

	requestConfig := createSendHTTPRequestConfig(baseURL, path, queryParams, verifyTLS, timeout, nil)

	httpReqResp, err := standard.SendStandardRequest(ctx, requestConfig)
	if err != nil {
		log.Error("Failed to send request", svc1log.SafeParam("error", err.Error()))
		return nil, requests, err
	}
	requests = append(requests, &httpReqResp)

	if httpReqResp.Response == nil || httpReqResp.Response.StatusCode == nil || *httpReqResp.Response.StatusCode != 200 {
		log.Warn("Catalog endpoint returned non-200 status")
		return nil, requests, nil
	}

	var allRepositories []string
	if httpReqResp.Response.ResponseBody != nil {
		bodyStr := requesthelpers.GetResponseBodyStringFromBodyStruct(httpReqResp.Response.ResponseBody)
		if bodyStr != nil {
			var catalogResp enumeratedockerfern.DockerCatalogResponse
			if err := json.Unmarshal([]byte(*bodyStr), &catalogResp); err != nil {
				log.Error("Failed to decode catalog response", svc1log.SafeParam("error", err.Error()))
				return nil, requests, err
			}
			allRepositories = catalogResp.Repositories
			log.Info("Found repositories", svc1log.SafeParam("count", len(allRepositories)))
		}
	}

	return allRepositories, requests, nil
}

// getImageTags retrieves tags for a specific image repository
func getImageTags(ctx context.Context, targetURL, repository string, verifyTLS bool, timeout int) ([]string, []*common.HttpRequestResponse, error) {
	log := svc1log.FromContext(ctx)
	var requests []*common.HttpRequestResponse

	tagsURL := strings.TrimSuffix(targetURL, "/") + "/v2/" + repository + "/tags/list"

	baseURL, path, queryParams, err := requesthelpers.SplitTargetURL(tagsURL)
	if err != nil {
		log.Error("Failed to parse tags URL", svc1log.SafeParam("error", err.Error()))
		return nil, requests, err
	}

	requestConfig := createSendHTTPRequestConfig(baseURL, path, queryParams, verifyTLS, timeout, nil)

	httpReqResp, err := standard.SendStandardRequest(ctx, requestConfig)
	if err != nil {
		log.Error("Failed to send request", svc1log.SafeParam("error", err.Error()))
		return nil, requests, err
	}
	requests = append(requests, &httpReqResp)

	if httpReqResp.Response == nil || httpReqResp.Response.StatusCode == nil || *httpReqResp.Response.StatusCode != 200 {
		log.Warn("Tags endpoint returned non-200 status", svc1log.SafeParam("repository", repository))
		return []string{}, requests, nil
	}

	var tags []string
	if httpReqResp.Response.ResponseBody != nil {
		bodyStr := requesthelpers.GetResponseBodyStringFromBodyStruct(httpReqResp.Response.ResponseBody)
		if bodyStr != nil {
			var tagsResp enumeratedockerfern.DockerTagsResponse
			if err := json.Unmarshal([]byte(*bodyStr), &tagsResp); err != nil {
				log.Error("Failed to decode tags response", svc1log.SafeParam("error", err.Error()), svc1log.SafeParam("repository", repository))
				return []string{}, requests, nil
			}
			tags = tagsResp.Tags
		}
	}

	return tags, requests, nil
}

// getImageManifest retrieves the manifest for a specific image:tag and returns the digest, manifest content, size, and requests.
func getImageManifest(ctx context.Context, targetURL, repository, tag string, verifyTLS bool, timeout int) (string, string, *int, []*common.HttpRequestResponse, error) {
	log := svc1log.FromContext(ctx)
	var requests []*common.HttpRequestResponse

	manifestURL := strings.TrimSuffix(targetURL, "/") + "/v2/" + repository + "/manifests/" + tag

	baseURL, path, queryParams, err := requesthelpers.SplitTargetURL(manifestURL)
	if err != nil {
		log.Error("Failed to parse manifest URL", svc1log.SafeParam("error", err.Error()))
		return "", "", nil, requests, err
	}

	acceptHeaders := []string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.oci.image.index.v1+json",
	}
	requestConfig := createSendHTTPRequestConfig(baseURL, path, queryParams, verifyTLS, timeout, acceptHeaders)

	httpReqResp, err := standard.SendStandardRequest(ctx, requestConfig)
	if err != nil {
		log.Error("Failed to send request", svc1log.SafeParam("error", err.Error()))
		return "", "", nil, requests, err
	}
	requests = append(requests, &httpReqResp)

	if httpReqResp.Response == nil || httpReqResp.Response.StatusCode == nil || *httpReqResp.Response.StatusCode != 200 {
		log.Warn("Manifest endpoint returned non-200 status", svc1log.SafeParam("repository", repository), svc1log.SafeParam("tag", tag))
		return "", "", nil, requests, nil
	}

	var digest string
	if httpReqResp.Response.ResponseHeaders != nil {
		if digestValues, ok := httpReqResp.Response.ResponseHeaders["Docker-Content-Digest"]; ok && len(digestValues) > 0 {
			digest = digestValues[0]
		}
	}

	var manifestContent string
	var totalSize *int
	if httpReqResp.Response.ResponseBody != nil {
		bodyStr := requesthelpers.GetResponseBodyStringFromBodyStruct(httpReqResp.Response.ResponseBody)
		if bodyStr != nil {
			manifestContent = *bodyStr

			var manifest enumeratedockerfern.DockerManifestV2
			if err := json.Unmarshal([]byte(manifestContent), &manifest); err == nil {
				hasSize := false
				size := 0
				if manifest.Config != nil && manifest.Config.Size != nil {
					size += *manifest.Config.Size
					hasSize = true
				}
				for _, layer := range manifest.Layers {
					if layer != nil && layer.Size != nil {
						size += *layer.Size
						hasSize = true
					}
				}
				if hasSize {
					totalSize = &size
				}
			}
		}
	}

	return digest, manifestContent, totalSize, requests, nil
}

// enumerateTarget performs enumeration against a single registry target and returns a per-target result.
// Step 1: Hit /v2/_catalog to list all repositories. Returns success=false if inaccessible.
// Step 2: For each repository, hit /v2/{repo}/tags/list to retrieve available tags.
// Step 3: For each tag, hit /v2/{repo}/manifests/{tag} to fetch the manifest and digest.
// Step 4: Group images by digest so tags pointing to the same image are consolidated.
func enumerateTarget(ctx context.Context, targetURL string, verifyTLS bool, timeout int) (*enumeratedockerfern.EnumerateDockerResult, []string) {
	log := svc1log.FromContext(ctx)
	var allRequests []*common.HttpRequestResponse
	var errors []string

	// Step 1: Hit /v2/_catalog to list all repositories
	repositories, repoRequests, err := enumerateRepositories(ctx, targetURL, verifyTLS, timeout)
	allRequests = append(allRequests, repoRequests...)
	if err != nil {
		errors = append(errors, fmt.Sprintf("Failed to enumerate repositories: %v", err))
		successVal := false
		return &enumeratedockerfern.EnumerateDockerResult{
			Target:   targetURL,
			Requests: allRequests,
			Success:  &successVal,
		}, errors
	}

	if repositories == nil {
		log.Info("Registry did not return repositories (possibly requires authentication)")
		successVal := false
		return &enumeratedockerfern.EnumerateDockerResult{
			Target:   targetURL,
			Requests: allRequests,
			Success:  &successVal,
		}, errors
	}

	if len(repositories) == 0 {
		log.Info("No repositories found in registry")
		successVal := true
		return &enumeratedockerfern.EnumerateDockerResult{
			Target:   targetURL,
			Requests: allRequests,
			Success:  &successVal,
		}, errors
	}

	var containerRepos []*enumeratedockerfern.ContainerRepository

	for _, repoName := range repositories {
		log.Info("Processing repository", svc1log.SafeParam("repository", repoName))

		// Step 2: For each repository, retrieve available tags
		tags, tagRequests, err := getImageTags(ctx, targetURL, repoName, verifyTLS, timeout)
		allRequests = append(allRequests, tagRequests...)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to get tags for repository %s: %v", repoName, err))
			continue
		}

		if len(tags) == 0 {
			log.Warn("No tags found for repository", svc1log.SafeParam("repository", repoName))
			containerRepos = append(containerRepos, &enumeratedockerfern.ContainerRepository{
				Name:   repoName,
				Images: []*enumeratedockerfern.ContainerImage{},
			})
			continue
		}

		imageMap := make(map[string]*enumeratedockerfern.ContainerImage)

		// Step 3: For each tag, fetch the manifest and digest
		for _, tag := range tags {
			digest, manifestContent, size, manifestRequests, err := getImageManifest(ctx, targetURL, repoName, tag, verifyTLS, timeout)
			allRequests = append(allRequests, manifestRequests...)
			if err != nil {
				errors = append(errors, fmt.Sprintf("Failed to get manifest for %s:%s: %v", repoName, tag, err))
				continue
			}

			if digest == "" {
				digest = repoName + ":" + tag
			}

			// Compact the manifest into a single-line JSON string
			var manifestStr *string
			if manifestContent != "" {
				var raw json.RawMessage
				if err := json.Unmarshal([]byte(manifestContent), &raw); err == nil {
					compacted, err := json.Marshal(raw)
					if err == nil {
						s := string(compacted)
						manifestStr = &s
					}
				}
			}

			// Step 4: Group images by digest so tags pointing to the same image are consolidated
			if existing, ok := imageMap[digest]; ok {
				existing.Tags = append(existing.Tags, tag)
			} else {
				imageMap[digest] = &enumeratedockerfern.ContainerImage{
					Digest:   digest,
					Tags:     []string{tag},
					Size:     size,
					Manifest: manifestStr,
				}
			}
		}

		images := make([]*enumeratedockerfern.ContainerImage, 0, len(imageMap))
		for _, image := range imageMap {
			images = append(images, image)
		}

		containerRepos = append(containerRepos, &enumeratedockerfern.ContainerRepository{
			Name:   repoName,
			Images: images,
		})

		log.Info("Processed repository", svc1log.SafeParam("repository", repoName), svc1log.SafeParam("imageCount", len(images)), svc1log.SafeParam("totalTags", len(tags)))
	}

	successVal := true
	return &enumeratedockerfern.EnumerateDockerResult{
		Target:       targetURL,
		Requests:     allRequests,
		Repositories: containerRepos,
		Success:      &successVal,
	}, errors
}

// PerformAppEnumerateContainerRegistryDocker performs comprehensive enumeration of Docker container registries.
func PerformAppEnumerateContainerRegistryDocker(ctx context.Context, config *enumeratedockerfern.EnumerateDockerConfig) *enumeratedockerfern.EnumerateDockerReport {
	// Initialize logger
	log := svc1log.FromContext(ctx)
	log.Info("Starting Docker registry enumeration", svc1log.SafeParam("targets", config.Targets), svc1log.SafeParam("timeout", config.Timeout))

	// Initialize report
	report := &enumeratedockerfern.EnumerateDockerReport{Config: config, Result: &enumeratedockerfern.EnumerateDockerResults{}}
	targets := []*enumeratedockerfern.EnumerateDockerResult{}
	errors := []string{}

	for _, targetURL := range config.Targets {
		result, errs := enumerateTarget(ctx, targetURL, config.VerifyTls, config.Timeout)
		if result != nil {
			targets = append(targets, result)
		}
		errors = append(errors, errs...)
	}

	// Populate report
	report.Result.Targets = targets
	report.Errors = errors

	log.Info("Docker registry enumeration completed", svc1log.SafeParam("targetCount", len(targets)), svc1log.SafeParam("errorCount", len(errors)))

	return report
}
