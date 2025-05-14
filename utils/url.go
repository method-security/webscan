package utils

import (
	"fmt"
	"net/url"
	"strings"
)

// SplitTarget splits a target URL and standardizes it into its base URL and path components.
func SplitTarget(target string) (string, string, error) {
	parsedURL, err := url.Parse(target)
	if err != nil {
		return "", "", fmt.Errorf("error parsing URL: %w", err)
	}

	// Standardize the base URL (ie. http://example.com/ -> http://example.com)
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	baseURL = strings.TrimRight(baseURL, "/")

	// Standardize the path
	// If the path is empty, set it to "", else trim the trailing slash (ie. "/foo/" -> "/foo")
	path := strings.TrimRight(parsedURL.Path, "/")

	return baseURL, path, nil
}
