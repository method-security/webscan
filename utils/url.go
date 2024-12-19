package utils

import (
	"fmt"
	"net/url"
	"strings"
)

// SplitTarget splits a target URL into its base URL and path components.
func SplitTarget(target string) (string, string, error) {
	parsedURL, err := url.Parse(target)
	if err != nil {
		return "", "", fmt.Errorf("error parsing URL: %w", err)
	}

	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	baseURL = strings.TrimRight(baseURL, "/")

	path := strings.TrimRight(parsedURL.Path, "/")

	return baseURL, path, nil
}
