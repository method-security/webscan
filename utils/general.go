package utils

import (
	"bufio"
	"errors"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// GetEntriesFromTXTFiles returns a list of entries from a list of text files
func GetEntriesFromTXTFiles(paths []string) ([]string, error) {
	entries := []string{}
	for _, path := range paths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		file, err := os.Open(absPath)
		if err != nil {
			return nil, err
		}
		var lines []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			_ = file.Close()
			return nil, err
		}
		err = file.Close()
		if err != nil {
			return nil, err
		}
		entries = append(entries, lines...)
	}
	return entries, nil
}

// ParseResponseCodes parses a comma-separated or range-based string of response codes
// (e.g., "200,301,404-410") and returns a map of valid codes.
func ParseResponseCodes(responseCodes string) (map[int]bool, error) {
	validCodes := make(map[int]bool)
	for _, part := range strings.Split(responseCodes, ",") {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			start, err1 := strconv.Atoi(rangeParts[0])
			end, err2 := strconv.Atoi(rangeParts[1])
			if err1 != nil || err2 != nil || start > end {
				return nil, errors.New("invalid response code range")
			}
			for i := start; i <= end; i++ {
				validCodes[i] = true
			}
		} else {
			code, err := strconv.Atoi(part)
			if err != nil {
				return nil, errors.New("invalid response code")
			}
			validCodes[code] = true
		}
	}
	return validCodes, nil
}

// IsStaticAsset returns true if the URL is a static asset, false otherwise
func IsStaticAsset(url string) bool {
	staticExts := []string{
		".7z", ".assetx", ".avif", ".bmp", ".cjs", ".css", ".csv",
		".doc", ".docx", ".eot", ".gif", ".gz", ".ico",
		".ini", ".jpg", ".jpeg", ".js", ".jsx", ".json",
		".less", ".m4a", ".m4v", ".map", ".markdown", ".md",
		".mjs", ".mp3", ".mp4", ".ogg", ".otf", ".pdf",
		".png", ".ppt", ".pptx", ".rar", ".sass", ".scss",
		".sfnt", ".svg", ".tar", ".toml", ".ts", ".tsx",
		".ttf", ".txt", ".webm", ".webp", ".woff", ".woff2",
		".xls", ".xlsx", ".xml", ".yaml", ".yml", ".zip",
	}

	if i := strings.IndexAny(url, "?#"); i != -1 {
		url = url[:i]
	}

	ext := strings.ToLower(path.Ext(url))
	for _, staticExt := range staticExts {
		if ext == staticExt {
			return true
		}
	}
	return false
}

// IsHostInScope reports whether targetURL is the same host as baseURL or a
// subdomain (child) of it. The comparison is case-insensitive and ignores the
// port. Scope is anchored on the FULL base host, so children are allowed while
// the apex domain and sibling subdomains are excluded. For a base of
// www.example.com this admits www.example.com and app.www.example.com, but not
// example.com (parent) or careers.example.com (sibling). IP addresses have no
// subdomain hierarchy, so they require an exact match. This is the shared
// scoping check used by the ignore-cross-domain flag across discovery commands.
func IsHostInScope(baseURL string, targetURL string) bool {
	base, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	target, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	baseHost := strings.ToLower(base.Hostname())
	targetHost := strings.ToLower(target.Hostname())
	if baseHost == "" || targetHost == "" {
		return false
	}

	// IP addresses have no subdomain hierarchy — require an exact match.
	if net.ParseIP(baseHost) != nil || net.ParseIP(targetHost) != nil {
		return baseHost == targetHost
	}

	return targetHost == baseHost || strings.HasSuffix(targetHost, "."+baseHost)
}

// IsTrailingSlashRedirect checks if the redirect is just adding a trailing slash.
// Default ports are normalized so https://host:443/path and https://host/path/
// are treated as the same origin.
func IsTrailingSlashRedirect(from, to string) bool {
	fromURL, err := url.Parse(from)
	if err != nil {
		return false
	}
	toURL, err := url.Parse(to)
	if err != nil {
		return false
	}
	// Must be same origin. url.Host cannot be compared directly because an
	// explicit default port is equivalent to an omitted port.
	if !sameURLOrigin(fromURL, toURL) {
		return false
	}

	// Check if query parameters are the same
	if fromURL.RawQuery != toURL.RawQuery {
		return false
	}

	// Check if fragment is the same
	if fromURL.Fragment != toURL.Fragment {
		return false
	}

	// Normalize paths for comparison
	fromPath := fromURL.Path
	toPath := toURL.Path

	// Remove trailing slash from both for comparison
	fromPathNormalized := strings.TrimSuffix(fromPath, "/")
	toPathNormalized := strings.TrimSuffix(toPath, "/")

	// They should be the same after normalization, and the redirect should be adding a slash
	return fromPathNormalized == toPathNormalized &&
		!strings.HasSuffix(fromPath, "/") &&
		strings.HasSuffix(toPath, "/")
}

func sameURLOrigin(left, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	if !strings.EqualFold(left.Scheme, right.Scheme) {
		return false
	}
	if !strings.EqualFold(left.Hostname(), right.Hostname()) {
		return false
	}
	return effectiveURLPort(left) == effectiveURLPort(right)
}

func effectiveURLPort(parsedURL *url.URL) string {
	if parsedURL == nil {
		return ""
	}
	if port := parsedURL.Port(); port != "" {
		return port
	}
	switch strings.ToLower(parsedURL.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}
