package utils

import (
	// Standard
	"net/url"
	"path"
	"strings"
)

// IsStaticAsset returns true if the URL is a static asset, false otherwise
func IsStaticAsset(url string) bool {
	staticExts := []string{
		".7z", ".avif", ".bmp", ".cjs", ".css", ".csv",
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

// IsTrailingSlashRedirect checks if the redirect is just adding a trailing slash
func IsTrailingSlashRedirect(from, to string) bool {
	fromURL, err := url.Parse(from)
	if err != nil {
		return false
	}
	toURL, err := url.Parse(to)
	if err != nil {
		return false
	}
	// Must be same scheme and host
	if fromURL.Scheme != toURL.Scheme || fromURL.Host != toURL.Host {
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
