package utils

import (
	// Standard
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
