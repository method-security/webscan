package configs

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

//go:embed discover enumerate pentest
var configFS embed.FS

// ReadFile reads a file from the embedded config filesystem.
// The path should be relative to the configs/ directory.
func ReadFile(path string) ([]byte, error) {
	return configFS.ReadFile(path)
}

// ReadLines reads a text file from the embedded config filesystem and returns its lines.
func ReadLines(path string) ([]string, error) {
	data, err := configFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded config %s: %w", path, err)
	}
	content := strings.TrimRight(string(data), "\n")
	if content == "" {
		return []string{}, nil
	}
	return strings.Split(content, "\n"), nil
}

// ReadFileWithFallback tries to read from the filesystem first, then falls back to the embedded config.
// This supports user-provided custom paths (filesystem) while defaulting to embedded configs.
func ReadFileWithFallback(filesystemPath string, embeddedPath string) ([]byte, error) {
	data, err := os.ReadFile(filesystemPath)
	if err == nil {
		return data, nil
	}
	return ReadFile(embeddedPath)
}

// FS returns the embedded filesystem for direct access if needed.
func FS() fs.FS {
	return configFS
}
