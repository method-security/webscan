package configs

import (
	_ "embed"
	"fmt"
	"io/fs"
	"strings"

	"github.com/Method-Security/webscan/internal/compressedfs"
)

//go:generate sh -c "cd .. && go run scripts/build-embedded-assets.go"
//go:embed embedded/configs.tar.gz
var configArchive []byte

var configFS fs.FS = compressedfs.NewLazyTarGzip(configArchive)

// ReadFile reads a file from the embedded config filesystem.
// The path should be relative to the configs/ directory.
func ReadFile(path string) ([]byte, error) {
	return fs.ReadFile(configFS, path)
}

// ReadLines reads a text file from the embedded config filesystem and returns its lines.
func ReadLines(path string) ([]string, error) {
	data, err := fs.ReadFile(configFS, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded config %s: %w", path, err)
	}
	content := strings.TrimRight(string(data), "\r\n")
	if content == "" {
		return []string{}, nil
	}
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, "\r")
	}
	return lines, nil
}
