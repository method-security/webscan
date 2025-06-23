package utils

import (
	"bufio"
	"os"
	"path/filepath"
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
		err = file.Close()
		if err != nil {
			return nil, err
		}
		entries = append(entries, lines...)
	}
	return entries, nil
}

func GetEnumerateWordpressPluginWordlistPath(pluginFileSize string) string {
	wordlistPaths := map[string]string{
		"SMALL": "/opt/method/webscan/var/conf/enumerate/cms/wordpress/plugins_small.txt",
		"LARGE": "/opt/method/webscan/var/conf/enumerate/cms/wordpress/plugins_large.txt",
	}
	return wordlistPaths[pluginFileSize]
}
