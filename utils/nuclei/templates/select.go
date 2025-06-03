package nuclei

import (
	// Standard
	"context"
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// All is the pentest templates
//
//go:embed pentest
var All embed.FS

// GetTemplateFileSystem returns filesystem views for templates based on the provided template paths.
// templatePaths can contain either:
// - Complete paths to template files (e.g., "pentest/scan/cve/2024/CVE-2024-13624.yaml")
// - Folder paths (e.g., "pentest/scan/cve") - will collect all .yaml/.yml files recursively from that folder
func GetTemplateFileSystem(ctx context.Context, templatePaths []string) ([]fs.FS, error) {
	log := svc1log.FromContext(ctx)

	if len(templatePaths) == 0 {
		return nil, fmt.Errorf("no template paths provided")
	}

	log.Info("Using template paths", svc1log.SafeParam("templatePaths", templatePaths))

	// Collect all template files from the provided paths
	var allTemplateFiles []string

	for _, templatePath := range templatePaths {
		// Clean the template path - remove utils/nuclei/templates/ prefix if present
		cleanPath := templatePath
		cleanPath = strings.TrimPrefix(cleanPath, "utils/nuclei/templates/")
		// Also handle if it starts with just pentest/
		if !strings.HasPrefix(cleanPath, "pentest/") {
			cleanPath = filepath.Join("pentest", cleanPath)
		}

		// Check if this is a file or directory
		if isTemplateFile(cleanPath) {
			// It's a template file - verify it exists and add it
			if _, err := fs.Stat(All, cleanPath); err != nil {
				log.Warn("Template file not found, skipping", svc1log.SafeParam("templatePath", templatePath), svc1log.SafeParam("cleanPath", cleanPath), svc1log.SafeParam("error", err.Error()))
				continue
			}
			allTemplateFiles = append(allTemplateFiles, cleanPath)
		} else {
			// It's a directory - collect all template files recursively
			templates, err := collectTemplatesFromDirectory(cleanPath)
			if err != nil {
				log.Warn("Failed to collect templates from directory, skipping", svc1log.SafeParam("templatePath", templatePath), svc1log.SafeParam("cleanPath", cleanPath), svc1log.SafeParam("error", err.Error()))
				continue
			}
			allTemplateFiles = append(allTemplateFiles, templates...)
		}
	}

	if len(allTemplateFiles) == 0 {
		return nil, fmt.Errorf("no valid template files found")
	}

	log.Info("Found template files", svc1log.SafeParam("templateCount", len(allTemplateFiles)))

	// Group template files by their directory to create minimal filesystems
	dirToFiles := make(map[string][]string)

	for _, templateFile := range allTemplateFiles {
		templateDir := filepath.Dir(templateFile)
		templateName := filepath.Base(templateFile)
		dirToFiles[templateDir] = append(dirToFiles[templateDir], templateName)
	}

	var filesystems []fs.FS
	for templateDir, templateFiles := range dirToFiles {
		// Create a base filesystem for the directory
		baseFS, err := fs.Sub(All, templateDir)
		if err != nil {
			log.Warn("Template directory not found, skipping", svc1log.SafeParam("templateDir", templateDir), svc1log.SafeParam("error", err.Error()))
			continue
		}

		// Create a filtered filesystem that only exposes the specific template files
		filteredFS := &specificTemplateFS{
			baseFS:        baseFS,
			templateFiles: templateFiles,
		}

		filesystems = append(filesystems, filteredFS)
	}

	if len(filesystems) == 0 {
		return nil, fmt.Errorf("no valid template directories found")
	}

	return filesystems, nil
}

// isTemplateFile checks if the given path appears to be a template file based on extension
func isTemplateFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

// collectTemplatesFromDirectory recursively collects all .yaml and .yml files from the given directory
func collectTemplatesFromDirectory(dirPath string) ([]string, error) {
	var templates []string

	err := fs.WalkDir(All, dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Check if this is a template file
		if isTemplateFile(path) {
			templates = append(templates, path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", dirPath, err)
	}

	return templates, nil
}

// specificTemplateFS wraps the base filesystem and only exposes specific template files
type specificTemplateFS struct {
	baseFS        fs.FS
	templateFiles []string
}

// Open implements fs.FS interface for the specific template filesystem.
func (s *specificTemplateFS) Open(name string) (fs.File, error) {
	if name == "." {
		return &specificTemplateDir{fs: s}, nil
	}

	// Check if this file is one of the requested templates
	for _, templateFile := range s.templateFiles {
		if name == templateFile {
			return s.baseFS.Open(name)
		}
	}

	return nil, fs.ErrNotExist
}

// specificTemplateDir implements fs.ReadDirFile for directory listing
type specificTemplateDir struct {
	fs *specificTemplateFS
}

func (s *specificTemplateDir) Stat() (fs.FileInfo, error) {
	return &dirInfo{name: "."}, nil
}

func (s *specificTemplateDir) Read([]byte) (int, error) {
	return 0, fmt.Errorf("cannot read directory")
}

func (s *specificTemplateDir) Close() error {
	return nil
}

// ReadDir returns only the specific template files.
func (s *specificTemplateDir) ReadDir(n int) ([]fs.DirEntry, error) {
	var filteredEntries []fs.DirEntry

	for _, templateFile := range s.fs.templateFiles {
		// Try to get the file info
		file, err := s.fs.baseFS.Open(templateFile)
		if err != nil {
			continue
		}

		if stat, err := file.Stat(); err == nil {
			filteredEntries = append(filteredEntries, &fileDirEntry{
				name:    templateFile,
				size:    stat.Size(),
				mode:    stat.Mode(),
				modTime: stat.ModTime(),
			})
		}
		err = file.Close()
		if err != nil {
			continue
		}
	}

	if n <= 0 {
		return filteredEntries, nil
	}

	if n > len(filteredEntries) {
		n = len(filteredEntries)
	}

	return filteredEntries[:n], nil
}

// fileDirEntry implements fs.DirEntry for files
type fileDirEntry struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
}

func (f *fileDirEntry) Name() string               { return f.name }
func (f *fileDirEntry) IsDir() bool                { return false }
func (f *fileDirEntry) Type() fs.FileMode          { return f.mode.Type() }
func (f *fileDirEntry) Info() (fs.FileInfo, error) { return &fileInfo{f}, nil }

// fileInfo implements fs.FileInfo for files
type fileInfo struct {
	entry *fileDirEntry
}

func (f *fileInfo) Name() string       { return f.entry.name }
func (f *fileInfo) Size() int64        { return f.entry.size }
func (f *fileInfo) Mode() fs.FileMode  { return f.entry.mode }
func (f *fileInfo) ModTime() time.Time { return f.entry.modTime }
func (f *fileInfo) IsDir() bool        { return false }
func (f *fileInfo) Sys() interface{}   { return nil }

// dirInfo implements fs.FileInfo for directories
type dirInfo struct {
	name string
}

func (d *dirInfo) Name() string       { return d.name }
func (d *dirInfo) Size() int64        { return 0 }
func (d *dirInfo) Mode() fs.FileMode  { return fs.ModeDir | 0755 }
func (d *dirInfo) ModTime() time.Time { return time.Time{} }
func (d *dirInfo) IsDir() bool        { return true }
func (d *dirInfo) Sys() interface{}   { return nil }
