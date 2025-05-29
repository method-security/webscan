package nuclei

import (
	// Standard library imports
	"context"       // For context-aware operations and cancellation
	"embed"         // For embedding static files into the binary
	"fmt"           // For formatted string operations and error creation
	"io/fs"         // For filesystem interface abstractions
	"path/filepath" // For cross-platform file path manipulation
	"strings"       // For string manipulation operations
	"time"          // For time-related operations

	// Generated code imports - auto-generated API types
	pentestgeneralfern "github.com/Method-Security/webscan/generated/go/pentest/general"
	// External library imports
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log" // Structured logging
)

// All is the pentest templates
//
//go:embed pentest
var All embed.FS

// resourceTypeToFileMap maps the application resource type to the file name of the template.
var resourceTypeToFileMap = map[pentestgeneralfern.ApplicationResourceType]string{
	pentestgeneralfern.ApplicationResourceTypeContentManagementSystem: "cms",
	pentestgeneralfern.ApplicationResourceTypeWebServer:               "webserver",
}

// getFullTemplatePaths walks "pentest/<kind>/<subs…>" and returns each matching fs.FS or an error.
func getFullTemplatePaths(kind string, subs []string) ([]fs.FS, error) {
	var out []fs.FS
	for _, sub := range subs {
		path := filepath.Join("pentest", kind, sub)
		subFS, err := fs.Sub(All, path)
		if err != nil {
			return nil, fmt.Errorf("no templates under %q: %w", path, err)
		}
		out = append(out, subFS)
	}
	return out, nil
}

// GetScanFileSystem returns filesystem views for scan templates based on the provided configuration.
func GetScanFileSystem(ctx context.Context, config pentestgeneralfern.ScanConfig) ([]fs.FS, error) {
	log := svc1log.FromContext(ctx)

	// If specific template paths are provided, use only those
	if len(config.TemplatePaths) > 0 {
		log.Info("Using specific template paths", svc1log.SafeParam("templatePaths", config.TemplatePaths))

		// Group template files by their directory to create minimal filesystems
		dirToFiles := make(map[string][]string)

		for _, templatePath := range config.TemplatePaths {
			// Clean the template path - remove utils/nuclei/templates/ prefix if present
			cleanPath := templatePath
			if strings.HasPrefix(cleanPath, "utils/nuclei/templates/") {
				cleanPath = strings.TrimPrefix(cleanPath, "utils/nuclei/templates/")
			}
			// Also handle if it starts with just pentest/
			if !strings.HasPrefix(cleanPath, "pentest/") {
				cleanPath = filepath.Join("pentest", cleanPath)
			}

			// Get the directory and filename
			templateDir := filepath.Dir(cleanPath)
			templateFile := filepath.Base(cleanPath)

			// Verify the template file exists
			if _, err := fs.Stat(All, cleanPath); err != nil {
				log.Warn("Template file not found, skipping", svc1log.SafeParam("templatePath", templatePath), svc1log.SafeParam("cleanPath", cleanPath), svc1log.SafeParam("error", err.Error()))
				continue
			}

			dirToFiles[templateDir] = append(dirToFiles[templateDir], templateFile)
		}

		if len(dirToFiles) == 0 {
			return nil, fmt.Errorf("no valid template paths found")
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

	// Build the hierarchical path: scan/<category>/<resource>/<module>
	var pathParts []string

	// Category is required
	if config.Category != nil {
		category := strings.ToLower(string(*config.Category))
		pathParts = append(pathParts, category)
	}

	// Add resource type if specified
	if config.ApplicationResourceType != nil {
		resourceType := resourceTypeToFileMap[*config.ApplicationResourceType]
		pathParts = append(pathParts, resourceType)
		log.Info("Adding resource type", svc1log.SafeParam("resourceType", resourceType))
	}

	// Add module if specified (this becomes the lowest layer)
	if config.Module != nil {
		module := *config.Module
		pathParts = append(pathParts, module)
		log.Info("Adding module", svc1log.SafeParam("module", module))
	}

	// Build the final path
	finalPath := strings.Join(pathParts, "/")
	log.Info("Building template path", svc1log.SafeParam("path", finalPath))

	// For any path, check if it contains subdirectories and collect all templates
	fullPath := filepath.Join("pentest", "scan", finalPath)
	entries, err := fs.ReadDir(All, fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %q: %w", fullPath, err)
	}

	// Check if directory contains subdirectories
	hasSubdirs := false
	for _, entry := range entries {
		if entry.IsDir() {
			hasSubdirs = true
			break
		}
	}

	if hasSubdirs {
		// Collect all subdirectories
		var subPaths []string
		for _, entry := range entries {
			if entry.IsDir() {
				subPaths = append(subPaths, filepath.Join(finalPath, entry.Name()))
			}
		}
		log.Info("Found subdirectories, collecting all", svc1log.SafeParam("subPaths", subPaths))
		return getFullTemplatePaths("scan", subPaths)
	}

	log.Info("Using final path for templates", svc1log.SafeParam("finalPath", finalPath))
	return getFullTemplatePaths("scan", []string{finalPath})
}

// GetDastFileSystem returns filesystem views for DAST templates organized by vulnerability categories.
func GetDastFileSystem(dastCategories []pentestgeneralfern.DastCategory) ([]fs.FS, error) {
	// Build the "dast/<vuln>" paths
	var subs []string
	for _, dastCategory := range dastCategories {
		subs = append(subs, strings.ToLower(string(dastCategory)))
	}

	return getFullTemplatePaths("dast", subs)
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
		file.Close()
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
