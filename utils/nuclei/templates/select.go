package nuclei

import (
	// Standard library imports
	"context"       // For context-aware operations and cancellation
	"embed"         // For embedding static files into the binary
	"fmt"           // For formatted string operations and error creation
	"io/fs"         // For filesystem interface abstractions
	"path/filepath" // For cross-platform file path manipulation
	"strings"       // For string manipulation operations
	"time"

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

// getFilteredTemplatePaths filters within a hierarchical path for specific template IDs.
func getFilteredTemplatePaths(kind, path string, templateIds []string) ([]fs.FS, error) {
	// First get the full filesystem for the hierarchical path
	fullPath := filepath.Join("pentest", kind, path)
	baseFS, err := fs.Sub(All, fullPath)
	if err != nil {
		return nil, fmt.Errorf("no templates under %q: %w", fullPath, err)
	}

	// Create a filtered filesystem that only contains the requested template files
	filteredFS := &filteredFS{
		baseFS:      baseFS,
		templateIds: templateIds,
	}

	return []fs.FS{filteredFS}, nil
}

// filteredFS wraps a base filesystem and only exposes specific template files
type filteredFS struct {
	baseFS      fs.FS
	templateIds []string
}

// Open implements fs.FS interface for the filtered filesystem.
func (f *filteredFS) Open(name string) (fs.File, error) {
	if name == "." {
		return &filteredDir{fs: f}, nil
	}

	// Check if this file is one of the requested templates
	baseName := strings.TrimSuffix(name, filepath.Ext(name))
	for _, templateId := range f.templateIds {
		if baseName == templateId {
			return f.baseFS.Open(name)
		}
	}

	return nil, fs.ErrNotExist
}

// filteredDir implements fs.ReadDirFile for directory listing
type filteredDir struct {
	fs *filteredFS
}

func (f *filteredDir) Stat() (fs.FileInfo, error) {
	return &dirInfo{name: "."}, nil
}

func (f *filteredDir) Read([]byte) (int, error) {
	return 0, fmt.Errorf("cannot read directory")
}

func (f *filteredDir) Close() error {
	return nil
}

// ReadDir returns only the template files that match the configured template IDs.
func (f *filteredDir) ReadDir(n int) ([]fs.DirEntry, error) {
	// Read all entries from the base filesystem
	baseDir, err := f.fs.baseFS.Open(".")
	if err != nil {
		return nil, err
	}
	defer baseDir.Close()

	readDirFile, ok := baseDir.(fs.ReadDirFile)
	if !ok {
		return nil, fmt.Errorf("base filesystem does not support ReadDir")
	}

	allEntries, err := readDirFile.ReadDir(-1)
	if err != nil {
		return nil, err
	}

	// Filter entries to only include requested template files
	var filteredEntries []fs.DirEntry
	for _, entry := range allEntries {
		if entry.IsDir() {
			continue
		}

		baseName := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		for _, templateId := range f.fs.templateIds {
			if baseName == templateId {
				filteredEntries = append(filteredEntries, entry)
				break
			}
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

// GetScanFileSystem returns filesystem views for scan templates based on the provided configuration.
// It builds a hierarchical path from category/resource/module and supports filtering by specific template IDs.
func GetScanFileSystem(ctx context.Context, config pentestgeneralfern.ScanConfig) ([]fs.FS, error) {
	log := svc1log.FromContext(ctx)

	// Build the hierarchical path: scan/<category>/<resource>/<module>
	var pathParts []string

	// Category is required
	category := strings.ToLower(string(config.Category))
	pathParts = append(pathParts, category)

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

	// If specific template IDs are provided, filter within the hierarchical path
	if len(config.TemplateIds) > 0 {
		log.Info("Filtering for specific template IDs", svc1log.SafeParam("templateIds", config.TemplateIds), svc1log.SafeParam("path", finalPath))
		return getFilteredTemplatePaths("scan", finalPath, config.TemplateIds)
	}

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
