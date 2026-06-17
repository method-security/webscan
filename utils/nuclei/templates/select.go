package nuclei

import (
	// Standard
	"context"
	_ "embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Method-Security/webscan/internal/compressedfs"

	// External
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// All is the templates (pentest and discover)
//
//go:embed embedded/templates.tar.gz
var templateArchive []byte

var All fs.FS = compressedfs.NewLazyTarGzip(templateArchive)

// GetTemplateFileSystem returns filesystem views for templates based on the provided template paths.
// templatePaths can contain either:
// - Absolute paths or relative paths starting with ./ or ../ — read from disk
// - Embedded paths (e.g., "pentest/scan/cve/2024/CVE-2024-13624.yaml" or "pentest/scan/cve")
func GetTemplateFileSystem(ctx context.Context, templatePaths []string) ([]fs.FS, error) {
	log := svc1log.FromContext(ctx)

	if len(templatePaths) == 0 {
		return nil, fmt.Errorf("no template paths provided")
	}

	log.Info("Using template paths", svc1log.SafeParam("templatePaths", templatePaths))

	var filesystems []fs.FS
	var embeddedPaths []string

	for _, templatePath := range templatePaths {
		if isDiskPath(templatePath) {
			diskFS, err := getDiskFS(templatePath)
			if err != nil {
				log.Warn("Failed to open disk template path, skipping",
					svc1log.SafeParam("templatePath", templatePath),
					svc1log.SafeParam("error", err.Error()))
				continue
			}
			log.Info("Using disk template path", svc1log.SafeParam("templatePath", templatePath))
			filesystems = append(filesystems, diskFS)
		} else {
			embeddedPaths = append(embeddedPaths, templatePath)
		}
	}

	if len(embeddedPaths) > 0 {
		embeddedFSes, err := getEmbeddedFileSystems(ctx, embeddedPaths)
		if err != nil {
			if len(filesystems) == 0 {
				return nil, err
			}
			log.Warn("Some embedded template paths failed", svc1log.SafeParam("error", err.Error()))
		} else {
			filesystems = append(filesystems, embeddedFSes...)
		}
	}

	if len(filesystems) == 0 {
		return nil, fmt.Errorf("no valid template files found")
	}

	return filesystems, nil
}

// isDiskPath reports whether path should be read from the OS filesystem.
// Only absolute paths and explicitly relative paths (./  ../) qualify;
// bare relative paths always resolve against the embedded archive to avoid
// CWD shadowing of built-in template names like pentest/dast.
func isDiskPath(path string) bool {
	if filepath.IsAbs(path) {
		return true
	}
	return strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") ||
		strings.HasPrefix(path, ".\\") || strings.HasPrefix(path, "..\\")
}

// getDiskFS returns an fs.FS backed by the OS filesystem at path.
func getDiskFS(path string) (fs.FS, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve path %s: %w", path, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("path not found %s: %w", abs, err)
	}
	if info.IsDir() {
		count, err := countDiskTemplateFiles(abs)
		if err != nil {
			return nil, fmt.Errorf("failed to scan directory %s: %w", abs, err)
		}
		if count == 0 {
			return nil, fmt.Errorf("no .yaml/.yml files found in %s", abs)
		}
		return os.DirFS(abs), nil
	}
	return &singleFileFS{path: abs}, nil
}

// countDiskTemplateFiles counts .yaml/.yml files recursively under dir.
func countDiskTemplateFiles(dir string) (int, error) {
	count := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && isTemplateFile(path) {
			count++
		}
		return nil
	})
	return count, err
}

// singleFileFS is an fs.FS containing exactly one file.
type singleFileFS struct {
	path string // absolute path to the file
}

func (s *singleFileFS) Open(name string) (fs.File, error) {
	if name == "." {
		return &singleFileDirHandle{fsys: s}, nil
	}
	if name == filepath.Base(s.path) {
		return os.Open(s.path)
	}
	return nil, fs.ErrNotExist
}

type singleFileDirHandle struct {
	fsys   *singleFileFS
	offset int
}

func (d *singleFileDirHandle) Stat() (fs.FileInfo, error)  { return &dirInfo{name: "."}, nil }
func (d *singleFileDirHandle) Read([]byte) (int, error)    { return 0, fmt.Errorf("is a directory") }
func (d *singleFileDirHandle) Close() error                { return nil }

func (d *singleFileDirHandle) ReadDir(n int) ([]fs.DirEntry, error) {
	info, err := os.Stat(d.fsys.path)
	if err != nil {
		return nil, err
	}
	entries := []fs.DirEntry{fs.FileInfoToDirEntry(info)}

	if n <= 0 {
		result := entries[d.offset:]
		d.offset = len(entries)
		return result, nil
	}
	if d.offset >= len(entries) {
		return nil, io.EOF
	}
	end := d.offset + n
	if end > len(entries) {
		end = len(entries)
	}
	result := entries[d.offset:end]
	d.offset = end
	return result, nil
}

// getEmbeddedFileSystems resolves embedded template paths against the bundled archive.
func getEmbeddedFileSystems(ctx context.Context, templatePaths []string) ([]fs.FS, error) {
	log := svc1log.FromContext(ctx)

	var allTemplateFiles []string

	for _, templatePath := range templatePaths {
		cleanPath := strings.TrimPrefix(templatePath, "utils/nuclei/templates/")
		if !strings.HasPrefix(cleanPath, "pentest/") && !strings.HasPrefix(cleanPath, "discover/") {
			cleanPath = filepath.Join("pentest", cleanPath)
		}

		if isTemplateFile(cleanPath) {
			if _, err := fs.Stat(All, cleanPath); err != nil {
				log.Warn("Template file not found, skipping",
					svc1log.SafeParam("templatePath", templatePath),
					svc1log.SafeParam("cleanPath", cleanPath),
					svc1log.SafeParam("error", err.Error()))
				continue
			}
			allTemplateFiles = append(allTemplateFiles, cleanPath)
		} else {
			templates, err := collectTemplatesFromDirectory(cleanPath)
			if err != nil {
				log.Warn("Failed to collect templates from directory, skipping",
					svc1log.SafeParam("templatePath", templatePath),
					svc1log.SafeParam("cleanPath", cleanPath),
					svc1log.SafeParam("error", err.Error()))
				continue
			}
			allTemplateFiles = append(allTemplateFiles, templates...)
		}
	}

	if len(allTemplateFiles) == 0 {
		return nil, fmt.Errorf("no valid template files found")
	}

	log.Info("Found embedded template files", svc1log.SafeParam("templateCount", len(allTemplateFiles)))

	dirToFiles := make(map[string][]string)
	for _, templateFile := range allTemplateFiles {
		templateDir := filepath.Dir(templateFile)
		templateName := filepath.Base(templateFile)
		dirToFiles[templateDir] = append(dirToFiles[templateDir], templateName)
	}

	var filesystems []fs.FS
	for templateDir, templateFiles := range dirToFiles {
		baseFS, err := fs.Sub(All, templateDir)
		if err != nil {
			log.Warn("Template directory not found, skipping",
				svc1log.SafeParam("templateDir", templateDir),
				svc1log.SafeParam("error", err.Error()))
			continue
		}
		filesystems = append(filesystems, &specificTemplateFS{
			baseFS:        baseFS,
			templateFiles: templateFiles,
		})
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
