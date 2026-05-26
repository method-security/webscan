package compressedfs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// NewLazyTarGzip returns a filesystem that inflates the archive on first use.
func NewLazyTarGzip(data []byte) fs.FS {
	return &LazyFS{data: data}
}

// LoadTarGzip loads a gzip-compressed tar archive into an in-memory fs.FS.
func LoadTarGzip(data []byte) (*FS, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	defer func() {
		_ = gzr.Close()
	}()

	fsys := &FS{entries: make(map[string]*entry)}
	fsys.ensureDir(".")

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar entry: %w", err)
		}

		name, err := cleanArchivePath(hdr.Name)
		if err != nil {
			return nil, err
		}
		if name == "." {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			fsys.ensureDir(name)
		case tar.TypeReg, tar.TypeRegA:
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("read %s: %w", name, err)
			}
			fsys.ensureDir(path.Dir(name))
			mode := fs.FileMode(hdr.Mode) & 0o777
			if mode == 0 {
				mode = 0o644
			}
			fsys.entries[name] = &entry{
				name:    name,
				base:    path.Base(name),
				mode:    mode,
				modTime: normalizeModTime(hdr.ModTime),
				data:    data,
			}
		}
	}

	fsys.rebuildChildren()
	return fsys, nil
}

// LazyFS defers loading a compressed archive until the first filesystem operation.
type LazyFS struct {
	data []byte
	once sync.Once
	fsys *FS
	err  error
}

func (l *LazyFS) Open(name string) (fs.File, error) {
	fsys, err := l.load()
	if err != nil {
		return nil, err
	}
	return fsys.Open(name)
}

func (l *LazyFS) ReadFile(name string) ([]byte, error) {
	fsys, err := l.load()
	if err != nil {
		return nil, err
	}
	return fsys.ReadFile(name)
}

func (l *LazyFS) ReadDir(name string) ([]fs.DirEntry, error) {
	fsys, err := l.load()
	if err != nil {
		return nil, err
	}
	return fsys.ReadDir(name)
}

func (l *LazyFS) Stat(name string) (fs.FileInfo, error) {
	fsys, err := l.load()
	if err != nil {
		return nil, err
	}
	return fsys.Stat(name)
}

func (l *LazyFS) load() (*FS, error) {
	l.once.Do(func() {
		l.fsys, l.err = LoadTarGzip(l.data)
	})
	return l.fsys, l.err
}

// FS is an in-memory filesystem loaded from a compressed archive.
type FS struct {
	entries map[string]*entry
}

func (f *FS) Open(name string) (fs.File, error) {
	clean, err := cleanFSPath(name)
	if err != nil {
		return nil, err
	}

	e, ok := f.entries[clean]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if e.IsDir() {
		children := append([]fs.DirEntry(nil), e.children...)
		return &dirFile{entry: e, entries: children}, nil
	}

	return &memFile{Reader: bytes.NewReader(e.data), entry: e}, nil
}

func (f *FS) ReadFile(name string) ([]byte, error) {
	clean, err := cleanFSPath(name)
	if err != nil {
		return nil, err
	}

	e, ok := f.entries[clean]
	if !ok {
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrNotExist}
	}
	if e.IsDir() {
		return nil, &fs.PathError{Op: "read", Path: name, Err: errIsDir}
	}

	return append([]byte(nil), e.data...), nil
}

func (f *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	clean, err := cleanFSPath(name)
	if err != nil {
		return nil, err
	}

	e, ok := f.entries[clean]
	if !ok {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	if !e.IsDir() {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errNotDir}
	}

	return append([]fs.DirEntry(nil), e.children...), nil
}

func (f *FS) Stat(name string) (fs.FileInfo, error) {
	clean, err := cleanFSPath(name)
	if err != nil {
		return nil, err
	}

	e, ok := f.entries[clean]
	if !ok {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
	}
	return e, nil
}

func (f *FS) ensureDir(name string) {
	if name == "" {
		name = "."
	}
	name = path.Clean(name)
	if _, ok := f.entries[name]; ok {
		return
	}
	f.entries[name] = &entry{
		name:    name,
		base:    path.Base(name),
		mode:    fs.ModeDir | 0o755,
		modTime: time.Unix(0, 0).UTC(),
	}
	if name != "." {
		f.ensureDir(path.Dir(name))
	}
}

func (f *FS) rebuildChildren() {
	for _, e := range f.entries {
		e.children = nil
	}
	for name, e := range f.entries {
		if name == "." {
			continue
		}
		parent := f.entries[path.Dir(name)]
		parent.children = append(parent.children, e)
	}
	for _, e := range f.entries {
		sort.Slice(e.children, func(i, j int) bool {
			return e.children[i].Name() < e.children[j].Name()
		})
	}
}

type entry struct {
	name     string
	base     string
	mode     fs.FileMode
	modTime  time.Time
	data     []byte
	children []fs.DirEntry
}

func (e *entry) Name() string {
	if e.name == "." {
		return "."
	}
	return e.base
}

func (e *entry) Size() int64 {
	return int64(len(e.data))
}

func (e *entry) Mode() fs.FileMode {
	return e.mode
}

func (e *entry) ModTime() time.Time {
	return e.modTime
}

func (e *entry) IsDir() bool {
	return e.mode.IsDir()
}

func (e *entry) Sys() any {
	return nil
}

func (e *entry) Type() fs.FileMode {
	return e.mode.Type()
}

func (e *entry) Info() (fs.FileInfo, error) {
	return e, nil
}

type memFile struct {
	*bytes.Reader
	entry *entry
}

func (f *memFile) Stat() (fs.FileInfo, error) {
	return f.entry, nil
}

func (f *memFile) Close() error {
	return nil
}

type dirFile struct {
	entry   *entry
	entries []fs.DirEntry
	offset  int
}

func (d *dirFile) Stat() (fs.FileInfo, error) {
	return d.entry, nil
}

func (d *dirFile) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.entry.name, Err: errIsDir}
}

func (d *dirFile) Close() error {
	return nil
}

func (d *dirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if d.offset >= len(d.entries) && n > 0 {
		return nil, io.EOF
	}

	if n <= 0 {
		out := append([]fs.DirEntry(nil), d.entries[d.offset:]...)
		d.offset = len(d.entries)
		return out, nil
	}

	end := d.offset + n
	if end > len(d.entries) {
		end = len(d.entries)
	}
	out := append([]fs.DirEntry(nil), d.entries[d.offset:end]...)
	d.offset = end
	return out, nil
}

func cleanArchivePath(name string) (string, error) {
	clean := strings.TrimPrefix(path.Clean(strings.TrimPrefix(name, "/")), "./")
	if clean == "" {
		clean = "."
	}
	if clean == "." {
		return clean, nil
	}
	if !fs.ValidPath(clean) {
		return "", fmt.Errorf("invalid archive path %q", name)
	}
	return clean, nil
}

func cleanFSPath(name string) (string, error) {
	if name == "." {
		return ".", nil
	}
	if !fs.ValidPath(name) {
		return "", &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	return path.Clean(name), nil
}

func normalizeModTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Unix(0, 0).UTC()
	}
	return t.UTC()
}

var (
	errIsDir  = errors.New("is a directory")
	errNotDir = errors.New("not a directory")
)
