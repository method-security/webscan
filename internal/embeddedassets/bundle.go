package embeddedassets

import (
	"archive/tar"
	"compress/gzip"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Bundle describes a set of source roots to archive with paths relative to Base.
type Bundle struct {
	Output string
	Roots  []string
	Base   string
}

type archiveFile struct {
	source string
	name   string
}

// WriteBundle writes a deterministic tar.gz archive for the provided bundle.
func WriteBundle(b Bundle) (returnErr error) {
	files, err := collectFiles(b)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(b.Output), 0o755); err != nil {
		return err
	}

	out, err := os.Create(b.Output)
	if err != nil {
		return err
	}
	defer func() {
		if err := out.Close(); returnErr == nil {
			returnErr = err
		}
	}()

	gzw, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		return err
	}
	gzw.ModTime = time.Unix(0, 0).UTC()
	gzw.OS = 255

	tw := tar.NewWriter(gzw)
	for _, file := range files {
		data, err := os.ReadFile(file.source)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{
			Name:     file.name,
			Mode:     0o644,
			Size:     int64(len(data)),
			ModTime:  time.Unix(0, 0).UTC(),
			Typeflag: tar.TypeReg,
		}); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gzw.Close()
}

func collectFiles(b Bundle) ([]archiveFile, error) {
	var files []archiveFile
	for _, root := range b.Roots {
		if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if isEmbedExcluded(d.Name()) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(b.Base, p)
			if err != nil {
				return err
			}
			files = append(files, archiveFile{
				source: p,
				name:   filepath.ToSlash(rel),
			})
			return nil
		}); err != nil {
			return nil, err
		}
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].name < files[j].name
	})
	return files, nil
}

func isEmbedExcluded(name string) bool {
	return len(name) > 0 && (name[0] == '.' || name[0] == '_')
}
