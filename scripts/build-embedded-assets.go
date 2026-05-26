//go:build ignore

package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

func main() {
	bundles := []bundle{
		{
			output: "configs/embedded/configs.tar.gz",
			roots:  []string{"configs/discover", "configs/enumerate", "configs/pentest"},
			base:   "configs",
		},
		{
			output: "utils/nuclei/templates/embedded/templates.tar.gz",
			roots:  []string{"utils/nuclei/templates/discover", "utils/nuclei/templates/pentest"},
			base:   "utils/nuclei/templates",
		},
	}

	for _, b := range bundles {
		if err := writeBundle(b); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", b.output, err)
			os.Exit(1)
		}
	}
}

type bundle struct {
	output string
	roots  []string
	base   string
}

type archiveFile struct {
	source string
	name   string
}

func writeBundle(b bundle) error {
	files, err := collectFiles(b)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(b.output), 0o755); err != nil {
		return err
	}

	out, err := os.Create(b.output)
	if err != nil {
		return err
	}
	defer out.Close()

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

func collectFiles(b bundle) ([]archiveFile, error) {
	var files []archiveFile
	for _, root := range b.roots {
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
			rel, err := filepath.Rel(b.base, p)
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
