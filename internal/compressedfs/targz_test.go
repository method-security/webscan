package compressedfs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io/fs"
	"testing"
	"time"
)

func TestLoadTarGzip(t *testing.T) {
	archive := testArchive(t, map[string]string{
		"discover/a.yaml": "id: a\n",
		"pentest/b.yml":   "id: b\n",
	})

	fsys, err := LoadTarGzip(archive)
	if err != nil {
		t.Fatalf("LoadTarGzip returned error: %v", err)
	}

	data, err := fs.ReadFile(fsys, "discover/a.yaml")
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(data) != "id: a\n" {
		t.Fatalf("ReadFile data = %q", string(data))
	}

	sub, err := fs.Sub(fsys, "pentest")
	if err != nil {
		t.Fatalf("Sub returned error: %v", err)
	}
	data, err = fs.ReadFile(sub, "b.yml")
	if err != nil {
		t.Fatalf("sub ReadFile returned error: %v", err)
	}
	if string(data) != "id: b\n" {
		t.Fatalf("sub ReadFile data = %q", string(data))
	}

	var walked []string
	if err := fs.WalkDir(fsys, ".", func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		walked = append(walked, path)
		return nil
	}); err != nil {
		t.Fatalf("WalkDir returned error: %v", err)
	}

	want := []string{".", "discover", "discover/a.yaml", "pentest", "pentest/b.yml"}
	if len(walked) != len(want) {
		t.Fatalf("walked paths = %#v", walked)
	}
	for i := range want {
		if walked[i] != want[i] {
			t.Fatalf("walked[%d] = %q, want %q; all paths %#v", i, walked[i], want[i], walked)
		}
	}
}

func TestLazyTarGzipDefersLoadUntilFirstUse(t *testing.T) {
	fsys := NewLazyTarGzip([]byte("not a gzip archive"))

	if _, err := fs.ReadFile(fsys, "anything"); err == nil {
		t.Fatal("ReadFile returned nil error for invalid archive")
	}
}

func TestLazyTarGzipLoadsValidArchive(t *testing.T) {
	fsys := NewLazyTarGzip(testArchive(t, map[string]string{
		"discover/a.yaml": "id: a\n",
	}))

	data, err := fs.ReadFile(fsys, "discover/a.yaml")
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	if string(data) != "id: a\n" {
		t.Fatalf("ReadFile data = %q", string(data))
	}
}

func testArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	gzw.ModTime = time.Unix(0, 0).UTC()
	tw := tar.NewWriter(gzw)
	for name, contents := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(contents)),
			ModTime:  time.Unix(0, 0).UTC(),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("WriteHeader: %v", err)
		}
		if _, err := tw.Write([]byte(contents)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}
