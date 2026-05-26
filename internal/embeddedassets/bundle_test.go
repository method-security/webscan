package embeddedassets

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCollectFilesExcludesEmbedIgnoredNames(t *testing.T) {
	base := t.TempDir()
	roots := []string{
		filepath.Join(base, "discover"),
		filepath.Join(base, "pentest"),
	}

	for _, path := range []string{
		"discover/http.yaml",
		"discover/.gitkeep",
		"discover/_metadata.yaml",
		"discover/.cache/hidden.yaml",
		"discover/_generated/hidden.yaml",
		"discover/nested/.DS_Store",
		"discover/nested/_helper.yaml",
		"discover/nested/visible.yaml",
		"pentest/scan.yaml",
	} {
		writeTestFile(t, filepath.Join(base, path))
	}

	files, err := collectFiles(Bundle{
		Roots: roots,
		Base:  base,
	})
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, file := range files {
		names = append(names, file.name)
	}

	want := []string{
		"discover/http.yaml",
		"discover/nested/visible.yaml",
		"pentest/scan.yaml",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("collected files mismatch\n got: %#v\nwant: %#v", names, want)
	}
}

func writeTestFile(t *testing.T, path string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
}
