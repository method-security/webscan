package enumeratejavascript_test

import (
	"os"
	"sort"
	"strings"
	"testing"

	enumeratejavascript "github.com/Method-Security/webscan/internal/enumerate/javascript/helpers"
)

const angularRuntime = `r.f={},r.e=e=>Promise.all(Object.keys(r.f).reduce((n,t)=>(r.f[t](e,n),n),[])),` +
	`r.u=e=>(244===e?"common":e)+"."+{12:"72be1c23b6720bf4",27:"c9e27dcded280830",244:"5f063605d7248ff0"}[e]+".js",` +
	`r.miniCssF=e=>{},r.p="",`

func TestExtractWebpackChunkNamesAppliesHashAndRename(t *testing.T) {
	names := enumeratejavascript.ExtractWebpackChunkNames(angularRuntime)
	sort.Strings(names)

	expected := []string{
		"12.72be1c23b6720bf4.js",
		"27.c9e27dcded280830.js",
		"common.5f063605d7248ff0.js",
	}
	if len(names) != len(expected) {
		t.Fatalf("expected %d chunks, got %d: %v", len(expected), len(names), names)
	}
	for i, want := range expected {
		if names[i] != want {
			t.Fatalf("expected %s, got %s", want, names[i])
		}
	}
}

func TestExtractWebpackChunkNamesHonorsLiteralPrefix(t *testing.T) {
	runtime := `r.u=e=>"static/js/"+e+"."+{7:"aaaa1111"}[e]+".chunk.js",r.p="",`
	names := enumeratejavascript.ExtractWebpackChunkNames(runtime)
	if len(names) != 1 || names[0] != "static/js/7.aaaa1111.chunk.js" {
		t.Fatalf("expected the prefixed chunk name, got %v", names)
	}
}

func TestExtractWebpackChunkNamesIgnoresRuntimeWithoutManifest(t *testing.T) {
	if names := enumeratejavascript.ExtractWebpackChunkNames(`r.p="",r.nc=void 0`); len(names) != 0 {
		t.Fatalf("expected no chunks, got %v", names)
	}
}

func TestExtractPublicPathReadsConfiguredOrigin(t *testing.T) {
	if got := enumeratejavascript.ExtractPublicPath(`r.p="https://cdn.example.com/app/",`); got != "https://cdn.example.com/app/" {
		t.Fatalf("expected the configured public path, got %q", got)
	}
	if got := enumeratejavascript.ExtractPublicPath(angularRuntime); got != "" {
		t.Fatalf("expected an empty public path, got %q", got)
	}
}

func TestExtractViteChunkNamesFindsAssetImports(t *testing.T) {
	names := enumeratejavascript.ExtractViteChunkNames(`import("./assets/Dashboard-a1b2c3.js");const x="/assets/vendor-d4e5f6.js"`)
	sort.Strings(names)
	if len(names) != 2 || names[0] != "/assets/vendor-d4e5f6.js" || names[1] != "assets/Dashboard-a1b2c3.js" {
		t.Fatalf("expected both vite assets, got %v", names)
	}
}

// The parser must hold up against a full webpack runtime, not just the fragments above.
func TestExtractWebpackChunkNamesAgainstFullRuntime(t *testing.T) {
	content, err := os.ReadFile("testdata/webpack-runtime.js")
	if err != nil {
		t.Fatalf("reading runtime fixture: %s", err)
	}

	names := enumeratejavascript.ExtractWebpackChunkNames(string(content))
	if len(names) != 16 {
		t.Fatalf("expected 16 chunks, got %d: %v", len(names), names)
	}
	for _, name := range names {
		if !strings.HasSuffix(name, ".js") {
			t.Fatalf("expected every chunk to be a .js file, got %s", name)
		}
	}

	joined := strings.Join(names, " ")
	if !strings.Contains(joined, "common.5f063605d7248ff0.js") {
		t.Fatalf("expected the renamed common chunk, got %v", names)
	}
	if strings.Contains(joined, "244.") {
		t.Fatalf("expected chunk 244 to be renamed rather than emitted by id, got %v", names)
	}
}
