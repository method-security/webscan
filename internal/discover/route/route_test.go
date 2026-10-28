package discoverroute

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Method-Security/webscan/generated/go/discover"
	extractors "github.com/Method-Security/webscan/internal/discover/route/helpers/extractors"
	"github.com/PuerkitoBio/goquery"
)

func TestBuildWebApplicationsSeparatesWebFiles(t *testing.T) {
	const baseURL = "https://app.example.com"
	applications := buildWebApplications(nil, map[string][]string{
		baseURL: {
			baseURL + "/report.PDF?download=1#page=2",
			baseURL + "/export.csv",
			baseURL + "/export.csv",
			"https://files.app.example.com/archive.zip",
			"https://downloads.other.com/manual.docx",
			baseURL + "/app.js",
			baseURL + "/app.css",
			"https://cdn.other.com/logo.png",
		},
		baseURL + ":443": {baseURL + "/export.csv", baseURL + "/app.js"},
	})
	if len(applications) != 1 {
		t.Fatalf("expected one application, got %d", len(applications))
	}
	application := applications[0]
	if application.WebFiles == nil || application.StaticAssets == nil {
		t.Fatalf("expected separate file and asset collections: %+v", application)
	}
	assertURLs := func(name string, got, want []string) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	assertURLs("local files", application.WebFiles.Local, []string{
		baseURL + "/export.csv", baseURL + "/report.PDF?download=1#page=2",
		"https://files.app.example.com/archive.zip",
	})
	assertURLs("remote files", application.WebFiles.Remote, []string{"https://downloads.other.com/manual.docx"})
	assertURLs("local assets", application.StaticAssets.Local, []string{baseURL + "/app.css", baseURL + "/app.js"})
	assertURLs("remote assets", application.StaticAssets.Remote, []string{"https://cdn.other.com/logo.png"})
}

func TestWebFileOnlyApplicationSerializesSeparateSignalField(t *testing.T) {
	applications := buildWebApplications(nil, map[string][]string{
		"https://app.example.com": {"https://app.example.com/manual.pdf"},
	})
	if len(applications) != 1 || applications[0].WebFiles == nil || applications[0].StaticAssets != nil {
		t.Fatalf("expected files without static assets, got %+v", applications)
	}
	data, err := json.Marshal(applications[0])
	if err != nil {
		t.Fatal(err)
	}
	var signal map[string]json.RawMessage
	if err := json.Unmarshal(data, &signal); err != nil {
		t.Fatal(err)
	}
	if _, ok := signal["webFiles"]; !ok {
		t.Fatalf("signal is missing webFiles: %s", data)
	}
	if _, ok := signal["staticAssets"]; ok {
		t.Fatalf("file-only signal should omit staticAssets: %s", data)
	}
}

func TestSpiderWebFilesHonorCollectionAndScope(t *testing.T) {
	const baseURL = "https://app.example.com"
	for _, test := range []struct {
		name           string
		collect        bool
		ignoreExternal bool
		wantLocal      int
		wantRemote     int
	}{
		{"disabled", false, false, 0, 0},
		{"local only", true, true, 1, 0},
		{"include remote", true, false, 1, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			doc, err := goquery.NewDocumentFromReader(strings.NewReader(`<a href="/manual.pdf">PDF</a>
				<a href="https://downloads.other.com/archive.zip">Archive</a>`))
			if err != nil {
				t.Fatal(err)
			}
			routes, urls, errors := extractors.ExtractAnchorRoutes(doc, baseURL, discover.DiscoverRouteConfig{
				Target: baseURL, CollectStaticAssets: test.collect,
				IgnoreCrossDomainStaticAssets: test.ignoreExternal,
			})
			if len(errors) > 0 || len(routes) > 0 {
				t.Fatalf("documents should not become spider routes: routes=%v errors=%v", routes, errors)
			}
			applications := buildWebApplications(routes, map[string][]string{baseURL: urls})
			files := applications[0].WebFiles
			if !test.collect {
				if files != nil {
					t.Fatalf("expected no files when collection is disabled, got %+v", files)
				}
				return
			}
			if files == nil || len(files.Local) != test.wantLocal || len(files.Remote) != test.wantRemote {
				t.Fatalf("unexpected file scope: %+v", files)
			}
		})
	}
}

func TestWebFileURLClassification(t *testing.T) {
	for _, extension := range []string{
		"7z", "csv", "doc", "docx", "gz", "ini", "json", "markdown", "md", "pdf", "ppt", "pptx",
		"rar", "tar", "toml", "txt", "xls", "xlsx", "xml", "yaml", "yml", "zip",
	} {
		if !isWebFileURL("https://app.example.com/file." + extension + "?download=1") {
			t.Errorf("expected %s to be a web file", extension)
		}
	}
	for _, reference := range []string{"app.js", "style.css", "logo.png", "font.woff2", "video.mp4", "page.html", "download", "page?name=file.pdf"} {
		if isWebFileURL("https://app.example.com/" + reference) {
			t.Errorf("unexpected web file classification for %s", reference)
		}
	}
}
