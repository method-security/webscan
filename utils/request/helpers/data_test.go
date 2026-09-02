package request_test

import (
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

func TestNormalizeTargetPath(t *testing.T) {
	for path, want := range map[string]string{
		"":               "",
		"/":              "",
		"//":             "",
		"/static":        "/static",
		"/static/":       "/static/",
		"static/":        "/static/",
		"//static/":      "/static/",
		"/a/b/":          "/a/b/",
		"/static/app.js": "/static/app.js",
	} {
		if got := requesthelpers.NormalizeTargetPath(path); got != want {
			t.Errorf("NormalizeTargetPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestJoinPath(t *testing.T) {
	for _, tc := range []struct{ base, child, want string }{
		{"", "wp-json", "/wp-json"},
		{"/", "wp-json", "/wp-json"},
		{"/blog", "wp-json", "/blog/wp-json"},
		{"/blog", "/wp-json", "/blog/wp-json"},
		{"/blog/", "/wp-json", "/blog/wp-json"},
		{"/blog/", "wp-json/", "/blog/wp-json/"},
		{"/blog", "", "/blog/"},
	} {
		if got := requesthelpers.JoinPath(tc.base, tc.child); got != tc.want {
			t.Errorf("JoinPath(%q, %q) = %q, want %q", tc.base, tc.child, got, tc.want)
		}
	}
}

func TestSplitTargetURLPreservesTrailingSlash(t *testing.T) {
	for _, tc := range []struct{ target, wantBase, wantPath string }{
		{"https://api.example.com/static/", "https://api.example.com", "/static/"},
		{"https://api.example.com/static", "https://api.example.com", "/static"},
		{"https://api.example.com/", "https://api.example.com", ""},
		{"https://api.example.com", "https://api.example.com", ""},
		{"https://api.example.com:8443/a/b/", "https://api.example.com:8443", "/a/b/"},
	} {
		base, path, _, err := requesthelpers.SplitTargetURL(tc.target)
		if err != nil {
			t.Fatalf("SplitTargetURL(%q) returned error: %v", tc.target, err)
		}
		if base != tc.wantBase || path != tc.wantPath {
			t.Errorf("SplitTargetURL(%q) = (%q, %q), want (%q, %q)", tc.target, base, path, tc.wantBase, tc.wantPath)
		}
	}
}

func TestGetResponseBodyMimeTypeFromBodyStruct(t *testing.T) {
	for _, tc := range []struct {
		name string
		body *common.Body
		want string
	}{
		{
			name: "binary",
			body: requesthelpers.CreateBodyFromBytes("image/x-icon", []byte{0, 0, 1, 0}),
			want: "image/x-icon",
		},
		{
			name: "text with parameters",
			body: requesthelpers.CreateBodyFromBytes("Text/HTML; charset=utf-8", []byte("<html></html>")),
			want: "text/html",
		},
		{
			name: "nil body",
			body: nil,
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := requesthelpers.GetResponseBodyMimeTypeFromBodyStruct(tc.body); got != tc.want {
				t.Errorf("GetResponseBodyMimeTypeFromBodyStruct() = %q, want %q", got, tc.want)
			}
		})
	}
}
