package directory_test

import (
	"reflect"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	discoverdirectory "github.com/Method-Security/webscan/internal/discover/directory"
)

func TestExpandPathsExtensionsOnly(t *testing.T) {
	for _, tc := range []struct {
		name       string
		paths      []string
		extensions []string
		want       []string
	}{
		{
			name:       "no extensions leaves paths untouched",
			paths:      []string{"static", "app"},
			extensions: nil,
			want:       []string{"static", "app"},
		},
		{
			name:       "bare word is always probed alongside each variant",
			paths:      []string{"app"},
			extensions: []string{"js", ".map"},
			want:       []string{"app", "app.js", "app.map"},
		},
		{
			name:       "extensions are normalized and de-duplicated",
			paths:      []string{"app"},
			extensions: []string{" .JS ", "js", "", "."},
			want:       []string{"app", "app.js"},
		},
		{
			name:       "surrounding slashes are trimmed before appending",
			paths:      []string{"/static/"},
			extensions: []string{"js"},
			want:       []string{"/static/", "static.js"},
		},
		{
			name:       "root path takes no extension",
			paths:      []string{""},
			extensions: []string{"js"},
			want:       []string{""},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := discoverdirectory.ExpandPaths(tc.paths, tc.extensions, false)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("discoverdirectory.ExpandPaths(%q, %q, false) = %q, want %q", tc.paths, tc.extensions, got, tc.want)
			}
		})
	}
}

func TestPathLooksLikeFile(t *testing.T) {
	for path, want := range map[string]bool{
		"/static":         false,
		"/static/":        false,
		"/static/app.js":  true,
		"/v1.0/admin":     false,
		"/.env":           true,
		"":                false,
		"/assets/main.js": true,
	} {
		if got := discoverdirectory.PathLooksLikeFile(path); got != want {
			t.Errorf("discoverdirectory.PathLooksLikeFile(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestNormalizeFrontierPath(t *testing.T) {
	for path, want := range map[string]string{
		"/static/": "/static",
		"/static":  "/static",
		"/":        "/",
		"":         "/",
		"/a/b/":    "/a/b",
	} {
		if got := discoverdirectory.NormalizeFrontierPath(path); got != want {
			t.Errorf("discoverdirectory.NormalizeFrontierPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestIsRecursionCandidate(t *testing.T) {
	codes := map[int]bool{200: true, 301: true, 403: true}
	attempt := func(path string, status int) *common.HttpRequestResponse {
		return &common.HttpRequestResponse{
			Request:  &common.HttpRequest{Path: path},
			Response: &common.HttpResponse{StatusCode: &status},
		}
	}

	for _, tc := range []struct {
		name string
		in   *common.HttpRequestResponse
		want bool
	}{
		{name: "forbidden directory still proves the directory exists", in: attempt("/static", 403), want: true},
		{name: "a file is never descended into", in: attempt("/static/app.js", 200), want: false},
		{name: "redirect with no body is still a candidate", in: attempt("/static", 301), want: true},
		{name: "status outside the recursion set is skipped", in: attempt("/static", 500), want: false},
		{name: "missing response", in: &common.HttpRequestResponse{Request: &common.HttpRequest{Path: "/static"}}, want: false},
		{name: "nil attempt", in: nil, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := discoverdirectory.IsRecursionCandidate(tc.in, codes); got != tc.want {
				t.Errorf("discoverdirectory.IsRecursionCandidate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsUnfilteredRecursionCandidate(t *testing.T) {
	codes := map[int]bool{200: true, 403: true}
	attempt := func(path string, status int) *common.HttpRequestResponse {
		return &common.HttpRequestResponse{
			Request:  &common.HttpRequest{Path: path},
			Response: &common.HttpResponse{StatusCode: &status},
		}
	}

	if !discoverdirectory.IsUnfilteredRecursionCandidate(attempt("/static", 403), codes, map[int]bool{}) {
		t.Error("a 403 directory with a clean noise floor should be a candidate")
	}
	if discoverdirectory.IsUnfilteredRecursionCandidate(attempt("/static", 403), codes, map[int]bool{403: true}) {
		t.Error("a status every calibration probe returned should not be a candidate")
	}
	if discoverdirectory.IsUnfilteredRecursionCandidate(attempt("/static/app.js", 403), codes, map[int]bool{}) {
		t.Error("a file should never be a candidate")
	}
}

func TestUnanimousDirectoryStatuses(t *testing.T) {
	probe := func(path string, code int) *common.HttpRequestResponse {
		return &common.HttpRequestResponse{
			Request:  &common.HttpRequest{Path: path},
			Response: &common.HttpResponse{StatusCode: &code},
		}
	}

	for _, tc := range []struct {
		name string
		in   []*common.HttpRequestResponse
		want map[int]bool
	}{
		{
			name: "a status every directory probe returns is noise",
			in:   []*common.HttpRequestResponse{probe("/cal-1", 404), probe("/cal-2/", 404)},
			want: map[int]bool{404: true},
		},
		{
			name: "one divergent probe must not suppress a real directory status",
			in:   []*common.HttpRequestResponse{probe("/cal-1", 403), probe("/cal-2/", 404)},
			want: map[int]bool{},
		},
		{
			name: "the file-shaped probe does not inform directory noise",
			in:   []*common.HttpRequestResponse{probe("/cal-1", 404), probe("/cal-2/", 404), probe("/cal-3.txt", 403)},
			want: map[int]bool{404: true},
		},
		{
			name: "too little evidence yields no noise floor",
			in:   []*common.HttpRequestResponse{probe("/cal-1", 403)},
			want: map[int]bool{},
		},
		{
			name: "malformed probes are ignored",
			in:   []*common.HttpRequestResponse{probe("/cal-1", 404), probe("/cal-2/", 404), nil, {}},
			want: map[int]bool{404: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := discoverdirectory.UnanimousDirectoryStatuses(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("discoverdirectory.UnanimousDirectoryStatuses() = %v, want %v", got, tc.want)
			}
		})
	}
}
