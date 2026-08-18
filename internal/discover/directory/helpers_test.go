package discoverdirectory

import (
	"reflect"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
)

func TestApplyExtensions(t *testing.T) {
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
			got := applyExtensions(tc.paths, tc.extensions)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("applyExtensions(%q, %q) = %q, want %q", tc.paths, tc.extensions, got, tc.want)
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
		if got := pathLooksLikeFile(path); got != want {
			t.Errorf("pathLooksLikeFile(%q) = %v, want %v", path, got, want)
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
		if got := normalizeFrontierPath(path); got != want {
			t.Errorf("normalizeFrontierPath(%q) = %q, want %q", path, got, want)
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
		name  string
		in    *common.HttpRequestResponse
		noisy map[int]bool
		want  bool
	}{
		{name: "forbidden directory still proves the directory exists", in: attempt("/static", 403), want: true},
		{name: "status outside the recursion set", in: attempt("/static", 404), want: false},
		{name: "a file is never descended into", in: attempt("/static/app.js", 200), want: false},
		{name: "redirect with no body is still a candidate", in: attempt("/static", 301), want: true},
		{name: "status outside the recursion set is skipped", in: attempt("/static", 500), want: false},
		{name: "status a random path also returns is noise", in: attempt("/static", 403), noisy: map[int]bool{403: true}, want: false},
		{name: "missing response", in: &common.HttpRequestResponse{Request: &common.HttpRequest{Path: "/static"}}, want: false},
		{name: "nil attempt", in: nil, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			noisy := tc.noisy
			if noisy == nil {
				noisy = map[int]bool{}
			}
			if got := isRecursionCandidate(tc.in, codes, noisy); got != tc.want {
				t.Errorf("isRecursionCandidate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStatusCodesOf(t *testing.T) {
	status := func(code int) *common.HttpRequestResponse {
		return &common.HttpRequestResponse{Response: &common.HttpResponse{StatusCode: &code}}
	}
	got := statusCodesOf([]*common.HttpRequestResponse{status(404), status(404), status(403), nil, {}})
	want := map[int]bool{404: true, 403: true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("statusCodesOf() = %v, want %v", got, want)
	}
}
