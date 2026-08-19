package helpers_test

import (
	"context"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	standardhelpers "github.com/Method-Security/webscan/utils/request/standard/helpers"
)

func constructed(t *testing.T, baseURL, path string, params common.HttpRequestParams) string {
	t.Helper()
	request := &common.HttpRequest{BaseUrl: baseURL, Path: path, Method: common.HttpMethodGet, Params: &params}
	got, err := standardhelpers.ConstructURL(context.Background(), request)
	if err != nil {
		t.Fatalf("ConstructURL(%q, %q) returned error: %v", baseURL, path, err)
	}
	return *got
}

func TestConstructURLPreservesTrailingSlash(t *testing.T) {
	for _, tc := range []struct {
		name string
		base string
		path string
		want string
	}{
		{
			name: "trailing slash reaches the server",
			base: "https://api.example.com",
			path: "/static/",
			want: "https://api.example.com/static/",
		},
		{
			name: "no trailing slash stays bare",
			base: "https://api.example.com",
			path: "/static",
			want: "https://api.example.com/static",
		},
		{
			name: "nested directory form is preserved",
			base: "https://api.example.com",
			path: "/assets/js/",
			want: "https://api.example.com/assets/js/",
		},
		{
			name: "root path",
			base: "https://api.example.com",
			path: "/",
			want: "https://api.example.com/",
		},
		{
			name: "empty path",
			base: "https://api.example.com",
			path: "",
			want: "https://api.example.com",
		},
		{
			name: "file path is untouched",
			base: "https://api.example.com",
			path: "/static/app.js",
			want: "https://api.example.com/static/app.js",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := constructed(t, tc.base, tc.path, common.HttpRequestParams{}); got != tc.want {
				t.Errorf("ConstructURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestConstructURLPathParamsAndQuery(t *testing.T) {
	got := constructed(t, "https://api.example.com", "/api/v1/customers/{id}/", common.HttpRequestParams{
		Path:  map[string]string{"id": "4021"},
		Query: map[string]string{"expand": "orders"},
	})
	want := "https://api.example.com/api/v1/customers/4021/?expand=orders"
	if got != want {
		t.Errorf("ConstructURL() = %q, want %q", got, want)
	}
}

func TestConstructURLEscapedPath(t *testing.T) {
	got := constructed(t, "https://api.example.com", "/files/report%20final/", common.HttpRequestParams{})
	want := "https://api.example.com/files/report%20final/"
	if got != want {
		t.Errorf("ConstructURL() = %q, want %q", got, want)
	}
}
