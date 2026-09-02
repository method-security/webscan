package witnesshelpers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchFaviconRejectsHtmlContentType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<!doctype html><title>Access denied</title>"))
	}))
	t.Cleanup(server.Close)

	body, hash, err := FetchFavicon(context.Background(), server.URL, faviconConfig())
	require.NoError(t, err)
	assert.Nil(t, body)
	assert.Empty(t, hash)
}

func TestFetchFaviconRejectsEmptyBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	body, hash, err := FetchFavicon(context.Background(), server.URL, faviconConfig())
	require.NoError(t, err)
	assert.Nil(t, body)
	assert.Empty(t, hash)
}

func TestFetchFaviconAcceptsIcoImageContentType(t *testing.T) {
	icon := []byte{0, 0, 1, 0, 1, 0}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write(icon)
	}))
	t.Cleanup(server.Close)

	body, hash, err := FetchFavicon(context.Background(), server.URL, faviconConfig())
	require.NoError(t, err)
	assert.Equal(t, icon, body)
	assert.NotEmpty(t, hash)
}

func TestFetchFaviconAcceptsSVGImageContentType(t *testing.T) {
	svg := []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"></svg>`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write(svg)
	}))
	t.Cleanup(server.Close)

	body, hash, err := FetchFavicon(context.Background(), server.URL, faviconConfig())
	require.NoError(t, err)
	assert.Equal(t, svg, body)
	assert.NotEmpty(t, hash)
}

func faviconConfig() discover.DiscoverWitnessConfig {
	return discover.DiscoverWitnessConfig{
		MaxRedirects:               2,
		Timeout:                    5,
		IgnoreCrossDomainRedirects: true,
		UserAgent:                  common.UserAgentPresetCurl,
	}
}
