// Package discoverrequest end-to-end tests for the freeform HTTP request
// primitive. The tests in this file exist to pin the AITF-138 Part 3 bug
// class: the user's invocation
//
//	webscan discover request --target ... --verify-tls TRUE --user-agent CHROME \
//	  --header "Accept: application/json" \
//	  --header "Accept: text/html;q=0.9" \
//	  --header "Accept: */*;q=0.8"
//
// was supposed to send three Accept values comma-joined per RFC 7230, but
// silently dropped headers that did not contain a colon and overwrote
// repeated header names. We now (a) error on malformed headers and (b)
// comma-join repeated names — these tests run the full PerformRequest
// pipeline against a local httptest.Server and assert the server saw the
// expected request shape.
package discoverrequest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	discover "github.com/Method-Security/webscan/generated/go/discover"
	requesthelpers "github.com/Method-Security/webscan/utils/request/helpers"
)

// TestPerformRequest_MultiValueAcceptHeaderArrivesCommaJoined exercises the
// canonical multi-header invocation from the AITF-138 repro. Three
// --header "Accept: ..." values must comma-join on the wire and the server
// must see exactly one Accept header containing all three media types.
func TestPerformRequest_MultiValueAcceptHeaderArrivesCommaJoined(t *testing.T) {
	var receivedAccept string
	var receivedAcceptCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// net/http canonicalizes header names; "Accept" is the canonical form.
		// r.Header["Accept"] returns the list of values for the canonical name.
		values := r.Header.Values("Accept")
		receivedAcceptCount = len(values)
		receivedAccept = strings.Join(values, " || ")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	// Mirror what cmd/discover.go does for the request command: parse the
	// repeated --header flag through ParseHeaderPairs.
	headers, err := requesthelpers.ParseHeaderPairs([]string{
		"Accept: application/json",
		"Accept: text/html;q=0.9",
		"Accept: */*;q=0.8",
	})
	if err != nil {
		t.Fatalf("ParseHeaderPairs errored: %v", err)
	}

	report := PerformRequest(context.Background(), discover.DiscoverRequestConfig{
		Target:                     server.URL,
		HttpMethod:                 common.HttpMethodGet,
		Headers:                    headers,
		MaxRedirects:               10,
		FollowRedirects:            true,
		VerifyTls:                  false, // server is plain http
		Timeout:                    30,
		UserAgent:                  common.UserAgentPresetChrome,
		IgnoreCrossDomainRedirects: false,
	})

	if len(report.Errors) != 0 {
		t.Fatalf("PerformRequest produced unexpected errors: %v", report.Errors)
	}
	if report.Result == nil || report.Result.Request == nil || report.Result.Request.Response == nil {
		t.Fatal("PerformRequest produced no response")
	}
	if got := report.Result.Request.Response.StatusCode; got == nil || *got != http.StatusOK {
		var s int
		if got != nil {
			s = *got
		}
		t.Fatalf("status: got %d, want 200", s)
	}

	// Wire-level assertion: the server canonicalizes to "Accept" and sees a
	// SINGLE value containing all three media types comma-separated, NOT
	// three separate header values nor a clobbered single value.
	if receivedAcceptCount != 1 {
		t.Fatalf("server saw %d Accept values, want 1 (comma-joined): %q", receivedAcceptCount, receivedAccept)
	}
	want := "application/json, text/html;q=0.9, */*;q=0.8"
	if receivedAccept != want {
		t.Fatalf("comma-joined Accept mismatch:\n got %q\nwant %q", receivedAccept, want)
	}
}

// TestPerformRequest_RepeatedHeaderCaseInsensitive — `Accept` and `accept`
// must fold into one header on the wire. Without case-insensitive merge in
// ParseHeaderPairs the downstream HTTP transport canonicalizes both into
// `Accept` and sends two values, which silently duplicates the header.
func TestPerformRequest_RepeatedHeaderCaseInsensitive(t *testing.T) {
	var values []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values = append([]string(nil), r.Header.Values("Accept")...)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	headers, err := requesthelpers.ParseHeaderPairs([]string{
		"Accept: application/json",
		"accept: text/html",
		"ACCEPT: */*",
	})
	if err != nil {
		t.Fatalf("ParseHeaderPairs errored: %v", err)
	}
	report := PerformRequest(context.Background(), discover.DiscoverRequestConfig{
		Target:                     server.URL,
		HttpMethod:                 common.HttpMethodGet,
		Headers:                    headers,
		MaxRedirects:               10,
		FollowRedirects:            true,
		VerifyTls:                  false,
		Timeout:                    30,
		UserAgent:                  common.UserAgentPresetChrome,
		IgnoreCrossDomainRedirects: false,
	})
	if len(report.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", report.Errors)
	}

	if len(values) != 1 {
		t.Fatalf("server saw %d Accept values, want 1 (case-insensitive merge): %v", len(values), values)
	}
	want := "application/json, text/html, */*"
	if values[0] != want {
		t.Fatalf("case-insensitive merge mismatch on wire:\n got %q\nwant %q", values[0], want)
	}
}

// TestPerformRequest_DistinctHeadersAllArrive — pre-existing single-value
// behavior continues to work; this is a non-regression for the parser
// changes.
func TestPerformRequest_DistinctHeadersAllArrive(t *testing.T) {
	var receivedAuth, receivedTrace string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedTrace = r.Header.Get("X-Trace-Id")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	headers, err := requesthelpers.ParseHeaderPairs([]string{
		"Authorization: Bearer xyz",
		"X-Trace-Id: abc-123",
	})
	if err != nil {
		t.Fatalf("ParseHeaderPairs errored: %v", err)
	}
	report := PerformRequest(context.Background(), discover.DiscoverRequestConfig{
		Target:                     server.URL,
		HttpMethod:                 common.HttpMethodGet,
		Headers:                    headers,
		MaxRedirects:               10,
		FollowRedirects:            true,
		VerifyTls:                  false,
		Timeout:                    30,
		UserAgent:                  common.UserAgentPresetChrome,
		IgnoreCrossDomainRedirects: false,
	})
	if len(report.Errors) != 0 {
		t.Fatalf("unexpected errors: %v", report.Errors)
	}
	if receivedAuth != "Bearer xyz" {
		t.Fatalf("Authorization: got %q, want %q", receivedAuth, "Bearer xyz")
	}
	if receivedTrace != "abc-123" {
		t.Fatalf("X-Trace-Id: got %q, want %q", receivedTrace, "abc-123")
	}
}

// TestParseHeaderPairs_MalformedSurfacesAtParseTime — the parser is the
// first line of defense. A no-colon header value never makes it to
// PerformRequest because the cobra Run func now surfaces the error and
// returns. We test the same contract at the parse layer.
func TestParseHeaderPairs_MalformedSurfacesAtParseTime(t *testing.T) {
	_, err := requesthelpers.ParseHeaderPairs([]string{
		"Accept: application/json",
		"text/html;q=0.9", // user almost certainly meant to extend Accept
		"*/*;q=0.8",
	})
	if err == nil {
		t.Fatal("expected error on malformed header (no colon), got nil")
	}
	if !strings.Contains(err.Error(), "text/html;q=0.9") {
		t.Fatalf("error did not name the offending value: %v", err)
	}
}

// TestPerformRequest_VerifyTlsTrueCaseInsensitive — strconv.ParseBool (which
// backs cobra's GetBool) accepts the uppercase form "TRUE" the user typed in
// the AITF-138 repro. Since cobra parses the flag before PerformRequest sees
// it, we can't reach PerformRequest with a malformed VerifyTls value — but
// we DO want a regression test confirming the bool actually propagates
// through to the request config and survives the round trip.
func TestPerformRequest_VerifyTlsTrueCaseInsensitive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	for _, verify := range []bool{true, false} {
		report := PerformRequest(context.Background(), discover.DiscoverRequestConfig{
			Target:                     server.URL,
			HttpMethod:                 common.HttpMethodGet,
			MaxRedirects:               10,
			FollowRedirects:            true,
			VerifyTls:                  verify, // server is plain http so either value succeeds
			Timeout:                    30,
			UserAgent:                  common.UserAgentPresetChrome,
			IgnoreCrossDomainRedirects: false,
		})
		if len(report.Errors) != 0 {
			t.Fatalf("verify=%v: unexpected errors: %v", verify, report.Errors)
		}
		if report.Config == nil || report.Config.VerifyTls != verify {
			t.Fatalf("VerifyTls did not round-trip: got %v, want %v", report.Config != nil && report.Config.VerifyTls, verify)
		}
	}
}
