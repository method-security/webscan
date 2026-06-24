// Package helpers - unit tests for the --header / --cookie / --form-data
// pair-parsing CLI helpers. The big behavior contracts pinned here are:
//
//  1. Malformed values (missing separator, empty name/key) return an error
//     rather than getting silently dropped. The latter is the bug from
//     AITF-138 Part 3 — operators reported headers vanishing without any
//     indication their input was malformed.
//  2. Repeated --header names (case-insensitive) are merged into a single
//     comma-joined value per RFC 7230 §3.2.2 rather than overwriting. The
//     CLI uses StringArray flags so repeated --header "Accept: ..." must
//     compose, not clobber.
//  3. ParseCookiePairs / ParseFormDataPairs do NOT comma-join; cookies and
//     form fields with the same name are last-write-wins (cookies follow
//     RFC 6265 set-cookie semantics; form-data has no multi-value contract).
package helpers

import (
	"strings"
	"testing"
)

func TestParseHeaderPairs_Empty(t *testing.T) {
	got, err := ParseHeaderPairs(nil)
	if err != nil {
		t.Fatalf("nil pairs returned error: %v", err)
	}
	if got != nil {
		t.Fatalf("nil pairs expected nil map, got %v", got)
	}

	got, err = ParseHeaderPairs([]string{})
	if err != nil {
		t.Fatalf("empty pairs returned error: %v", err)
	}
	if got != nil {
		t.Fatalf("empty pairs expected nil map, got %v", got)
	}
}

func TestParseHeaderPairs_SingleValue(t *testing.T) {
	got, err := ParseHeaderPairs([]string{"Accept: application/json"})
	if err != nil {
		t.Fatalf("single header errored: %v", err)
	}
	if got["Accept"] != "application/json" {
		t.Fatalf("single value: got %q, want %q", got["Accept"], "application/json")
	}
}

func TestParseHeaderPairs_TrimsWhitespace(t *testing.T) {
	got, err := ParseHeaderPairs([]string{"  Accept :   application/json  "})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if got["Accept"] != "application/json" {
		t.Fatalf("whitespace not trimmed: name keys=%v, Accept=%q", keysOf(got), got["Accept"])
	}
}

// TestParseHeaderPairs_RepeatedNameCommaJoins is THE bug from the user's
// AITF-138 repro. Three --header "Accept: ..." flags must produce a single
// Accept header whose value is the three values comma-joined per RFC 7230.
func TestParseHeaderPairs_RepeatedNameCommaJoins(t *testing.T) {
	got, err := ParseHeaderPairs([]string{
		"Accept: application/json",
		"Accept: text/html;q=0.9",
		"Accept: */*;q=0.8",
	})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry post-merge, got %d: %v", len(got), got)
	}
	want := "application/json, text/html;q=0.9, */*;q=0.8"
	if got["Accept"] != want {
		t.Fatalf("comma-join mismatch:\n got %q\nwant %q", got["Accept"], want)
	}
}

// TestParseHeaderPairs_RepeatedNameCaseInsensitive pins the case-insensitive
// merge. RFC 7230 §3.2 says header names are case-insensitive — `accept`
// and `Accept` MUST be folded into one entry, preserving the first-seen
// casing. Without this fold a malicious or sloppy caller could split values
// across two map keys and the downstream HTTP transport would send two
// headers with the same canonical name.
func TestParseHeaderPairs_RepeatedNameCaseInsensitive(t *testing.T) {
	got, err := ParseHeaderPairs([]string{
		"X-Custom: a",
		"x-custom: b",
		"X-CUSTOM: c",
	})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry post case-insensitive merge, got %d: %v", len(got), got)
	}
	// First-seen casing preserved:
	if v, ok := got["X-Custom"]; !ok || v != "a, b, c" {
		t.Fatalf("case-insensitive merge mismatch: keys=%v, X-Custom=%q", keysOf(got), v)
	}
}

func TestParseHeaderPairs_DistinctNamesCoexist(t *testing.T) {
	got, err := ParseHeaderPairs([]string{
		"Accept: application/json",
		"Authorization: Bearer xyz",
		"X-Trace-Id: abc",
	})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 distinct entries, got %d: %v", len(got), got)
	}
	if got["Accept"] != "application/json" ||
		got["Authorization"] != "Bearer xyz" ||
		got["X-Trace-Id"] != "abc" {
		t.Fatalf("distinct names mismatch: %v", got)
	}
}

// TestParseHeaderPairs_NoColonErrors is the second half of the AITF-138 bug:
// `--header "text/html;q=0.9"` (no colon) previously silently dropped. The
// user expected three Accept values, two were eaten, no error was surfaced.
// Now we surface the error so the operator KNOWS their CLI invocation was
// malformed.
func TestParseHeaderPairs_NoColonErrors(t *testing.T) {
	_, err := ParseHeaderPairs([]string{
		"Accept: application/json",
		"text/html;q=0.9", // no colon — user almost certainly meant to extend Accept
	})
	if err == nil {
		t.Fatal("expected error on header missing colon, got nil")
	}
	if !strings.Contains(err.Error(), "text/html;q=0.9") {
		t.Fatalf("error did not include the offending value: %v", err)
	}
	if !strings.Contains(err.Error(), "Name: Value") {
		t.Fatalf("error did not include the canonical form hint: %v", err)
	}
}

func TestParseHeaderPairs_EmptyNameErrors(t *testing.T) {
	_, err := ParseHeaderPairs([]string{": value"})
	if err == nil {
		t.Fatal("expected error on header with empty name, got nil")
	}
	if !strings.Contains(err.Error(), "header name is empty") {
		t.Fatalf("error did not name the failure mode: %v", err)
	}
}

// TestParseHeaderPairs_EmptyValueOK — an Accept: that's explicitly empty
// should be allowed (some auth flows use empty values intentionally). We
// reject only the *name*-empty case.
func TestParseHeaderPairs_EmptyValueOK(t *testing.T) {
	got, err := ParseHeaderPairs([]string{"X-Empty:"})
	if err != nil {
		t.Fatalf("empty value errored: %v", err)
	}
	if v, ok := got["X-Empty"]; !ok || v != "" {
		t.Fatalf("empty value not preserved: keys=%v, X-Empty=%q ok=%v", keysOf(got), v, ok)
	}
}

// TestParseHeaderPairs_EmptyValueAfterNonEmptyDoesNotTrail — guard against a
// trailing ", " when a non-empty value is followed by an empty one for the
// same header. The merge must not append an empty value onto the existing
// content.
func TestParseHeaderPairs_EmptyValueAfterNonEmptyDoesNotTrail(t *testing.T) {
	got, err := ParseHeaderPairs([]string{
		"Accept: application/json",
		"Accept:", // intentionally empty
	})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if got["Accept"] != "application/json" {
		t.Fatalf("empty merge produced trailing comma: %q", got["Accept"])
	}
}

// TestParseHeaderPairs_ColonInValuePreserved — the value side of "Name: Value"
// can legitimately contain colons (e.g. Authorization: Basic user:pass-base64
// or a URL in a custom header). We split on the FIRST colon only.
func TestParseHeaderPairs_ColonInValuePreserved(t *testing.T) {
	got, err := ParseHeaderPairs([]string{"X-Forwarded-Host: example.com:8443"})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if got["X-Forwarded-Host"] != "example.com:8443" {
		t.Fatalf("colon in value lost: %q", got["X-Forwarded-Host"])
	}
}

func TestParseCookiePairs_Empty(t *testing.T) {
	got, err := ParseCookiePairs(nil)
	if err != nil || got != nil {
		t.Fatalf("nil pairs: got %v err %v", got, err)
	}
	got, err = ParseCookiePairs([]string{})
	if err != nil || got != nil {
		t.Fatalf("empty pairs: got %v err %v", got, err)
	}
}

func TestParseCookiePairs_Valid(t *testing.T) {
	got, err := ParseCookiePairs([]string{"session=abc123", "csrf=xyz"})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if got["session"] != "abc123" || got["csrf"] != "xyz" {
		t.Fatalf("cookies mismatch: %v", got)
	}
}

func TestParseCookiePairs_NoEqualsErrors(t *testing.T) {
	_, err := ParseCookiePairs([]string{"session=abc", "csrf-only"})
	if err == nil {
		t.Fatal("expected error on cookie missing equals, got nil")
	}
	if !strings.Contains(err.Error(), "csrf-only") {
		t.Fatalf("error did not include offending value: %v", err)
	}
}

func TestParseCookiePairs_EmptyNameErrors(t *testing.T) {
	_, err := ParseCookiePairs([]string{"=value"})
	if err == nil {
		t.Fatal("expected error on cookie with empty name, got nil")
	}
}

// TestParseCookiePairs_ValueWithEqualsPreserved — cookies whose value is a
// base64 string (often ends with `=` padding) must round-trip cleanly.
func TestParseCookiePairs_ValueWithEqualsPreserved(t *testing.T) {
	got, err := ParseCookiePairs([]string{"session=YWJj=="})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if got["session"] != "YWJj==" {
		t.Fatalf("base64 padding lost: %q", got["session"])
	}
}

func TestParseFormDataPairs_Empty(t *testing.T) {
	got, err := ParseFormDataPairs(nil)
	if err != nil || got != nil {
		t.Fatalf("nil pairs: got %v err %v", got, err)
	}
}

func TestParseFormDataPairs_Valid(t *testing.T) {
	got, err := ParseFormDataPairs([]string{"username=admin", "password=hunter2"})
	if err != nil {
		t.Fatalf("errored: %v", err)
	}
	if got["username"] != "admin" || got["password"] != "hunter2" {
		t.Fatalf("form fields mismatch: %v", got)
	}
}

func TestParseFormDataPairs_NoEqualsErrors(t *testing.T) {
	_, err := ParseFormDataPairs([]string{"valid=ok", "barekey"})
	if err == nil {
		t.Fatal("expected error on form-data missing equals, got nil")
	}
	if !strings.Contains(err.Error(), "barekey") {
		t.Fatalf("error did not include offending value: %v", err)
	}
}

func TestParseFormDataPairs_EmptyKeyErrors(t *testing.T) {
	_, err := ParseFormDataPairs([]string{"=value"})
	if err == nil {
		t.Fatal("expected error on form-data with empty key, got nil")
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
