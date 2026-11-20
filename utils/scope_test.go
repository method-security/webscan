package utils_test

import (
	"testing"

	"github.com/Method-Security/webscan/utils"
)

func TestNewScopeNormalizes(t *testing.T) {
	scope, err := utils.NewScope(
		[]string{" Example.COM. ", "*.corp.example.net", "https://api.example.org/path", "203.0.113.7"},
		[]string{"198.51.100.17/24", "2001:db8::1"},
	)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	wantDomains := []string{"example.com", "corp.example.net", "api.example.org"}
	wantCidrs := []string{"203.0.113.7/32", "198.51.100.0/24", "2001:db8::1/128"}
	if !equal(scope.Domains, wantDomains) {
		t.Errorf("domains = %v, want %v", scope.Domains, wantDomains)
	}
	if !equal(scope.Cidrs, wantCidrs) {
		t.Errorf("cidrs = %v, want %v", scope.Cidrs, wantCidrs)
	}
}

func TestNewScopeEmptyIsNil(t *testing.T) {
	scope, err := utils.NewScope(nil, []string{})
	if err != nil || scope != nil {
		t.Fatalf("NewScope(empty) = %v, %v; want nil, nil", scope, err)
	}
}

func TestNewScopeRejectsInvalid(t *testing.T) {
	if _, err := utils.NewScope(nil, []string{"10.0.0.0/33"}); err == nil {
		t.Error("expected an error for an invalid CIDR")
	}
	if _, err := utils.NewScope([]string{"  "}, nil); err == nil {
		t.Error("expected an error for an empty domain")
	}
}

func TestScopeOfIsNilWithoutDomainsOrCidrs(t *testing.T) {
	if utils.ScopeOf(nil, []string{}) != nil {
		t.Fatal("expected no scope from empty fields")
	}
	scope := utils.ScopeOf(nil, []string{"198.51.100.0/24"})
	if scope == nil || !utils.HostInSeedScope(scope, "http://198.51.100.20/") {
		t.Fatalf("expected a CIDR-only scope, got %+v", scope)
	}
}

func TestHostInSeedScope(t *testing.T) {
	scope := &utils.Scope{
		Domains: []string{"example.com", "partner.example"},
		Cidrs:   []string{"198.51.100.0/24", "2001:db8::/32"},
	}
	cases := []struct {
		url  string
		want bool
	}{
		{"https://example.com/", true},
		{"https://www.example.com/login", true},
		{"https://api.partner.example:8443/x", true},
		{"https://EXAMPLE.COM./", true},
		{"https://notexample.com/", false},
		{"https://example.com.evil.test/", false},
		{"https://login.identity.test/", false},
		{"http://198.51.100.20/", true},
		{"http://198.51.101.20/", false},
		{"http://[2001:db8::5]/", true},
		{"http://[::ffff:198.51.100.9]/", true},
		{"not a url", false},
	}
	for _, c := range cases {
		if got := utils.HostInSeedScope(scope, c.url); got != c.want {
			t.Errorf("HostInSeedScope(%q) = %v, want %v", c.url, got, c.want)
		}
	}
	if utils.HostInSeedScope(nil, "https://example.com/") {
		t.Error("nil scope must not match")
	}
}

func TestHostAllowedWithoutScopeAdmitsEveryHost(t *testing.T) {
	for _, candidate := range []string{"https://login.identity.test/", "https://example.com/", "http://10.9.8.7/", "http://[2001:db8::9]/", "db.example.net:5432", "/relative", ""} {
		if !utils.HostAllowed(nil, "https://www.example.com/", candidate) {
			t.Errorf("expected %q to be allowed without a scope", candidate)
		}
	}
}

func TestAnchorScopeKeepsOnlyTheAnchor(t *testing.T) {
	anchor := "https://www.example.com/start"
	scope := utils.ScopeOf(utils.AnchorScope(anchor))
	if !utils.HostAllowed(scope, anchor, "https://app.www.example.com/") {
		t.Error("child of the anchor must be allowed")
	}
	if utils.HostAllowed(scope, anchor, "https://example.com/") {
		t.Error("parent of the anchor must be blocked")
	}
	if utils.HostAllowed(scope, anchor, "https://login.identity.test/") {
		t.Error("an unrelated host must be blocked")
	}
}

func TestHostAllowedWithScopeWidensAnchor(t *testing.T) {
	anchor := "https://www.example.com/"
	scope := &utils.Scope{Domains: []string{"example.com", "partner.example"}, Cidrs: []string{}}
	if !utils.HostAllowed(scope, anchor, "https://example.com/") {
		t.Error("seed parent must be allowed")
	}
	if !utils.HostAllowed(scope, anchor, "https://api.partner.example/services") {
		t.Error("second seed domain must be allowed")
	}
	if utils.HostAllowed(scope, anchor, "https://login.identity.test/") {
		t.Error("unseeded host must be blocked")
	}
	if !utils.HostAllowed(scope, "https://portal.unseeded.test/", "https://app.portal.unseeded.test/") {
		t.Error("children of the anchor stay allowed even when the anchor is not a seed")
	}
}

func TestNewScopeRejectsWildcards(t *testing.T) {
	if _, err := utils.NewScope([]string{"*"}, nil); err == nil {
		t.Error("expected a bare wildcard to be rejected")
	}
	if _, err := utils.NewScope([]string{"*.corp.example.net"}, nil); err != nil {
		t.Errorf("expected a leading wildcard label to be accepted, got %v", err)
	}
}

func TestScopeWithAnchorAddsTheAnchorHost(t *testing.T) {
	seeds := &utils.Scope{Domains: []string{"partner.example"}, Cidrs: []string{}}
	widened := utils.ScopeWithAnchor(seeds, "https://www.example.com/start")
	if !utils.HostInSeedScope(widened, "https://app.www.example.com/") || !utils.HostInSeedScope(widened, "https://api.partner.example/") {
		t.Fatalf("expected the anchor and the seeds, got %+v", widened)
	}
	if utils.HostInSeedScope(widened, "https://example.com/") {
		t.Fatal("expected the anchor's parent to stay out")
	}
	if len(seeds.Domains) != 1 {
		t.Fatal("expected the original scope to be left untouched")
	}
	if !utils.HostInSeedScope(utils.ScopeWithAnchor(nil, "http://198.51.100.7:8080/"), "http://198.51.100.7/") {
		t.Fatal("expected an IP anchor to admit its own address")
	}
}

func equal(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
