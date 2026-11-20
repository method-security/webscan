package nuclei

import (
	"testing"

	"github.com/Method-Security/webscan/utils"
)

func TestBuilderScopeDecidesOffTargetMatches(t *testing.T) {
	targets := []string{"https://www.example.com/"}
	partner := &utils.Scope{Domains: []string{"partner.example"}, Cidrs: []string{}}
	cases := []struct {
		name    string
		builder *Builder
		matched string
		want    bool
	}{
		{"any match is kept without a scope", NewBuilder(targets, nil), "https://cdn.other.test/x", true},
		{"hostless network match is kept without a scope", NewBuilder(targets, nil), "db.example.net:5432", true},
		{"target match is kept with a scope", NewBuilder(targets, partner), "https://www.example.com/admin", true},
		{"seeded match is kept", NewBuilder(targets, partner), "https://api.partner.example/x", true},
		{"off-target match is dropped with a scope", NewBuilder(targets, partner), "https://example.com/admin", false},
		{"hostless match is dropped with a scope", NewBuilder(targets, partner), "db.example.net:5432", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.builder.isTargetInScope(c.matched); got != c.want {
				t.Fatalf("isTargetInScope(%q) = %v, want %v", c.matched, got, c.want)
			}
		})
	}
}
