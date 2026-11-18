package nuclei

import (
	"testing"

	common "github.com/Method-Security/webscan/generated/go/common"
	"github.com/Method-Security/webscan/utils"
)

func TestBuilderScopeDecidesOffTargetMatches(t *testing.T) {
	targets := []string{"https://www.example.com/"}
	cases := []struct {
		name    string
		builder *Builder
		matched string
		want    bool
	}{
		{"target match is kept without seeds", NewBuilder(targets, nil), "https://www.example.com/admin", true},
		{"off-target match is dropped without seeds", NewBuilder(targets, nil), "https://example.com/admin", false},
		{"seeded match is kept", NewBuilder(targets, &common.Scope{Domains: []string{"example.com"}, Cidrs: []string{}}), "https://example.com/admin", true},
		{"unrestricted scope keeps any match", NewBuilder(targets, utils.UnrestrictedScope()), "https://cdn.other.test/x", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.builder.isTargetInScope(c.matched); got != c.want {
				t.Fatalf("isTargetInScope(%q) = %v, want %v", c.matched, got, c.want)
			}
		})
	}
}
