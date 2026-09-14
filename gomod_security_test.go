package main

import (
	"os"
	"regexp"
	"testing"

	"golang.org/x/mod/semver"
)

// securityFloors pins the lowest module versions that carry fixes for advisories
// govulncheck previously reported against this module. Bumping a module above its
// floor is always fine; dropping below one silently reintroduces a known
// vulnerability, so these tests fail instead.
var securityFloors = map[string]struct {
	minVersion string
	advisories string
}{
	// GO-2026-6355, GO-2026-6354 (ssh DoS), GO-2026-6303 (ssh source-address bypass).
	"golang.org/x/crypto": {"v0.56.0", "GO-2026-6355, GO-2026-6354, GO-2026-6303"},
	// GO-2026-6180, GO-2026-6179 (sumdb/tlog verification bypass).
	"golang.org/x/mod": {"v0.40.0", "GO-2026-6180, GO-2026-6179"},
	// Pulled in by x/crypto v0.56.0; keeps the idna and http2 fixes in place.
	"golang.org/x/net": {"v0.58.0", "transitive requirement of x/crypto v0.56.0"},
}

// goDirectiveFloor is the lowest toolchain that carries the patched standard
// library (net/url, html/template, crypto/tls, net/http, encoding/xml,
// encoding/asn1) for GO-2026-6218, -6091, -6090, -6089, -6088, -5972 and -5026.
const goDirectiveFloor = "v1.26.8"

var (
	requireRe     = regexp.MustCompile(`(?m)^\s*(\S+)\s+(v\S+?)(?:\s+//.*)?$`)
	goDirectiveRe = regexp.MustCompile(`(?m)^go\s+(\S+)$`)
)

// findFloorViolations reports modules in gomod that sit below their security
// floor, plus floors whose module is no longer required at all.
func findFloorViolations(gomod string) (below []string, missing []string) {
	seen := map[string]bool{}
	for _, m := range requireRe.FindAllStringSubmatch(gomod, -1) {
		path, version := m[1], m[2]
		floor, ok := securityFloors[path]
		if !ok {
			continue
		}
		seen[path] = true
		if semver.Compare(version, floor.minVersion) < 0 {
			below = append(below, path+" is "+version+", below floor "+
				floor.minVersion+"; reintroduces "+floor.advisories)
		}
	}
	for path := range securityFloors {
		if !seen[path] {
			missing = append(missing, path)
		}
	}
	return below, missing
}

// goDirectiveBelowFloor reports whether gomod's go directive is older than
// goDirectiveFloor. The second result is the directive that was found.
func goDirectiveBelowFloor(gomod string) (bool, string) {
	m := goDirectiveRe.FindStringSubmatch(gomod)
	if m == nil {
		return false, ""
	}
	return semver.Compare("v"+m[1], goDirectiveFloor) < 0, m[1]
}

func readGoMod(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	return string(data)
}

func TestGoModSecurityFloors(t *testing.T) {
	t.Parallel()

	below, missing := findFloorViolations(readGoMod(t))
	for _, v := range below {
		t.Error(v)
	}
	for _, path := range missing {
		t.Errorf("%s is no longer required by go.mod; drop its entry from securityFloors "+
			"if that is intentional", path)
	}
}

func TestGoDirectiveSecurityFloor(t *testing.T) {
	t.Parallel()

	if stale, got := goDirectiveBelowFloor(readGoMod(t)); stale {
		t.Errorf("go directive is %s, below the floor %s; the standard library below that "+
			"patch level carries GO-2026-6218, -6091, -6090, -6089, -6088, -5972 and -5026",
			got, goDirectiveFloor)
	}
}

// The checks above only protect us if they actually fire on a downgrade, so
// exercise them against synthetic go.mod content here.
func TestFindFloorViolationsDetectsDowngrade(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		gomod       string
		wantBelow   int
		wantMissing int
	}{
		{
			name: "all floors satisfied",
			gomod: "module m\n\ngo 1.26.8\n\nrequire (\n" +
				"\tgolang.org/x/crypto v0.56.0 // indirect\n" +
				"\tgolang.org/x/mod v0.40.0 // indirect\n" +
				"\tgolang.org/x/net v0.58.0 // indirect\n)\n",
		},
		{
			name: "newer than floors is fine",
			gomod: "module m\n\ngo 1.27.0\n\nrequire (\n" +
				"\tgolang.org/x/crypto v0.99.0 // indirect\n" +
				"\tgolang.org/x/mod v0.99.0 // indirect\n" +
				"\tgolang.org/x/net v0.99.0 // indirect\n)\n",
		},
		{
			name: "one module downgraded below its floor",
			gomod: "module m\n\ngo 1.26.8\n\nrequire (\n" +
				"\tgolang.org/x/crypto v0.54.0 // indirect\n" +
				"\tgolang.org/x/mod v0.40.0 // indirect\n" +
				"\tgolang.org/x/net v0.58.0 // indirect\n)\n",
			wantBelow: 1,
		},
		{
			name: "every module downgraded below its floor",
			gomod: "module m\n\ngo 1.26.8\n\nrequire (\n" +
				"\tgolang.org/x/crypto v0.54.0 // indirect\n" +
				"\tgolang.org/x/mod v0.39.0 // indirect\n" +
				"\tgolang.org/x/net v0.57.0 // indirect\n)\n",
			wantBelow: 3,
		},
		{
			name:        "module dropped entirely",
			gomod:       "module m\n\ngo 1.26.8\n\nrequire (\n\tgolang.org/x/crypto v0.56.0 // indirect\n)\n",
			wantMissing: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			below, missing := findFloorViolations(tt.gomod)
			if len(below) != tt.wantBelow {
				t.Errorf("below-floor count = %d, want %d (%v)", len(below), tt.wantBelow, below)
			}
			if len(missing) != tt.wantMissing {
				t.Errorf("missing count = %d, want %d (%v)", len(missing), tt.wantMissing, missing)
			}
		})
	}
}

func TestGoDirectiveBelowFloorDetectsDowngrade(t *testing.T) {
	t.Parallel()

	tests := []struct {
		directive string
		wantStale bool
	}{
		{"1.26.8", false},
		{"1.26.9", false},
		{"1.27.0", false},
		{"1.26.5", true},
		{"1.25.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.directive, func(t *testing.T) {
			t.Parallel()
			stale, got := goDirectiveBelowFloor("module m\n\ngo " + tt.directive + "\n")
			if got != tt.directive {
				t.Fatalf("parsed directive = %q, want %q", got, tt.directive)
			}
			if stale != tt.wantStale {
				t.Errorf("stale = %v, want %v", stale, tt.wantStale)
			}
		})
	}
}
