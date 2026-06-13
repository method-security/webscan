// Package application — MikroTik RouterOS 7.17+
// asset-hash → version lookup helper.
//
// Background (TC-001): RouterOS 7.17+ post-redesign WebFig dropped
// the user-visible RouterOS version string from the login page. The
// 6.x / 7.0–7.16 catalog regex `<h1>RouterOS v(\d+)\.(\d+)</h1>` no
// longer matches. The only HTTP-determinable version source on 7.17+
// is the webpack-style content hash baked into static asset paths
// (/assets/style-<hash>.css, /assets/script-<hash>.js). The hash is
// deterministic per RouterOS build — the same bundle ships
// everywhere — so a hash → version table built from official MikroTik
// releases pins the version exactly.
//
// Trade-off: this is a per-release table, not a parsing trick. The
// table requires maintenance (Cluster C seeds it; Cluster P / a
// future scheduled refresh keeps it current). The alternative
// (`Last-Modified` on the asset as a build-day proxy) is the
// universal fallback emitted directly by the template — this helper
// is the high-fidelity path when the hash is known.

package application

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"

	yaml "gopkg.in/yaml.v3"
)

// mikrotikAssetHashYAML is the embedded YAML source of truth for the
// hash → version table. Cluster C (MikroTik) seeds it from RouterOS
// 7.17+ captures; later data PRs extend coverage. Empty at seed-time.
//
//go:embed _data/mikrotik-asset-hashes.yaml
var mikrotikAssetHashYAML []byte

type mikrotikAssetHashFile struct {
	Hashes map[string]string `yaml:"hashes"`
}

// mikrotikAssetHashTable is the in-memory mirror of the embedded
// YAML. Key: the hash substring as it appears in the asset path,
// without the file extension. Value: the dotted RouterOS version
// string (e.g. "7.17", "7.18", "7.19.2"). Matches the canonical
// version form MikroTik publishes on their changelog.
var (
	mikrotikAssetHashTable   map[string]string
	mikrotikAssetHashOnce    sync.Once
	mikrotikAssetHashLoadErr error
)

func loadMikrotikAssetHash() {
	var parsed mikrotikAssetHashFile
	if err := yaml.Unmarshal(mikrotikAssetHashYAML, &parsed); err != nil {
		mikrotikAssetHashLoadErr = fmt.Errorf("mikrotik-asset-hashes.yaml unmarshal: %w", err)
		return
	}
	table := make(map[string]string, len(parsed.Hashes))
	for hash, version := range parsed.Hashes {
		hash = strings.TrimSpace(hash)
		version = strings.TrimSpace(version)
		if hash == "" || version == "" {
			continue
		}
		table[hash] = version
	}
	mikrotikAssetHashTable = table
}

// lookupMikrotikAssetHash returns the RouterOS version that ships
// the given asset hash, or ("", false) if the hash is not in the
// table. Hash is matched exactly — templates that emit a different
// representation (uppercase, prefixed with `style-`) won't hit;
// keep the convention "lowercase hex, no prefix".
func lookupMikrotikAssetHash(hash string) (string, bool) {
	mikrotikAssetHashOnce.Do(loadMikrotikAssetHash)
	if mikrotikAssetHashLoadErr != nil {
		return "", false
	}
	if hash == "" {
		return "", false
	}
	version, ok := mikrotikAssetHashTable[hash]
	if !ok || version == "" {
		return "", false
	}
	return version, true
}
