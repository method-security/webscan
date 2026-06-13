// Package application — SEC-702.A MikroTik RouterOS 7.17+
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

// mikrotikAssetHashTable is the in-memory mirror of
// utils/nuclei/templates/discover/application/_data/mikrotik-asset-hashes.yaml.
// Cluster C (MikroTik) seeds it from RouterOS 7.17+ captures; later
// data PRs extend coverage. Empty at SEC-702.A seed-time.
//
// Key: the hash substring as it appears in the asset path, without
// the file extension. Templates emit method-mikrotik-asset-hash
// exactly as captured by their extractor (which should anchor on
// the full /assets/<file>-<hash>.<ext> path to avoid collisions
// with hashes from other vendors).
//
// Value: the dotted RouterOS version string (e.g. "7.17", "7.18",
// "7.19.2"). Matches the canonical version form MikroTik publishes
// on their changelog.
var mikrotikAssetHashTable = map[string]string{
	// populated by per-cluster PRs; intentionally empty at SEC-702.A
}

// lookupMikrotikAssetHash returns the RouterOS version that ships
// the given asset hash, or ("", false) if the hash is not in the
// table. Hash is matched exactly — templates that emit a different
// representation (uppercase, prefixed with `style-`) won't hit;
// keep the convention "lowercase hex, no prefix".
func lookupMikrotikAssetHash(hash string) (string, bool) {
	if hash == "" {
		return "", false
	}
	version, ok := mikrotikAssetHashTable[hash]
	if !ok || version == "" {
		return "", false
	}
	return version, true
}
