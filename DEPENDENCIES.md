# Dependency security posture

Last reviewed: **2026-08-31**. Tooling: `govulncheck -mode=source ./...` and
`osv-scanner --lockfile=go.mod`.

Reachable-vulnerability count at last review: **1**, which has **no published
fix**. Everything with a fix available has been taken.

Reproduce with:

```sh
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck -mode=source ./...
```

`govulncheck` is the number that matters — it does call-graph reachability, so
it distinguishes "this module is in our graph" from "our code can actually
reach the vulnerable function". `osv-scanner` reports the former and is much
noisier. Where they disagree, prefer `govulncheck` and record the reasoning.

## Accepted risk

### GO-2026-5932 — `golang.org/x/crypto`

**Not an exploitable defect.** Read the advisory text: *"the golang.org/x/crypto/openpgp
package is unmaintained, unsafe by design, and has known security issues."* It is a
blanket **deprecation notice** for the package, which is why `Fixed in: N/A` — there is no
patch, the remedy is "stop using it". Do not triage this as if it were a CVE.

It reaches us through `google/go-github/v30` (a 2020-era release), which
`projectdiscovery/utils` uses for verifying self-update release signatures. It cannot be
removed from here: go-github v30 is pinned by `projectdiscovery/utils` and we are already
on that module's current release. Excising it means a `replace` directive that breaks
`utils`.

Re-check on each sweep in case a fix path appears upstream.

## Before you bump anything

This repo's hand-written tests (91 functions) cover pure string and URL logic;
the ~1100 tests under `generated/` are Fern-generated JSON round-trips. Nothing
tests a dependency surface, so a green `go build` is **not** evidence that a
bump is safe.

Run the smoke test, which drives the real CLI against a local HTTP server:

```sh
scripts/smoke/smoke.sh
```

Run it once **before** your change and once after, and compare. A suite that
only passes after the change tells you nothing; the before-run is the control.

**This script is not wired into CI**, by deliberate choice — running it is a
manual step during dependency work, not something that gates merges.

## Local build note

`generated/` is gitignored and produced by Fern; CI downloads it as an
artifact. A stale or missing local copy makes the repo fail to compile in ways
that look like dependency breakage but are not. Regenerate with:

```sh
fern generate --group local --retry-rate-limited
go generate ./configs
```
