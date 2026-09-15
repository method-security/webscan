# Security Policy

## Supported Versions

This is an open source project that is provided as-is without warrenty or liability.
As such no supportability commitment. The maintainers will do the best they can to address any report promptly and responsibly.

## Reporting a Vulnerability

Please use the "Private vulnerability reporting" feature in the GitHub repository (under the "Security" tab).

## Known Accepted Risks

Findings that `govulncheck` reports against this module but which we have reviewed
and accepted, with the reasoning. Re-check these whenever nuclei is upgraded.

### GO-2026-5932 — `golang.org/x/crypto/openpgp` is unmaintained

**Status:** accepted, no fix available.

The advisory is a deprecation notice rather than a specific defect: the `openpgp`
package is unmaintained and the Go team advises against using it. It carries
`Fixed in: N/A`, so no release of `golang.org/x/crypto` clears it.

**Why we cannot upgrade out of it.** The package reaches us through:

```
webscan -> projectdiscovery/nuclei/v3 -> projectdiscovery/utils/update
        -> google/go-github/v30 -> golang.org/x/crypto/openpgp
```

- `go-github/v30.1.0` is the newest release on the `v30` line. Later go-github
  releases use a different module path (`/v31` and beyond), so Go's minimal
  version selection cannot substitute them.
- The newest `projectdiscovery/utils` still imports `go-github/v30`, so bumping
  that dependency does not break the chain either.

Removing it therefore requires an upstream change in the projectdiscovery
ecosystem, not a version bump on our side.

**Exposure.** Low. Every call path `govulncheck` reports terminates in package
`init`, meaning the package is linked into the binary but none of its functions
are invoked. go-github references `openpgp` for commit signature verification, a
feature webscan never calls.

**Re-evaluate when:** nuclei is upgraded, or `projectdiscovery/utils` drops its
`go-github/v30` dependency. If either happens, re-run `govulncheck ./...` and
remove this entry if the finding is gone.
