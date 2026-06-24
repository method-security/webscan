#!/usr/bin/env python3
"""Warn about test artifacts entering the repo via changed code.

Currently checks for public (globally-routable) IPv4 addresses and CIDR blocks
in *added* lines only. Private, loopback, link-local and documentation ranges
(RFC 1918 / RFC 5737 / etc.) are intentionally allowed. This is a NON-BLOCKING
warning: it always exits 0 so it never stops a commit or fails CI.

The name is deliberately generic so additional artifact checks (FQDNs, scan
output signatures, ...) can be added here over time.

Modes:
  --staged          scan staged changes (default; used by the pre-commit hook)
  --base <ref>      scan changes between <ref> and HEAD (used in CI)
  --github          emit GitHub Actions ::warning annotations
                    (auto-enabled when GITHUB_ACTIONS=true)
"""
import argparse
import ipaddress
import os
import re
import subprocess
import sys

# IPv4 or CIDR, not embedded in a longer dotted/numeric run (avoids 5+ octets).
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d.])")

# vendored third-party code is not ours and is full of incidental IPs.
EXCLUDE_PREFIXES = ("vendor/",)


def is_public(token: str) -> bool:
    """True if the token is a globally-routable IPv4 address or network."""
    try:
        if "/" in token:
            return ipaddress.ip_network(token, strict=False).is_global
        return ipaddress.ip_address(token).is_global
    except ValueError:
        return False


def looks_like_version(line: str, start: int, end: int) -> bool:
    """Heuristic: suppress version strings that parse as valid public IPs.

    - `name-1.2.3.4` / `v1.2.3.4`  -> preceded by a letter or '-'
    - CPE component `:2.8.0.4:`     -> wrapped in colons
    URL/host forms (`//1.2.3.4`, `1.2.3.4:8080`) are intentionally NOT matched.
    """
    before = line[start - 1] if start > 0 else ""
    after = line[end] if end < len(line) else ""
    if before.isalpha() or before == "-":
        return True
    if before == ":" and after == ":":
        return True
    return False


def iter_added_lines(diff: str):
    """Yield (path, lineno, text) for added lines in a unified diff (-U0)."""
    path = None
    new_line = 0
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:]
            if target.startswith("b/"):
                target = target[2:]
            path = None if target == "/dev/null" else target
        elif raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            new_line = int(m.group(1)) if m else 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            if path is not None:
                yield path, new_line, raw[1:]
            new_line += 1
    # context/removed lines are absent with -U0, so no other bookkeeping needed


def excluded(path: str) -> bool:
    return any(path.startswith(p) for p in EXCLUDE_PREFIXES)


def get_diff(args) -> str:
    cmd = ["git", "diff", "--unified=0", "--no-color"]
    if args.base:
        cmd.append(f"{args.base}...HEAD")
    else:
        cmd.append("--cached")
    cmd += ["--", ".", ":(exclude)vendor"]
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--staged", action="store_true",
                    help="scan staged changes (default)")
    ap.add_argument("--base", metavar="REF",
                    help="scan changes between REF and HEAD")
    ap.add_argument("--github", action="store_true",
                    help="emit GitHub Actions ::warning annotations")
    args = ap.parse_args()

    use_github = args.github or os.environ.get("GITHUB_ACTIONS") == "true"

    diff = get_diff(args)
    findings = []
    for path, lineno, text in iter_added_lines(diff):
        if excluded(path):
            continue
        for m in IP_RE.finditer(text):
            token = m.group()
            if not is_public(token):
                continue
            if looks_like_version(text, m.start(), m.end()):
                continue
            findings.append((path, lineno, token, text.strip()))

    for path, lineno, token, text in findings:
        if use_github:
            print(f"::warning file={path},line={lineno}::Public IP/CIDR "
                  f"'{token}' found in changed code")
        else:
            print(f"{path}:{lineno}: warning: public IP/CIDR '{token}' "
                  f"in added code  ({text})", file=sys.stderr)

    if findings:
        msg = (f"\n⚠️  {len(findings)} possible test artifact(s) (public IPs) in "
               f"changed code.")
        print(msg, file=sys.stderr)

    return 0  # always non-blocking


if __name__ == "__main__":
    sys.exit(main())
