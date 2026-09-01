#!/usr/bin/env bash
#
# webscan dependency-bump smoke test.
#
# Purpose: this repo has no unit-test coverage of any third-party dependency
# surface (the ~1100 tests under generated/ are Fern-generated JSON round-trips
# and the hand-written tests cover pure string/URL logic only). After a
# dependency bump, `go build` proves the API still compiles but proves nothing
# about runtime behaviour. This script closes that gap cheaply: it stands up a
# local HTTP server and drives the real CLI against it, asserting exit codes and
# well-formed JSON output.
#
# All traffic is to 127.0.0.1. The script makes no external network requests.
#
# Usage:  scripts/smoke/smoke.sh [path-to-webscan-binary]
# Exit:   0 = all checks passed, 1 = one or more checks failed

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${1:-}"
# Pick a free ephemeral port unless one is pinned, so concurrent runs and
# leftover servers from an interrupted run cannot collide.
PORT="${SMOKE_PORT:-$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')}"
WORKDIR="$(mktemp -d)"
PASS=0
FAIL=0

cleanup() {
  [[ -n "${SRV_PID:-}" ]] && kill "$SRV_PID" 2>/dev/null
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; FAIL=$((FAIL+1)); }

# ---------------------------------------------------------------- build binary
if [[ -z "$BIN" ]]; then
  BIN="$WORKDIR/webscan"
  say "Building webscan"
  if ! (cd "$REPO_ROOT" && go build -mod=vendor -o "$BIN" . 2>"$WORKDIR/build.err"); then
    grep -v 'warning:' "$WORKDIR/build.err" >&2
    echo "build failed" >&2
    exit 1
  fi
fi
echo "binary: $BIN"
if ! "$BIN" version >/dev/null 2>&1; then
  echo "cannot execute $BIN -- wrong architecture, not a file, or not executable" >&2
  exit 1
fi

# ------------------------------------------------------------- local test site
mkdir -p "$WORKDIR/site/admin" "$WORKDIR/site/api"
cat >"$WORKDIR/site/index.html" <<'HTML'
<!doctype html>
<html><head>
  <title>Smoke Target</title>
  <meta name="generator" content="WordPress 6.4.2">
  <script src="/static/app.js"></script>
</head><body>
  <h1>smoke target</h1>
  <a href="/admin/">admin</a>
  <a href="/api/v1/users">users</a>
  <form action="/login" method="post"><input name="username"><input name="password" type="password"></form>
  <p>lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod</p>
</body></html>
HTML
echo '<!doctype html><html><body>admin area</body></html>' >"$WORKDIR/site/admin/index.html"
echo '{"openapi":"3.0.0","info":{"title":"smoke","version":"1"},"paths":{}}' >"$WORKDIR/site/api/openapi.json"
mkdir -p "$WORKDIR/site/static"
cat >"$WORKDIR/site/static/app.js" <<'JS'
const routes = ["/api/v1/users", "/api/v1/orders", "/api/v1/health"];
fetch("/api/v1/session", {method: "GET"});
JS

say "Starting local HTTP server on 127.0.0.1:$PORT"
# Launch python3 directly rather than wrapping it in a `(cd ... && ...)` subshell:
# with the subshell, $! is the subshell's pid, and killing it orphans the python
# process, which keeps holding the port after this script exits. bash on macOS
# hides that by exec'ing the last command in the subshell, but on Linux (and so
# in CI and in the container runs) the two are genuinely separate processes.
# --directory removes the need for the cd, so $! is python itself.
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$WORKDIR/site" >"$WORKDIR/httpd.log" 2>&1 &
SRV_PID=$!
# Readiness probe uses python3 rather than curl: python3 is already required
# to run the server, so this adds no dependency, and curl is absent from some
# minimal images.
ready() {
  python3 -c "
import socket, sys
s = socket.socket(); s.settimeout(0.3)
sys.exit(0 if s.connect_ex(('127.0.0.1', $PORT)) == 0 else 1)
"
}
for _ in $(seq 1 60); do ready && break; sleep 0.25; done
if ! ready; then
  echo "local http server failed to start" >&2
  cat "$WORKDIR/httpd.log" >&2
  exit 1
fi
TARGET="http://127.0.0.1:$PORT"
echo "target: $TARGET"

# ------------------------------------------------------------------- assertion
# check <name> <expected-exit> <cmd...>
#   Runs the CLI, asserts the exit code, and if -o json was requested asserts
#   the payload parses as JSON.
check() {
  local name="$1"; shift
  local want_exit="$1"; shift
  local out="$WORKDIR/out.$$.json"
  "$@" >"$out" 2>"$WORKDIR/err.$$.txt"
  local got=$?
  if [[ "$got" != "$want_exit" ]]; then
    bad "$name (exit $got, wanted $want_exit)"
    sed -n '1,6p' "$WORKDIR/err.$$.txt" | sed 's/^/        /'
    return
  fi
  if [[ " $* " == *" -o json "* ]] || [[ " $* " == *" --output json "* ]]; then
    if ! python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$out" 2>/dev/null; then
      bad "$name (exit ok but output is not valid JSON)"
      sed -n '1,4p' "$out" | sed 's/^/        /'
      return
    fi
  fi
  ok "$name"
}

# jsoncheck <name> <python-expr-on-var-d> <cmd...>
#   As check(), plus asserts a predicate over the parsed JSON so we prove the
#   scan actually produced findings rather than an empty well-formed envelope.
jsoncheck() {
  local name="$1"; shift
  local expr="$1"; shift
  local out="$WORKDIR/out.$$.json"
  "$@" >"$out" 2>"$WORKDIR/err.$$.txt"
  local got=$?
  if [[ "$got" != 0 ]]; then
    bad "$name (exit $got)"
    sed -n '1,6p' "$WORKDIR/err.$$.txt" | sed 's/^/        /'
    return
  fi
  # The predicate travels via the environment, never through shell
  # interpolation into the Python source — predicates contain quotes.
  if SMOKE_EXPR="$expr" python3 -c '
import json, os, sys
d = json.load(open(sys.argv[1]))
expr = os.environ["SMOKE_EXPR"]
if not eval(expr):
    sys.exit("predicate false: " + expr)
' "$out" 2>"$WORKDIR/pred.err"; then
    ok "$name"
  else
    bad "$name ($(tail -1 "$WORKDIR/pred.err"))"
    head -c 300 "$out" | sed 's/^/        /'; echo
  fi
}

# =============================================================================
say "1. Command tree loads (forces package init across all deps)"
# Every cobra subcommand tree walk runs the init() of its imported packages.
# This is what catches an init-time panic from a bumped dep (nuclei template
# loading, rod, x/crypto openpgp s2k registration).
check "root help"                 0 "$BIN" --help
for sub in discover enumerate pentest; do
  check "$sub help"               0 "$BIN" "$sub" --help
done
check "version"                   0 "$BIN" version

say "2. HTTP request path (x/net, net/http, request helpers)"
jsoncheck "discover request" \
  "d['content']['result']['request']['response']['statusCode'] == 200" \
  "$BIN" discover request --target "$TARGET/" --http-method GET -o json

say "3. Probe (concurrent HTTP, tech fingerprinting via wappalyzergo)"
jsoncheck "discover probe" \
  "d['content']['result'] is not None" \
  "$BIN" discover probe --targets "$TARGET" --protocol HTTP -o json

say "4. Directory discovery (wordlist engine, concurrency, --add-slash)"
jsoncheck "discover directory" \
  "any(a['request']['path'] == '/admin' for t in d['content']['result']['targets'] for a in t['attempts'])" \
  "$BIN" discover directory --targets "$TARGET" --paths admin,api,nope-does-not-exist -o json

say "5. Route discovery (JS parsing, route extraction)"
# --request-method STANDARD is required, not incidental. `discover route` defaults
# to HEADLESS (cmd/discover.go), which drives rod/Chrome instead of the goquery
# HTML+JS parsing path this fixture was written to exercise -- and, with no browser
# on the box, rod tries to download Chromium, which would make this script reach
# the network. STANDARD keeps the run hermetic and tests the intended surface.
# Assert on a route that only appears if static/app.js was fetched and parsed,
# so the check cannot pass on a bare HTML-anchor crawl.
jsoncheck "discover route" \
  "'/api/v1/orders' in [r['path'] for w in d['content']['result']['webApplications'] for r in w['routes']]" \
  "$BIN" discover route --target "$TARGET/" --request-method STANDARD -o json

say "6. Wordlist generation (HTML parsing via goquery)"
jsoncheck "discover wordlist" \
  "'lorem' in [w['word'] for w in d['content']['result']['words']]" \
  "$BIN" discover wordlist --target "$TARGET/" -o json

say "7. API application enumeration (kin-openapi / swagger parsing)"
check "enumerate api-application" 0 "$BIN" enumerate api-application swagger --target "$TARGET/" --spec-url "$TARGET/api/openapi.json" -o json

say "8. CMS enumeration (fingerprint match on the WordPress generator tag)"
check "enumerate cms wordpress"   0 "$BIN" enumerate cms wordpress plugins --targets "$TARGET/" --plugins akismet,jetpack -o json

say "9. Output formats (signal + yaml writers, Method-Security/pkg)"
check "output yaml"               0 "$BIN" discover request --target "$TARGET/" --http-method GET -o yaml
check "output signal"             0 "$BIN" discover request --target "$TARGET/" --http-method GET -o signal

say "10. Graceful failure on a dead port (error paths, no panic)"
# Wants a clean non-zero-or-zero-with-error, never a panic. We only assert the
# process did not crash with a Go panic.
"$BIN" discover probe --targets "http://127.0.0.1:1" --protocol HTTP -o json >"$WORKDIR/dead.json" 2>"$WORKDIR/dead.err"
if grep -q "panic:" "$WORKDIR/dead.err" "$WORKDIR/dead.json"; then
  bad "dead port handled without panic"
  grep -m3 -A3 "panic:" "$WORKDIR/dead.err" | sed 's/^/        /'
else
  ok "dead port handled without panic"
fi

# =============================================================================
say "Result"
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
