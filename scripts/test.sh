#!/usr/bin/env bash
# Single entry point for the netbox-passwork checks.
#
#   scripts/test.sh [pytest-args...]   Python tests (all of them by default; a file, node id or
#                                      flags work too: scripts/test.sh netbox_passwork/tests/test_proxy.py -x)
#   scripts/test.sh js                 JS tests (node --test + jsdom)
#   scripts/test.sh lint               ruff check + ruff format --check
#   scripts/test.sh all                lint + Python + JS, with a markdown summary for the PR body
#
# The Python tests need an installed NetBox with the plugin registered (see docs/development.md
# sections 1-2). Paths and the configuration module come from environment variables — the
# convenient place for them is .env in the repository root (see .env.example; .env is git-ignored):
#   NETBOX_ROOT           NetBox directory             (default: /opt/netbox)
#   NETBOX_VENV           NetBox venv                  (default: $NETBOX_ROOT/venv)
#   NETBOX_CONFIGURATION  NetBox configuration module  (default: netbox.configuration)
#   NODE_BIN              Linux node binary            (default: auto — node from PATH if it is a
#                         Linux build, otherwise the newest ~/.vscode-server/bin/*/node)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [ -f .env ]; then set -a; . ./.env; set +a; fi

NETBOX_ROOT="${NETBOX_ROOT:-/opt/netbox}"
NETBOX_VENV="${NETBOX_VENV:-$NETBOX_ROOT/venv}"
export NETBOX_CONFIGURATION="${NETBOX_CONFIGURATION:-netbox.configuration}"
export PYTHONPATH="$NETBOX_ROOT/netbox${PYTHONPATH:+:$PYTHONPATH}"

PYTEST="$NETBOX_VENV/bin/pytest"
RUFF="$NETBOX_VENV/bin/ruff"; [ -x "$RUFF" ] || RUFF="$(command -v ruff || true)"

die() { echo "scripts/test.sh: $*" >&2; exit 2; }

find_node() {
    if [ -n "${NODE_BIN:-}" ]; then echo "$NODE_BIN"; return; fi
    if command -v node >/dev/null 2>&1 && [ "$(node -p process.platform 2>/dev/null)" = "linux" ]; then
        command -v node; return
    fi
    # WSL: PATH may only have a Windows node — fall back to the Linux node from vscode-server
    ls -t "$HOME"/.vscode-server/bin/*/node 2>/dev/null | head -1
}

run_py() {
    [ -x "$PYTEST" ] || die "$PYTEST not found — install NetBox and the dev dependencies: pip install -e \".[dev]\" into the NetBox venv"
    if [ $# -eq 0 ]; then set -- netbox_passwork/tests/; fi
    "$PYTEST" "$@"
}

run_js() {
    local node; node="$(find_node)"
    [ -n "$node" ] && [ -x "$node" ] || die "no Linux node found — set NODE_BIN (see .env.example)"
    [ -d node_modules/jsdom ] || die "node_modules/jsdom is missing — run npm install"
    "$node" --experimental-vm-modules --test netbox_passwork/tests/js/*.test.js
}

run_lint() {
    [ -n "$RUFF" ] || die "ruff not found"
    "$RUFF" check . && "$RUFF" format --check .
}

# --- PR summary: every step runs to completion, the result is a table ----------------
run_all() {
    local tmp; tmp="$(mktemp -d)"; trap "rm -rf '$tmp'" EXIT
    local rc_lint rc_py rc_js
    # each step runs in a subshell so die/exit in one step does not abort the summary
    echo "==> lint";   ( run_lint ) >"$tmp/lint" 2>&1; rc_lint=$?; cat "$tmp/lint"
    echo "==> pytest"; ( run_py )   >"$tmp/py"   2>&1; rc_py=$?;   tail -n 15 "$tmp/py"
    echo "==> js";     ( run_js )   >"$tmp/js"   2>&1; rc_js=$?;   grep -E '^(# |ℹ )(tests|pass|fail)' "$tmp/js" || tail -n 15 "$tmp/js"

    local py_line js_line
    py_line="$(grep -Eo '[0-9]+ (passed|failed|error|errors|skipped|xfailed|xpassed|deselected).* in [0-9.]+s' "$tmp/py" | tail -1)"
    py_line="${py_line:-see the output above}"
    local js_pass js_fail
    # node --test: the spec reporter prints 'i pass N', tap prints '# pass N'
    js_pass="$(grep -E '^(# |ℹ )pass ' "$tmp/js" | awk '{print $NF}')"; js_fail="$(grep -E '^(# |ℹ )fail ' "$tmp/js" | awk '{print $NF}')"
    js_line="${js_pass:+$js_pass pass, $js_fail fail}"; js_line="${js_line:-see the output above}"

    mark() { [ "$1" -eq 0 ] && echo "✅" || echo "❌"; }
    echo
    echo "## Checks (scripts/test.sh all, $(date +%F))"
    echo
    echo "| Check | Result |"
    echo "|---|---|"
    echo "| ruff check + format --check | $(mark $rc_lint) $([ $rc_lint -eq 0 ] && echo clean || echo 'see output') |"
    echo "| pytest (NetBox $(basename "$NETBOX_ROOT"), $NETBOX_CONFIGURATION) | $(mark $rc_py) $py_line |"
    echo "| node --test (JS, jsdom) | $(mark $rc_js) $js_line |"
    [ $rc_lint -eq 0 ] && [ $rc_py -eq 0 ] && [ $rc_js -eq 0 ]
}

case "${1:-}" in
    js)   run_js ;;
    lint) run_lint ;;
    all)  run_all ;;
    -h|--help|help) sed -n '2,17p' "$0" ;;
    *)    run_py "$@" ;;
esac
