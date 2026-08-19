#!/usr/bin/env bash
# netbox-passwork release: preparation (release PR) and publishing (tag + GitHub Release + PyPI).
#
#   scripts/release.sh check             status: version, latest tag, what has piled up in [Unreleased]
#   scripts/release.sh prepare X.Y.Z     on a clean, up-to-date main: branch release/vX.Y.Z, version bump
#                                        in pyproject.toml, CHANGELOG [Unreleased] -> [X.Y.Z] — date,
#                                        scripts/test.sh all, commit, push, PR
#   scripts/release.sh publish           on main after the release PR is merged: sdist/wheel, signed tag
#                                        vX.Y.Z, tag push, GitHub Release with notes from CHANGELOG,
#                                        upload to PyPI
#
# Flags:  --yes       do not ask for confirmation of the manual checklist (prepare)
#         --no-test   prepare without scripts/test.sh all (use deliberately)
#         --unsigned  publish with an unsigned (annotated) tag when no signing key is available
#         --no-pypi   publish without uploading to PyPI
#
# Requirements: git with user.signingkey configured (or --unsigned), an authenticated gh, python with
# the build and twine modules (dev extra: pip install -e ".[dev]"; PYTHON=... to pick the interpreter),
# and PyPI credentials in ~/.pypirc or TWINE_USERNAME/TWINE_PASSWORD unless --no-pypi.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
    if [ -x venv/bin/python ]; then PYTHON=venv/bin/python; else PYTHON=python3; fi
fi

YES=0; NO_TEST=0; UNSIGNED=0; NO_PYPI=0; ARGS=()
for a in "$@"; do
    case "$a" in
        --yes) YES=1 ;; --no-test) NO_TEST=1 ;; --unsigned) UNSIGNED=1 ;; --no-pypi) NO_PYPI=1 ;;
        *) ARGS+=("$a") ;;
    esac
done
CMD="${ARGS[0]:-}"; VER="${ARGS[1]:-}"

die()  { echo "release: error: $*" >&2; exit 1; }
info() { echo "release: $*"; }

current_version() { sed -n 's/^version = "\([^"]*\)"/\1/p' pyproject.toml | head -1; }
latest_tag()      { git tag -l 'v*' --sort=-v:refname | head -1; }
tag_exists()      { git tag -l "v$1" | grep -q . || git ls-remote --tags origin "refs/tags/v$1" | grep -q .; }
# top version section in CHANGELOG (the first `## [X.Y.Z]`, skipping [Unreleased])
changelog_top_version() { grep -m1 -E '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' CHANGELOG.md | sed -E 's/^## \[([^]]+)\].*/\1/'; }
# section body: the lines between `## [V]` and the next `## [`
changelog_section() { awk -v v="$1" '$0 ~ "^## \\["v"\\]" {f=1; next} /^## \[/ {f=0} f' CHANGELOG.md | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}'; }
unreleased_entries() { changelog_section Unreleased | grep -cE '^- ' || true; }

require_clean_main() {
    [ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] || die "you must be on main (currently: $(git rev-parse --abbrev-ref HEAD))"
    [ -z "$(git status --porcelain)" ] || die "the working tree is not clean — commit or stash your changes"
    git fetch -q origin
    [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || die "main has diverged from origin/main — run git pull --ff-only"
}
require_gh() { gh auth status >/dev/null 2>&1 || die "gh is not authenticated (gh auth login)"; }
require_semver() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "the version must be X.Y.Z (SemVer), got: '$1'"; }

cmd_check() {
    local cur tag n top
    cur="$(current_version)"; tag="$(latest_tag)"; n="$(unreleased_entries)"; top="$(changelog_top_version)"
    echo "version in pyproject.toml : $cur"
    echo "latest tag                : ${tag:-<none>}"
    echo "top CHANGELOG section     : ${top:-<none>}"
    echo "entries in [Unreleased]   : $n"
    echo "branch / working tree     : $(git rev-parse --abbrev-ref HEAD) / $([ -z "$(git status --porcelain)" ] && echo clean || echo dirty)"
    echo "git signing key           : $(git config --get user.signingkey || echo '<none> (publish will need --unsigned)')"
    echo
    if [ "$top" = "$cur" ] && ! tag_exists "$cur"; then
        echo "-> version $cur is described in CHANGELOG but tag v$cur does not exist: next step is scripts/release.sh publish (on main, after the release PR is merged)"
    elif [ "$n" -gt 0 ]; then
        echo "-> there are unreleased changes: next step is scripts/release.sh prepare X.Y.Z (current version $cur)"
    else
        echo "-> nothing to release: [Unreleased] is empty"
    fi
}

cmd_prepare() {
    [ -n "$VER" ] || die "specify the version: scripts/release.sh prepare X.Y.Z"
    require_semver "$VER"
    local cur; cur="$(current_version)"
    [ "$VER" != "$cur" ] && [ "$(printf '%s\n%s\n' "$cur" "$VER" | sort -V | tail -1)" = "$VER" ] \
        || die "the new version $VER must be greater than the current $cur"
    require_clean_main; require_gh
    tag_exists "$VER" && die "tag v$VER already exists"
    grep -q '^## \[Unreleased\]' CHANGELOG.md || die "CHANGELOG.md has no ## [Unreleased] section"
    [ "$(unreleased_entries)" -gt 0 ] || die "the [Unreleased] section in CHANGELOG.md is empty — nothing to release"

    local summary=""
    if [ "$NO_TEST" -eq 0 ]; then
        info "running scripts/test.sh all ..."
        local out; out="$(mktemp)"
        if ! scripts/test.sh all | tee "$out"; then rm -f "$out"; die "checks failed — release stopped"; fi
        summary="$(sed -n '/^## Checks/,$p' "$out")"; rm -f "$out"
    fi

    if [ "$YES" -eq 0 ]; then
        cat <<'CHK'

Manual checklist (the script does not verify this — see docs/development.md section 5):
  - every change of this release is already in main through a merged PR;
  - live page run: Device / Virtual Machine / Service pages return 200, the Passwork tab
    and its badge render correctly;
  - if the release has migrations — manage.py migrate netbox_passwork against a database
    with realistic data.
CHK
        read -r -p "Checklist done? [yes/N] " ans; [ "$ans" = "yes" ] || die "aborted"
    fi

    local date branch; date="$(date +%F)"; branch="release/v$VER"
    info "branch $branch, version $cur -> $VER, CHANGELOG [Unreleased] -> [$VER] — $date"
    git switch -q -c "$branch"
    sed -i "s/^version = \"$cur\"/version = \"$VER\"/" pyproject.toml
    [ "$(current_version)" = "$VER" ] || die "failed to bump the version in pyproject.toml"
    sed -i "0,/^## \[Unreleased\]/s//## [Unreleased]\n\n## [$VER] — $date/" CHANGELOG.md
    git add pyproject.toml CHANGELOG.md
    git commit -q -m "release: v$VER"
    git push -q -u origin "$branch"

    local body; body="$(mktemp)"
    {
        echo "## Release v$VER"; echo
        echo "Version bump \`$cur\` -> \`$VER\` in \`pyproject.toml\`, \`[Unreleased]\` -> \`[$VER] — $date\` in \`CHANGELOG.md\`."; echo
        echo "### Changelog"; echo; changelog_section "$VER"; echo
        [ -n "$summary" ] && { echo "$summary"; echo; }
        echo "### After the merge"; echo; echo '`scripts/release.sh publish` on `main` — signed tag `v'"$VER"'`, sdist/wheel, GitHub Release, PyPI upload.'
    } >"$body"
    gh pr create --base main --head "$branch" --title "release: v$VER" --body-file "$body"
    rm -f "$body"
    info "release PR opened. After the merge: git switch main && git pull --ff-only && scripts/release.sh publish"
}

cmd_publish() {
    require_clean_main; require_gh
    local ver top; ver="$(current_version)"; top="$(changelog_top_version)"
    require_semver "$ver"
    [ "$top" = "$ver" ] || die "the top CHANGELOG section ($top) does not match the version in pyproject.toml ($ver) — run scripts/release.sh prepare first"
    tag_exists "$ver" && die "tag v$ver already exists — release $ver is published"
    [ -n "$(changelog_section "$ver")" ] || die "the [$ver] section in CHANGELOG.md is empty"

    info "building sdist/wheel ($PYTHON -m build) ..."
    rm -rf dist
    "$PYTHON" -m build >/dev/null || die "build failed (the build module is required: pip install -e \".[dev]\")"
    ls dist/netbox_passwork-"$ver"* >/dev/null 2>&1 || die "no artifacts for version $ver in dist/"
    "$PYTHON" -m twine check dist/netbox_passwork-"$ver"* || die "twine check failed on the built artifacts"

    if [ "$UNSIGNED" -eq 1 ]; then
        git tag -a "v$ver" -m "Release $ver"
    else
        [ -n "$(git config --get user.signingkey)" ] || die "no user.signingkey configured to sign the tag (or use --unsigned)"
        git tag -s "v$ver" -m "Release $ver"
        git tag -v "v$ver" >/dev/null 2>&1 || die "the signature of tag v$ver does not verify"
    fi
    git push -q origin "v$ver"
    info "tag v$ver pushed"

    local notes; notes="$(mktemp)"; changelog_section "$ver" >"$notes"
    gh release create "v$ver" dist/netbox_passwork-"$ver"* --verify-tag --title "v$ver" --notes-file "$notes"
    rm -f "$notes"
    info "GitHub Release v$ver created"

    if [ "$NO_PYPI" -eq 1 ]; then
        info "PyPI upload skipped (--no-pypi)"
    else
        info "uploading to PyPI ($PYTHON -m twine upload) ..."
        "$PYTHON" -m twine upload dist/netbox_passwork-"$ver"* \
            || die "twine upload failed — the tag and the GitHub Release are already published; fix the credentials and rerun: $PYTHON -m twine upload dist/netbox_passwork-$ver*"
        info "netbox-passwork $ver uploaded to PyPI"
    fi

    info "update servers with: sudo ./update.sh v$ver"
}

case "$CMD" in
    check)   cmd_check ;;
    prepare) cmd_prepare ;;
    publish) cmd_publish ;;
    -h|--help|help|"") sed -n '2,19p' "$0" ;;
    *) die "unknown command '$CMD' (check | prepare X.Y.Z | publish)" ;;
esac
