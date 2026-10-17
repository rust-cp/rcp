#!/usr/bin/env bash
# Cut a release in two steps, each one a thing a person reviews:
#
#   scripts/release.sh prepare VERSION   on a clean tree: move CHANGELOG.md's [Unreleased]
#                                        entries under [VERSION] - today, bump Cargo.toml and
#                                        Cargo.lock, and commit "chore: release VERSION" on a
#                                        new branch release/vVERSION, for a pull request
#   scripts/release.sh tag VERSION       after that pull request merges: check that
#                                        origin/main carries VERSION in both files, then make
#                                        the annotated tag vVERSION on it and print the push
#   scripts/release.sh check VERSION [REF]  only the checks tag makes, against REF
#                                        (default origin/main); the release workflow runs it
#                                        before it tags a manual run
#
# Pushing the tag runs .github/workflows/release.yml, which builds, tests and publishes, and
# takes the release notes from the [VERSION] section. Running that workflow by hand on main
# with the version does the same and makes the tag itself. Neither step here pushes anything.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

die() { echo "release: $*" >&2; exit 1; }
usage() { die "usage: scripts/release.sh prepare|tag VERSION, or check VERSION [REF]"; }

[ $# -eq 2 ] || { [ $# -eq 3 ] && [ "$1" = check ]; } || usage
step=$1 version=${2#v} ref=${3:-origin/main}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "$version is not a semantic version"

crate_version() { sed -n 's/^version = "\(.*\)"/\1/p' "${1:-Cargo.toml}" | head -1; }
repo_url() {
    git config --get remote.origin.url | sed -E 's#^git@github.com:#https://github.com/#; s#\.git$##'
}
# the body of one CHANGELOG section, without its heading and without blank lines
section() { # section NAME [FILE]
    awk -v v="$1" '
        /^## \[/ { if (on) exit; on = index($0, "[" v "]") > 0; next }
        /^\[[^]]+\]: / { exit }
        on && NF' "${2:-CHANGELOG.md}"
}
# a is lower than b, in semantic-version order (a prerelease sorts before its release)
lower() { # lower A B
    [ "$1" != "$2" ] || return 1
    local a=${1%%-*} b=${2%%-*}
    if [ "$a" = "$b" ]; then
        # same core: the one with a prerelease is lower; two prereleases compare as strings
        [[ $1 == *-* ]] || return 1
        [[ $2 == *-* ]] || return 0
        [ "$(printf '%s\n%s\n' "$1" "$2" | LC_ALL=C sort | head -1)" = "$1" ]
    else
        [ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -1)" = "$a" ]
    fi
}

prepare() {
    [ -z "$(git status --porcelain)" ] || die "the tree has changes; commit or stash them first"
    local current today url branch=release/v$version
    current=$(crate_version)
    lower "$current" "$version" || die "$version is not above the current version $current"
    git rev-parse -q --verify "refs/tags/v$version" >/dev/null && die "tag v$version already exists"
    [ -n "$(section Unreleased | grep -v '^### ')" ] || die "CHANGELOG.md's [Unreleased] has no entries"
    grep -q "^## \[$version\]" CHANGELOG.md && die "CHANGELOG.md already has a [$version] section"
    today=$(date -u +%F)
    url=$(repo_url)

    git switch -q -c "$branch"
    # a fresh, empty [Unreleased] above the new section, and the comparison links moved on
    awk -v v="$version" -v d="$today" -v url="$url" -v prev="$current" '
        /^## \[Unreleased\]/ { print; print ""; print "## [" v "] - " d; next }
        /^\[Unreleased\]: / {
            print "[Unreleased]: " url "/compare/v" v "...HEAD"
            print "[" v "]: " url "/compare/v" prev "...v" v
            next
        }
        { print }' CHANGELOG.md > CHANGELOG.md.new
    mv CHANGELOG.md.new CHANGELOG.md
    # only the package's own version line, the first one in the file
    sed -i "0,/^version = \"$current\"/s//version = \"$version\"/" Cargo.toml
    cargo metadata --format-version 1 --offline >/dev/null
    [ "$(crate_version)" = "$version" ] || die "Cargo.toml still reads $(crate_version)"
    [ -n "$(section "$version")" ] || die "the [$version] section came out empty"

    git add CHANGELOG.md Cargo.toml Cargo.lock
    git commit -q -m "chore: release $version"
    echo "release: committed on $branch:"
    git show --stat --format='  %h %s' HEAD | sed 's/^/  /'
    echo "release: push it and open a pull request; after it merges, run: scripts/release.sh tag $version"
}

tag() {
    git fetch -q origin main
    check
    local head
    head=$(git rev-parse origin/main)
    git tag -a "v$version" -m "rcp $version" "$head"
    echo "release: tagged v$version at $(git rev-parse --short "$head"): $(git log -1 --format=%s "$head")"
    echo "release: publish it with: git push origin v$version"
}

# the release commit is at $ref: the version, a section with entries, and prepare's date
check() {
    [ "$(git show "$ref:Cargo.toml" | crate_version /dev/stdin)" = "$version" ] ||
        die "$ref's Cargo.toml is not at $version; has the release pull request merged?"
    [ -n "$(git show "$ref:CHANGELOG.md" | section "$version" /dev/stdin)" ] ||
        die "$ref's CHANGELOG.md has no [$version] section"
    # the date is what prepare writes, so an undated heading means prepare's commit is not there
    git show "$ref:CHANGELOG.md" | grep -qE "^## \[${version//./\\.}\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" ||
        die "$ref's [$version] heading has no release date; has the release pull request merged?"
    git rev-parse -q --verify "refs/tags/v$version" >/dev/null && die "tag v$version already exists"
    echo "release: $ref is release $version"
}

case $step in
    prepare) prepare ;;
    tag) tag ;;
    check) check ;;
    *) usage ;;
esac
