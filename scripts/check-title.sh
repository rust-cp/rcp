#!/usr/bin/env bash
# Check that a pull request title is a Conventional Commit subject.
#
#   scripts/check-title.sh "fix(nfs): retry a MOUNT refused while the server starts"
#
# Pull requests are squash-merged, so the title becomes the commit on main; this is the one
# place the convention can be enforced. The " (#N)" GitHub appends on merge is accepted, so the
# same check reads main's history: git log --format=%s | while read -r s; do ...; done
set -euo pipefail

title=${1-}
types='build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test'
# type, an optional (scope) of lowercase words, an optional ! for a breaking change, ": ",
# then a description that starts with something other than a space
re="^($types)(\([a-z0-9][a-z0-9._/,-]*\))?!?: [^ ].*$"

if [[ $title =~ $re ]]; then
    exit 0
fi
{
    echo "not a Conventional Commit title: $title"
    echo "expected TYPE(SCOPE): description, or TYPE: description, where TYPE is one of"
    echo "  ${types//|/, }"
    echo "and SCOPE, when given, is lowercase (the endpoint or module: nfs, smb, dav, uring ...);"
    echo "add ! before the colon for a breaking change. See CONTRIBUTING.md."
} >&2
exit 1
