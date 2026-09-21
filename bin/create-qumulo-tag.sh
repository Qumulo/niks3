#!/usr/bin/env bash
# Tag HEAD for a qcr build: <upstream release>-qumulo-<commits>-<hash>,
# e.g. v1.11.0-qumulo-029-2cccc1d. The release is the nearest upstream v*
# tag below HEAD, the count is HEAD's distance from it, zero-padded so the
# tags sort as strings, and the hash pins the exact commit, so a rebase of
# the same stack gets a new tag rather than reusing one.
#
# USAGE: bin/create-qumulo-tag.sh [--push] [--dry-run]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
cd "$SCRIPT_DIR/.."

push=0
dry_run=0
for arg in "$@"; do
  case "$arg" in
    --push) push=1 ;;
    --dry-run | -n) dry_run=1 ;;
    *)
      echo "USAGE: $0 [--push] [--dry-run]" >&2
      exit 1
      ;;
  esac
done

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo "There are uncommitted changes, exiting" >&2
  exit 1
fi

# Upstream releases are v<major>.<minor>.<patch>; our own tags are excluded
# so a second build on the same stack still measures from the release.
if ! base=$(git describe --tags --abbrev=0 --match 'v[0-9]*' --exclude '*-qumulo-*' HEAD 2>/dev/null); then
  echo "No upstream release tag below HEAD; fetch them with: git fetch upstream --tags" >&2
  exit 1
fi

count=$(git rev-list --count "${base}..HEAD")
hash=$(git rev-parse --short=7 HEAD)
tag=$(printf '%s-qumulo-%03d-%s' "$base" "$count" "$hash")

if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
  echo "Tag ${tag} already exists, exiting" >&2
  exit 1
fi

if [[ $dry_run == 1 ]]; then
  echo "$tag"
  exit 0
fi

git tag -a -m "niks3 ${base} with ${count} Qumulo commits on top, at ${hash}" "$tag"
echo "Created ${tag}"

if [[ $push == 1 ]]; then
  git push origin "refs/tags/${tag}"
else
  echo "Push it to start the qcr build: git push origin ${tag}"
fi
