#!/usr/bin/env bash
# Compute the release version for the current workflow run.
#
# Usage: compute-version.sh <ref_type> <ref_name> [requested_version]
#
#   ref_type          "branch" or "tag" (github.ref_type)
#   ref_name          branch or tag name (github.ref_name)
#   requested_version optional version from workflow_dispatch (with or without "v")
#
# The script writes version, tag, previous_tag, cliff_args and skip to
# $GITHUB_OUTPUT (or stdout when run locally).
set -euo pipefail

ref_type="${1:-branch}"
ref_name="${2:-main}"
requested_version="${3:-}"
requested_version="${requested_version//[[:space:]]/}"

: "${GITHUB_OUTPUT:=/dev/stdout}"

semver_re='^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'
tag_glob='v[0-9]*'

normalize() {
  local value="$1"
  printf '%s' "${value#v}"
}

# Highest version tag reachable from HEAD.
latest_tag() {
  git tag --merged HEAD --list "$tag_glob" --sort=-v:refname | head -n1 || true
}

# Tag pointing at the current commit, if any. This keeps workflow re-runs
# idempotent: a commit that was already released reuses its version.
head_tag() {
  git tag --points-at HEAD --list "$tag_glob" --sort=-v:refname | head -n1 || true
}

workspace_version() {
  awk '
    /^\[workspace\.package\]/ { in_section = 1; next }
    /^\[/ { in_section = 0 }
    in_section && /^version[[:space:]]*=/ {
      gsub(/.*=[[:space:]]*"|".*/, "", $0)
      print $0
      exit
    }
  ' Cargo.toml
}

current_tag="$(head_tag)"

if [[ -n "$requested_version" ]]; then
  version="$(normalize "$requested_version")"
  tag="v${version}"
elif [[ "$ref_type" == "tag" ]]; then
  tag="$ref_name"
  version="$(normalize "$ref_name")"
elif [[ -n "$current_tag" ]]; then
  tag="$current_tag"
  version="$(normalize "$tag")"
else
  latest="$(latest_tag)"
  if [[ -z "$latest" ]]; then
    version="$(workspace_version)"
    version="${version:-0.1.0}"
  else
    base="$(normalize "$latest")"
    IFS='.' read -r major minor patch _rest <<< "$base"
    patch="${patch%%[-+]*}"
    version="${major}.${minor}.$((patch + 1))"
  fi
  tag="v${version}"
fi

if [[ ! "$version" =~ $semver_re ]]; then
  echo "error: invalid release version '${version}'" >&2
  exit 1
fi

# Previous release tag used to scope the generated notes. Exclude the tag being
# released so a tag-triggered run does not compare the tag with itself.
previous_tag="$(git tag --merged HEAD --list "$tag_glob" --sort=-v:refname | grep -vx "$tag" | head -n1 || true)"

if [[ "$ref_type" == "tag" || "$tag" == "$current_tag" ]]; then
  if [[ -n "$previous_tag" ]]; then
    cliff_args="${previous_tag}..${tag} --strip header"
  else
    cliff_args="--latest --strip header"
  fi
else
  # The tag does not exist yet on a branch run, so git-cliff labels the
  # unreleased commits with the version we are about to publish.
  cliff_args="--unreleased --tag ${tag} --strip header"
fi

# Never publish the same branch build twice (e.g. when re-running a workflow).
# Tag pushes are allowed to refresh an existing release.
skip=false
if [[ "$ref_type" != "tag" ]] && command -v gh >/dev/null 2>&1 && [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
  if gh release view "$tag" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
    echo "release ${tag} already exists; skipping this run" >&2
    skip=true
  fi
fi

{
  echo "version=${version}"
  echo "tag=${tag}"
  echo "previous_tag=${previous_tag}"
  echo "cliff_args=${cliff_args}"
  echo "skip=${skip}"
} >> "$GITHUB_OUTPUT"
