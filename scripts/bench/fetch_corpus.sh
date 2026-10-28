#!/usr/bin/env bash
#
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
#
# Fetch the `large` workload block corpus (issue #2104, epic #2101) from its
# GitHub release asset, verify every file against MANIFEST.sha256 and the
# manifest itself against the sha256 pinned in benchmarks/corpus/large.ref,
# then install it into benchmarks/corpus/large/ (git-ignored).
#
# Usage: fetch_corpus.sh [--ref FILE] [--url URL] [--from TARBALL]
#                        [--dest DIR] [--force]
#   --ref FILE     url + manifest_sha256 pin (default benchmarks/corpus/large.ref)
#   --url URL      override the asset URL (also: CORPUS_URL)
#   --from FILE    install from a local tarball instead of downloading
#   --dest DIR     install directory (default benchmarks/corpus/large)
#   --force        replace an existing --dest
#
# Exit codes: 0 installed, 1 verification/usage error, 3 asset not published
# (or not reachable) - the message says how to generate the corpus locally.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
REF="$REPO_ROOT/benchmarks/corpus/large.ref"
URL="${CORPUS_URL:-}"
FROM=""
DEST="$REPO_ROOT/benchmarks/corpus/large"
FORCE=0

die() { echo "fetch_corpus: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --ref) REF="$2"; shift 2 ;;
        --url) URL="$2"; shift 2 ;;
        --from) FROM="$2"; shift 2 ;;
        --dest) DEST="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        -h|--help) sed -n '2,23p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -f "$REF" ] || die "no ref file $REF"
ref_value() { grep -E "^$1=" "$REF" | head -n1 | cut -d= -f2- | tr -d '[:space:]'; }
[ -n "$URL" ] || URL="$(ref_value url)"
PIN="$(ref_value manifest_sha256)"
[ -n "$PIN" ] || die "$REF has no manifest_sha256="

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

if [ -e "$DEST" ] && [ "$FORCE" != 1 ]; then
    die "$DEST already exists (pass --force to replace it)"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

not_published() {
    cat >&2 <<EOF
fetch_corpus: the large corpus is not available from
  $URL
($1). It is published by hand by a maintainer (docs/BENCHMARK_COMPARISON.md,
"Workload corpus"); until then, generate it locally (Linux, ~35 min, ~300 MB):

  bash scripts/bench/build_both.sh --skip-rust
  python3 scripts/bench/corpus/generate.py --preset large --out benchmarks/corpus/large

The generator is deterministic: a correct local build has the pinned
MANIFEST.sha256 sha256 $PIN.
EOF
    exit 3
}

if [ -n "$FROM" ]; then
    [ -f "$FROM" ] || die "no such tarball: $FROM"
    cp "$FROM" "$TMP/corpus.tar.gz"
else
    [ -n "$URL" ] || die "no url (set url= in $REF, CORPUS_URL or --url)"
    command -v curl >/dev/null 2>&1 || die "curl is required"
    echo "fetch_corpus: downloading $URL"
    code="$(curl -sSL --retry 3 -o "$TMP/corpus.tar.gz" -w '%{http_code}' "$URL" 2>"$TMP/curl.err" || true)"
    case "$code" in
        200) ;;
        404) not_published "HTTP 404" ;;
        000|"") not_published "$(tr '\n' ' ' < "$TMP/curl.err")" ;;
        *) not_published "HTTP $code" ;;
    esac
fi

mkdir "$TMP/x"
tar -xzf "$TMP/corpus.tar.gz" -C "$TMP/x" || die "not a .tar.gz corpus archive"
manifest="$(find "$TMP/x" -mindepth 1 -maxdepth 2 -name MANIFEST.sha256 | head -n1)"
[ -n "$manifest" ] || die "archive holds no MANIFEST.sha256"
cdir="$(dirname "$manifest")"

got="$(sha256_of "$manifest")"
[ "$got" = "$PIN" ] || die "MANIFEST.sha256 has sha256 $got, $REF pins $PIN (wrong or tampered asset)"

# Every file listed must match, and nothing unlisted may ride along.
while IFS= read -r line; do
    [ -n "$line" ] || continue
    digest="${line%%  *}"
    name="${line#*  }"
    case "$name" in */*|..*|"") die "bad manifest entry: $line" ;; esac
    [ -f "$cdir/$name" ] || die "$name: listed in MANIFEST.sha256 but missing"
    [ "$(sha256_of "$cdir/$name")" = "$digest" ] || die "$name: sha256 mismatch"
done < "$manifest"
for f in "$cdir"/*; do
    n="$(basename "$f")"
    [ "$n" = MANIFEST.sha256 ] && continue
    grep -q "  $n\$" "$manifest" || die "$n: present but not listed in MANIFEST.sha256"
done

rm -rf "$DEST"
mkdir -p "$(dirname "$DEST")"
mv "$cdir" "$DEST"
echo "fetch_corpus: installed $DEST (MANIFEST.sha256 $got verified)"
