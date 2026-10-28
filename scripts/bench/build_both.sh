#!/usr/bin/env bash
#
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
#
# Build both implementations for bench-compare at pinned commits (issue #2102,
# epic #2101):
#
#   * go-algorand `algod` + `goal` from a checkout that must sit EXACTLY on the
#     pinned tag (scripts/bench/go-algorand.pin, overridable via
#     GO_ALGORAND_REV); checked with `git describe --tags`, mismatch = exit 1.
#     Runs `make libsodium` first (go-algorand's crypto links the vendored
#     libsodium fork; see CLAUDE.md), then `go build` of just the two commands
#     with go-algorand's own release flags (tags, buildmode, ldflags), read
#     from its Makefile so the binary matches a `make build` one.
#   * algod-rust `algod-rust` with `cargo build --release --locked`.
#
# Binaries land in <bin-dir>/go/ and <bin-dir>/rust/; both commits, the tag,
# toolchain versions and binary sha256s go to <out>/build-info.json, which
# report.py shows in the report's Builds table.
#
# Usage: build_both.sh [--out DIR] [--bin-dir DIR] [--go-algorand DIR]
#                      [--clone] [--skip-go] [--skip-rust]
#   --clone      git clone the pinned tag into --go-algorand when it is absent
#   --skip-go / --skip-rust   build only one side (build-info marks the other
#                              as not built)
#
# Needs (Linux): git, go (go-algorand's go.mod version), cargo, make, and for
# libsodium: autoconf automake libtool build-essential.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

OUT="$REPO_ROOT/bench-results/build"
BIN_DIR="$REPO_ROOT/target/bench-compare"
GO_DIR="${GO_ALGORAND_DIR:-$REPO_ROOT/../go-algorand}"
CLONE=0
SKIP_GO=0
SKIP_RUST=0

die() { echo "build_both: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --bin-dir) BIN_DIR="$2"; shift 2 ;;
        --go-algorand) GO_DIR="$2"; shift 2 ;;
        --clone) CLONE=1; shift ;;
        --skip-go) SKIP_GO=1; shift ;;
        --skip-rust) SKIP_RUST=1; shift ;;
        -h|--help) sed -n '2,32p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

PIN_TAG="$(grep -v '^[[:space:]]*#' "$HERE/go-algorand.pin" | grep -v '^[[:space:]]*$' | head -n1 | tr -d '[:space:]')"
TAG="${GO_ALGORAND_REV:-$PIN_TAG}"
[ -n "$TAG" ] || die "no go-algorand tag (scripts/bench/go-algorand.pin empty?)"

mkdir -p "$OUT" "$BIN_DIR"
BIN_DIR="$(cd "$BIN_DIR" && pwd)"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

GO_COMMIT="" TAG_COMMIT="" GO_DESCRIBE="" GO_DIRTY="" GO_VERSION="" GO_BINS=""
if [ "$SKIP_GO" = 0 ]; then
    if [ ! -d "$GO_DIR/.git" ] && [ ! -f "$GO_DIR/.git" ]; then
        [ "$CLONE" = 1 ] || die "no go-algorand checkout at $GO_DIR (pass --clone, or: git clone --branch $TAG https://github.com/algorand/go-algorand $GO_DIR)"
        echo "build_both: cloning go-algorand $TAG into $GO_DIR"
        git clone --quiet --depth 1 --branch "$TAG" https://github.com/algorand/go-algorand "$GO_DIR"
    fi
    GO_DIR="$(cd "$GO_DIR" && pwd)"
    # The pin is checked by commit: HEAD must be the tag's commit. `git
    # describe` can name another tag on the same commit, so it is recorded
    # for information only.
    GO_COMMIT="$(git -C "$GO_DIR" rev-parse HEAD)"
    TAG_COMMIT="$(git -C "$GO_DIR" rev-parse --verify --quiet "refs/tags/$TAG^{commit}" || true)"
    GO_DESCRIBE="$(git -C "$GO_DIR" describe --tags 2>/dev/null || true)"
    [ -n "$TAG_COMMIT" ] || die "tag '$TAG' not found in $GO_DIR (git -C $GO_DIR fetch --tags)"
    [ "$GO_COMMIT" = "$TAG_COMMIT" ] || die "go-algorand at $GO_DIR is at $GO_COMMIT ('$GO_DESCRIBE'), not the pinned '$TAG' commit $TAG_COMMIT (git -C $GO_DIR checkout $TAG)"
    if [ -n "$(git -C "$GO_DIR" status --porcelain --untracked-files=no)" ]; then
        GO_DIRTY=true
        echo "build_both: WARNING: go-algorand has uncommitted changes to tracked files" >&2
    else
        GO_DIRTY=false
    fi
    GO_VERSION="$(go version)"
    echo "build_both: go-algorand $TAG ($GO_COMMIT), $GO_VERSION"

    echo "build_both: make libsodium"
    make -C "$GO_DIR" libsodium

    # Read go-algorand's own release build flags from its Makefile, so the
    # benchmarked binary is built like `make build` builds it. One target
    # prints all three variables, one per line, in a single Makefile parse
    # (go-algorand's Makefile runs several `go list` at parse time).
    FLAGS_MK="$(mktemp)"
    trap 'rm -f "$FLAGS_MK"' EXIT
    printf 'bench-print-flags:\n\t@echo "$(GOTAGSLIST)"\n\t@echo "$(GOBUILDMODE)"\n\t@echo "$(GOLDFLAGS)"\n' > "$FLAGS_MK"
    FLAGS_OUT="$(make -s -C "$GO_DIR" -f Makefile -f "$FLAGS_MK" bench-print-flags)"
    [ "$(printf '%s\n' "$FLAGS_OUT" | wc -l)" -eq 3 ] || die "unexpected flag output from go-algorand's Makefile: $FLAGS_OUT"
    { IFS= read -r GOTAGSLIST; IFS= read -r GOBUILDMODE; IFS= read -r GOLDFLAGS; } <<<"$FLAGS_OUT"
    echo "build_both: go tags='$GOTAGSLIST' buildmode='$GOBUILDMODE'"

    mkdir -p "$BIN_DIR/go"
    # shellcheck disable=SC2086 # GOBUILDMODE is "-buildmode pie" / "-buildmode=exe"
    (cd "$GO_DIR" && go build -trimpath --tags "$GOTAGSLIST" $GOBUILDMODE \
        -ldflags="$GOLDFLAGS" -o "$BIN_DIR/go/" ./cmd/algod ./cmd/goal)
    for b in algod goal; do
        [ -x "$BIN_DIR/go/$b" ] || die "go build did not produce $BIN_DIR/go/$b"
        GO_BINS="$GO_BINS go/$b:$(sha256_of "$BIN_DIR/go/$b")"
    done
fi

RUST_COMMIT="" RUST_DESCRIBE="" RUST_DIRTY="" RUST_VERSION="" RUST_BINS=""
if [ "$SKIP_RUST" = 0 ]; then
    RUST_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
    RUST_DESCRIBE="$(git -C "$REPO_ROOT" describe --tags --always)"
    if [ -n "$(git -C "$REPO_ROOT" status --porcelain --untracked-files=no)" ]; then
        RUST_DIRTY=true
        echo "build_both: WARNING: algod-rust has uncommitted changes to tracked files" >&2
    else
        RUST_DIRTY=false
    fi
    RUST_VERSION="$(rustc -V)"
    echo "build_both: algod-rust $RUST_COMMIT, $RUST_VERSION"
    # Ask cargo where it put the binary (honours CARGO_TARGET_DIR,
    # build.target-dir and --target) instead of assuming ./target/release.
    CARGO_MSGS="$(mktemp)"
    (cd "$REPO_ROOT" && cargo build --release --locked --bin algod-rust \
        --message-format=json-render-diagnostics) > "$CARGO_MSGS"
    RUST_EXE="$(python3 "$HERE/cargo_artifact.py" algod-rust < "$CARGO_MSGS")" \
        || die "cargo reported no executable for algod-rust"
    rm -f "$CARGO_MSGS"
    mkdir -p "$BIN_DIR/rust"
    exe_name="$(basename "$RUST_EXE")"
    cp "$RUST_EXE" "$BIN_DIR/rust/$exe_name"
    RUST_BINS="rust/$exe_name:$(sha256_of "$BIN_DIR/rust/$exe_name")"
fi

export TAG TAG_COMMIT GO_COMMIT GO_DESCRIBE GO_DIRTY GO_VERSION GO_BINS
export RUST_COMMIT RUST_DESCRIBE RUST_DIRTY RUST_VERSION RUST_BINS
python3 - "$OUT/build-info.json" <<'PY'
import datetime, json, os, sys
e = os.environ
def bins(s):
    out = {}
    for item in s.split():
        path, digest = item.rsplit(":", 1)
        out[path] = digest
    return out
def side(prefix, built):
    if not built:
        return {"built": False}
    return {"built": True,
            "commit": e[prefix + "_COMMIT"],
            "describe": e[prefix + "_DESCRIBE"],
            "dirty": e[prefix + "_DIRTY"] == "true",
            "toolchain": e[prefix + "_VERSION"],
            "binaries": sorted(bins(e[prefix + "_BINS"])),
            "sha256": bins(e[prefix + "_BINS"])}
go = side("GO", bool(e["GO_COMMIT"]))
if go["built"]:
    go.update({"tag": e["TAG"], "tag_commit": e["TAG_COMMIT"],
               "pin_ok": bool(e["TAG_COMMIT"]) and e["GO_COMMIT"] == e["TAG_COMMIT"]})
info = {
    "schema": "bench-build-info/v1",
    "built_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "expected_tag": e["TAG"],
    "go_algorand": go,
    "algod_rust": side("RUST", bool(e["RUST_COMMIT"])),
}
with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as f:
    json.dump(info, f, indent=2)
    f.write("\n")
print("build_both: wrote " + sys.argv[1])
PY
