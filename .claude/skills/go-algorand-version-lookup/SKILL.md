---
name: go-algorand-version-lookup
description: Find which go-algorand release(s) a given upstream commit/feature first shipped in — the origin tag and whether it reached the current parity pin. Handles both new-feature lookups (given an addition commit) and bug/divergence lookups (algod-rust behaves differently from go-algorand's current logic — find the commit that implements the *correct* behavior algod-rust is missing, then its origin tag). Use whenever labeling an algod-rust issue/PR with an `algod:<tag>` upstream-version tag, or whenever asked "what version of go-algorand shipped X" / "when was this implemented upstream".
---

# go-algorand version lookup

Given a change in `../go-algorand`, determine the exact release tag(s) that carry it, so algod-rust issues can be labeled `algod:<tag>` accurately. This is a pure lookup — it does not create or edit anything by itself; other skills (`algod-issue-create`, `algod-issue-fix`, `algod-version-upgrade`) call into it.

## Two modes — pick the right one before searching

- **Addition mode**: algod-rust is missing something go-algorand added (a new opcode, a new field, a whole new feature). You're looking for the commit that *introduced* the thing.
- **Divergence mode (the common bug case)**: algod-rust *has* an implementation of some behavior, but it disagrees with go-algorand's current behavior — a bug report almost always means "the correct logic already exists upstream, algod-rust just built it differently or wrong." Here you are not looking for when something was *added* in the abstract — you're looking for the commit that shaped the **specific current logic** algod-rust diverges from, which may be old, may have been rewritten more than once, and is unrelated to when the surrounding feature was originally introduced. Don't default to "first commit that touched this file" — that's frequently a refactor or an unrelated earlier version of the logic, not the commit that produced the behavior algod-rust needs to match.

If you're not sure which mode applies: if algod-rust has no code path for this at all, it's addition mode; if algod-rust has code that runs but produces the wrong result/byte/status compared to go-algorand, it's divergence mode.

## Input forms

You'll be handed one of:
- **A commit SHA** in `../go-algorand` — the direct case, either mode.
- **A file/function/feature description** with no SHA yet — locate the commit(s) first (see below), then proceed as if given the SHA.
- **Nothing upstream at all** — the change is purely internal to algod-rust (tooling, CI config, this repo's own scripts/docs) with no corresponding go-algorand commit. Stop immediately and report **not applicable** — do not force a lookup or guess a tag. Not every algod-rust issue is a parity issue, and this applies in both modes: even a "bug" can be algod-rust-only (e.g. a broken CI script) with no upstream logic to diverge from at all.

## Steps

1. **Locate the commit if not given one.**

   **Addition mode** — search for when the thing was introduced:
   - `git -C ../go-algorand log --oneline -- <path>` for a known file/area.
   - `git -C ../go-algorand log -S'<distinctive string>' --oneline` for a specific symbol/behavior (pickaxe search).
   - Cross-check against `data/transactions/logic/opcodes.go`, `config/consensus.go`, etc. per `CLAUDE.md`'s reference-file table if the change is AVM/consensus-shaped.

   **Divergence mode** — find the commit that shaped the *current* correct logic, not the oldest touch on the file:
   - First pin down exactly which lines in `../go-algorand` (checked out at the current pin, `HEAD`/`PIN_TAG`) implement the specific behavior algod-rust gets wrong — you should already have this from investigating the bug (step 1 of `algod-issue-fix`, or the issue body itself).
   - Use **`git -C ../go-algorand log -L<start>,<end>:<path>`** (line-history log, not `blame`) on those lines. Unlike `blame`, this walks through every revision of that exact range and shows the actual diff each time, so gofmt-only or move-only commits are visibly no-ops instead of silently owning the blame for a line they didn't semantically change. Read backwards from the top (current) entry until you find the commit whose diff actually introduces the specific semantic detail algod-rust is missing (a condition, an off-by-one boundary, an ordering rule, an error-vs-ignore choice) — that's the target commit, not necessarily the most recent one and not necessarily the oldest.
   - If `git log -L` is awkward for the shape of the change (e.g. the logic isn't a stable contiguous line range — it moved files, or the "correct" behavior is really an emergent property of several call sites), fall back to `git log -p -- <path>` and read hunks, or a pickaxe search (`git log -S'<distinctive token>'`) for the specific literal/condition/constant that encodes the correct behavior.
   - `git blame -L<start>,<end> <path>` is acceptable as a fast first pass to get candidate SHAs, but never stop at blame's answer alone — always confirm with `git show <sha>` (or the `log -L` diff) that the commit's actual change is the semantic one, not a reformat/rename that blame attributes the line to.

   **Both modes**:
   - Confirm you have the right commit by reading its diff (`git -C ../go-algorand show <sha>`) before proceeding — a wrong commit produces a confidently wrong tag.
   - If nothing in `../go-algorand` implements the thing at all (it's algod-rust-only work — e.g. a script losing its execute bit, a CI workflow tweak, a doc fix, a Rust-side refactor with no upstream behavioral counterpart), stop here: **not applicable**, no `algod:<tag>` label.

2. **Refresh tags:** `git -C ../go-algorand fetch --tags`.

3. **Find the origin tag** — the earliest release (stable or pre-release alike; a `-beta`/`-rc` tag counts as its own release) whose history contains the commit:
   ```bash
   git -C ../go-algorand tag --contains <sha> --list | sort -V | head -1
   ```
   This is `ORIGIN_TAG`. go-algorand's tag history is linear enough that `sort -V | head -1` reliably picks the earliest reachable tag, but if the result looks surprising (e.g. an old-looking tag for a recently-authored commit), double check with `git -C ../go-algorand log <sha>..<tag> --oneline | wc -l` or by reading the tag's date (`git -C ../go-algorand log -1 --format=%ai <tag>`) against the commit's own date.

   In **divergence mode** the target commit is frequently years old — the correct logic has often been stable upstream since long before algod-rust existed. That's expected, not a sign you picked the wrong commit: it just means the `algod:<tag>` label will point at an old release, which is still the right answer (it's the true origin of the behavior algod-rust needs to match). If `git tag --contains <sha>` returns nothing at all (the commit predates go-algorand's earliest tag), say so explicitly and use the earliest tag that exists (`git -C ../go-algorand tag --list | sort -V | head -1`) as a floor, noting in the output that the behavior is older than tracked release history.

4. **Cross-check with release notes** (best-effort, not blocking): `gh release view <ORIGIN_TAG> -R algorand/go-algorand`. A tag-only pre-release with no GitHub Release object is normal — don't treat a missing release page as disqualifying; the tag-containment check in step 3 is the authoritative signal, release notes are corroboration.

5. **Determine reach into the current pin.** Read the pin from this repo's `CLAUDE.md` ("pinned to `<tag>`") — call it `PIN_TAG`. Check ancestry:
   ```bash
   git -C ../go-algorand merge-base --is-ancestor <sha> PIN_TAG && echo "reaches pin"
   ```
   - If it reaches `PIN_TAG` **and** `PIN_TAG != ORIGIN_TAG`, the feature has two applicable labels: `algod:<ORIGIN_TAG>` (true origin, especially important if origin is a pre-release) and `algod:<PIN_TAG>` (because it's part of what the current pin actually ships — a future reader filtering by the pin tag must find it).
   - If `PIN_TAG == ORIGIN_TAG`, one label suffices.
   - If it does **not** reach `PIN_TAG` (the commit is from a release newer than the current pin, or on an unrelated branch), report that explicitly — this usually means either the lookup target predates a future version-upgrade epic, or something is off with the assumed pin; don't silently label with a tag the codebase doesn't yet target.

## Output

Report, plainly, so a caller can act on it without re-deriving anything:

```
Mode: addition|divergence
Commit: <sha> — <one-line summary>
Origin tag: <ORIGIN_TAG> (<date>)
Reaches current pin (<PIN_TAG>): yes|no
Labels to apply: algod:<ORIGIN_TAG>[, algod:<PIN_TAG>]
```

or, when there's no upstream counterpart:

```
Not applicable — no corresponding go-algorand commit; this is internal to algod-rust.
No algod:<tag> label.
```

In divergence mode's labeled form, also state what specifically the commit changed/established, so the caller can quote it in the issue body's "Upstream change" section instead of just a tag number — the point of the label is to say *why this tag*, not just *which tag*.

## Notes

- This mirrors (and is the single source of truth for) the origin/pin dual-labeling logic previously described inline in `algod-version-upgrade`'s stage 3 — that skill's per-tag sweep over `TAGS_IN_RANGE` is a batch application of exactly this per-commit lookup, run once per stage-2 change (always addition mode, since version-upgrade epics are enumerating upstream additions by construction).
- `algod-issue-create` and `algod-issue-fix` are where divergence mode mostly gets used, since most parity **bug reports** are exactly this shape: algod-rust's behavior disagrees with go-algorand's current behavior, and the fix is to match logic that already exists upstream.
- Never guess a version from a changelog description alone when the actual commit is available — always ground the tag in `git tag --contains`, not prose.
- Never settle for "this file was touched in commit X" as the answer in divergence mode without reading the diff — `git log -L`/`git log -p` exist precisely because `blame`'s most-recent-touch answer is frequently a reformat, rename, or unrelated nearby edit, not the commit that produced the semantics in question.
- A commit can legitimately have no `algod:<tag>` label at all (new-scope work with no upstream analog, e.g. the libp2p P2P transport) — that's a correct "not applicable" outcome, not a gap to fill.
