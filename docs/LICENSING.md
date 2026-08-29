# Licensing rationale

This document explains *why* algod-rust is licensed the way it is. For
*what* each file is licensed as, see the checked-in audit table:
[`docs/LICENSING_AUDIT.md`](LICENSING_AUDIT.md). For the license texts
themselves, see [`COPYING`](../COPYING) (AGPL-3.0-or-later + go-algorand's
preserved section 7e Additional Terms) and [`LICENSE-MIT`](../LICENSE-MIT)
at the repository root.

## 1. Classification rationale

algod-rust is a full Rust reimplementation of
[go-algorand](https://github.com/algorand/go-algorand) — its node
software, its REST API, its wire (gossip/P2P) protocol, and its
consensus mechanism — developed file-by-file against the pinned
go-algorand source as the authoritative reference and verified
byte-for-byte through a conformance harness.

go-algorand's own `COPYING_FAQ` (item 2, "What do these licenses mean to
someone building on the Algorand blockchain?") states this directly:

> If you modify the Algorand node software (for example, creating a new
> blockchain), reimplement the APIs (not interfacing through the SDKs),
> use Algorand's consensus mechanism in other software, or otherwise
> create a new work based on any Algorand materials licensed under the
> AGPL, your software will be automatically licensed under the AGPL and
> needs to be made available to everyone who is a recipient of your new
> or modified software or interacts with it remotely over a network.

algod-rust does all three of the triggering things named in that
paragraph: it reimplements go-algorand's REST APIs (not merely
interfacing through Algorand's MIT-licensed SDKs), it uses Algorand's
consensus mechanism (the agreement protocol, sortition, VRF-based
committee selection), and it is a new work built directly against
go-algorand's AGPL-licensed source as its reference implementation. The
project owner's decision, recorded in `docs/PHASE15_PROPOSAL.md` and
implemented here, is therefore:

1. **algod-rust as a whole is classified as a modified work based on
   go-algorand, licensed AGPL-3.0-or-later**, preserving go-algorand's
   section 7e Additional Terms (the Algorand trademark reservation) as
   inherited additional terms, exactly as required by AGPL section 7 for
   additional terms attached to material the licensee builds upon.
2. **MIT is preferred wherever legally possible.** Any file that is
   genuinely original work of this project, with no AGPL derivation —
   CI configuration, infrastructure/ops scripts written from scratch,
   planning and validation documentation, fuzz harnesses that merely
   call this project's own library code — is licensed MIT instead.
   **When a file's status is genuinely in doubt, it is classified AGPL,
   not MIT** — over-claiming MIT would misrepresent a derivative work as
   unencumbered, which is the real legal risk here; classifying a
   borderline-original file as AGPL costs only a slightly broader
   copyleft footprint on our own code, a posture the project owner has
   already accepted (decision 4 below).
3. The legal entity for all algod-rust copyright/attribution statements
   is **Algod DAO**.
4. Deriving from go-algorand's AGPL source is accepted and intended —
   this project makes no attempt to reimplement Algorand's protocol
   "clean room" to avoid the AGPL. See section 4 below (Patent
   rationale) for why that is a deliberate choice, not merely an
   accepted cost.

See [`docs/LICENSING_AUDIT.md`](LICENSING_AUDIT.md) for the full
directory/crate-level table implementing this classification, including
every file that is an exception to its directory's default bucket.

## 2. AGPL section 13: the network-source obligation

AGPL section 13 ("Remote Network Interaction") requires that a modified
version of a covered work, when it supports interaction with users
remotely over a network, must "prominently offer all users interacting
with it remotely... an opportunity to receive the Corresponding Source of
your version by providing access to the Corresponding Source from a
network server at no charge." go-algorand's own `COPYING_FAQ` (item 3)
restates this obligation in plain language:

> It is your responsibility to make sure that your users know that the
> source code is available. You need to prominently include a "download
> source" button or link on your website, such as where programs are
> downloaded, and in the user interface of any software that interacts
> with your modified code. The "download source" button must allow
> anyone to directly download the exact source code and applicable
> cryptographic keys needed to install or use the modified AGPL
> software. You cannot remove the "download source" button or link.

**What algod-rust does today to satisfy this, stated honestly:** the
repository itself is public at
`https://github.com/xarmian/algod-rust`, and this PR adds a README
"Licensing" section pointing to it, `COPYING`, and this document. That
satisfies the obligation for anyone who *finds the repository*. It does
**not** yet satisfy the obligation for a user who only *interacts with a
running algod-rust node* (e.g. over its REST API or P2P/gossip
interfaces) without independently knowing where the source lives — the
FAQ's requirement is specifically that the "download source" pointer be
reachable from the running, user-facing software itself. **No such
in-node mechanism (a `source` field on `/versions`, a startup banner
line, or equivalent) exists in algod-rust as of this PR.** This is
recorded here as an honest gap, not papered over: implementing a
verified, correctly-wired source-pointer surface in the running node is
explicitly deferred as follow-up scope to a later part of
[#731](https://github.com/xarmian/algod-rust/issues/731) /
[epic #732](https://github.com/xarmian/algod-rust/issues/732), so it can
be implemented and tested as a proper code change rather than bundled
into this docs/license-files-only PR.

## 3. Trademark posture

The AGPL itself grants no trademark rights, and go-algorand's section 7e
Additional Terms (preserved verbatim in algod-rust's `COPYING`) make this
explicit:

> Algorand Foundation Ltd. ("Algorand") owns all rights, title and
> interest in and to the Algorand trademarks including, without
> limitation, the trademark ALGORAND, and any other trademarks owned or
> used by Algorand now or in the future... Nothing contained herein
> shall grant to Licensee any rights, title or interest in or to,
> including the right to use, the Algorand Trademarks. Licensee may
> request the right to use the Algorand Trademarks by contacting
> Algorand at legal@algorand.foundation.

algod-rust claims no Algorand trademark rights. Nominative/descriptive
references such as "a Rust reimplementation of go-algorand" or
"compatible with the Algorand protocol" are used throughout this
project's documentation instead of any implication of official
endorsement. Any permission to use the Algorand trademarks — should it
ever be needed for this project — must be requested from Algorand
directly at the address quoted above (`legal@algorand.foundation`, taken
verbatim from go-algorand's own `COPYING`); no other contact is invented
or assumed here. This is a matter for the project owner to pursue, not
something this document or any part of this phase decides unilaterally.

## 4. Patent rationale

go-algorand's `COPYING_FAQ` (item 6, "What about patents?") states:

> While Algorand and the Algorand consensus protocol are protected by
> patent rights, anyone using our code under the MIT, AGPL or a
> commercial license from us has a patent license... Re-implementations
> of the Algorand consensus protocol or other Algorand technology
> protected by patent rights require a separate patent license unless
> they use Algorand source code.

This is recorded here as a **deliberate reason for**, not merely a
consequence of, algod-rust's AGPL-derivative classification: because
algod-rust is developed directly against go-algorand's AGPL-licensed
source (rather than as a clean-room reimplementation of the protocol
from specifications alone), it falls within "anyone using our code under
the... AGPL" and therefore carries the patent license the FAQ describes.
A clean-room reimplementation of the same consensus mechanism, by
contrast, would need to separately negotiate a patent license per the
FAQ's own terms. Accepting the AGPL derivation (decision 4 in section 1
above) is therefore the path that secures patent coverage for this
project's reimplementation of Algorand's consensus mechanism, not just
an incidental side effect of following go-algorand's source too closely.

## 5. Third-party attributions

algod-rust ports a small number of algorithms from sources that are
neither its own original work nor go-algorand itself. Each is classified
AGPL *as part of* the algod-rust crate/file it lives in (per section 1's
rule — the surrounding code is itself AGPL-derived integration/consensus
work), while separately carrying its own upstream attribution obligation.
The full file-level detail is in `docs/LICENSING_AUDIT.md`; the
obligations themselves are recorded here:

### gnark-crypto v0.18.1 (Apache License 2.0) — poseidon2

The poseidon2 AVM opcode (`0xe7`, TEAL v13+, added in issue #665 / PR
#689) in `crates/core/algo-avm/src/ops/crypto.rs` is hand-ported from
**gnark-crypto v0.18.1** (`github.com/consensys/gnark-crypto`), Copyright
ConsenSys Software Inc., licensed under the **Apache License, Version
2.0**. Apache-2.0 requires (per its section 4) that a NOTICE file's
attribution content be preserved in redistributions "in any form" that
includes such a NOTICE from the original work. This attribution
satisfies that obligation for the ported portion:

> This file contains a Rust port of the Poseidon2 permutation
> implementation from **gnark-crypto v0.18.1**
> (`github.com/consensys/gnark-crypto`), Copyright ConsenSys Software
> Inc., licensed under the Apache License, Version 2.0
> (http://www.apache.org/licenses/LICENSE-2.0).

The specific functions covered are listed in
`docs/LICENSING_AUDIT.md`. A per-file header carrying this same
attribution text is scoped to the later per-file-header sweep (see "not
in this PR" below); it is recorded here now so the obligation is not
lost between parts of this phase.

### go-sumhash (MIT)

`crates/core/algo-consensus-crypto/src/sumhash.rs` reimplements the
Sumhash-512 algorithm and Algorand-specific parameters (seed
`b"Algorand"`, n=8, m=1024) matching **`github.com/algorand/go-sumhash`**
— one of the MIT-licensed "SDKs, example applications, and helper
libraries" go-algorand's own `COPYING_FAQ` (item 1) names explicitly.
MIT's only obligation is preserving the copyright/permission notice in
redistributions; that attribution is recorded here and will be carried
in the file's header in the later per-file-header sweep:

> This file reimplements the Sumhash-512 algorithm and Algorand's
> parameters for it, matching `github.com/algorand/go-sumhash`
> (MIT License).

### algorand/falcon v0.1.0 (MIT) — vendored C sources

The vendored Falcon-1024 C implementation under
`crates/core/algo-falcon/falcon-c/` is taken verbatim from
**`github.com/algorand/falcon` v0.1.0**. Unlike the Go wrapper module
of the same name (which carries "This file is part of go-algorand"
AGPL headers), the vendored C sources themselves are MIT-licensed: the
original Falcon reference implementation is Copyright (c) 2017–2019
Falcon Project, and Algorand's deterministic-mode extensions on top of
it are Copyright (c) Algorand, Inc., both under the MIT license. This is
already stated correctly in `crates/core/algo-falcon/falcon-c/LICENSE`
and in the individual `.c`/`.h` file headers — no changes were needed
during this audit. The surrounding Rust FFI integration
(`crates/core/algo-falcon/src/lib.rs`, `build.rs`) is classified AGPL as
part of algod-rust's consensus-critical integration work (see
`docs/LICENSING_AUDIT.md`), but the vendored C library it wraps keeps
its own, narrower MIT license standing on its own.

### Nothing else identified

The audit in `docs/LICENSING_AUDIT.md` did not surface any other
third-party-derived source beyond the three above (no `libsodium-fork`,
`secp256k1`, or `util/bloom` derivation was found in algod-rust's own
code — those are go-algorand's *own* vendored dependencies, not
anything algod-rust vendors or ports).

## Not in this PR (deferred to later parts of #731 / #732)

This document and the accompanying audit table are the foundation for,
but do not themselves include:

- Per-file SPDX license headers implementing the audit's classification
  (including the specific attribution text quoted in section 5 above).
- `license` SPDX fields in every crate's `Cargo.toml`.
- `CLAUDE.md` / `.claude/skills/*` updates so future files get the
  correct header at creation time.
- A CI header-presence check.
- The Rust dependency-tree license-compatibility check.
- The verified, wired-up in-node source-availability pointer discussed
  in section 2 above.

These are explicitly out of scope for this PR so it stays reviewable as
a docs/license-files-only change; they are tracked as remaining work
under epic #732.
