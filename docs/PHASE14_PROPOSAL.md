# Phase 14 Proposal — go-algorand v5.0.0-stable Parity

Phase 14 moves algod-rust's parity target from go-algorand `v4.7.4-stable`
to `v5.0.0-stable`, a consensus-upgrade release (V41 → **V42**) bringing
native post-quantum (Falcon-1024) account signatures, big-transaction
size pricing, AVM v13, a new `SelectF128` sortition algorithm, a new
`GET /v2/node/peers` endpoint, and removal of the `dryrun` REST endpoint.

Tracking epic: [#678](https://github.com/xarmian/algod-rust/issues/678).

## Scope

`TAGS_IN_RANGE` = `v4.7.4-beta` → `v5.0.0-beta` → `v5.0.0-stable`
(`OLD` = `v4.7.4-stable`, `NEW` = `v5.0.0-stable`). `v4.7.4-beta`'s only
change ("checks: recompute group IDs") was already implemented in Phase 13
(issue #649). Every other feature in this range originates at
`v5.0.0-beta`, the first pre-release carrying AVM v13 / consensus v42, and
also reaches `v5.0.0-stable`.

Upstream release notes for `v5.0.0-stable` (`gh release view v5.0.0-stable
-R algorand/go-algorand`) list every change also present in `v5.0.0-beta`'s
own notes — the two releases' changelogs are identical, confirming
`v5.0.0-beta` is where this range's real work landed and `v5.0.0-stable`
only stabilizes it. A line-by-line completeness check against both
releases' New Features / Enhancements / Bugfixes sections found no bullet
unaccounted for in the classified inventory below.

### Classified inventory

**consensus-critical**
- Consensus v42 parameter sweep — #658
- Post-quantum Falcon-1024 account signatures (PQSig/PQAddress/PQDelegatedProgram) — #660
- Falcon-1024 seed size (48→32) + sign-message convention fix — #663
- Big-transaction size pricing (MaxAbsolute* limits, per-byte surcharge, FeeForUsage rounding) — #657
- AVM inner-txn fee-residue threading (itxn_submit) + fee-shortfall message — #677
- Heartbeat explicit HbChallengeDiscount field — #668
- app_params_set opcode + ForeignBoxReads/FamilyBoxAccess fields + multi-byte opcode dispatch — #659
- Nine app_box_* foreign-box opcodes + authorization/reentrancy guard — #662
- Poseidon2 hash opcode — #665
- Variable-length (varint) branch encoding (bnz/bz/b/callsub) — #661
- Auto-salt TEAL v13 programs (`#pragma autosalt`) — #664
- Byte-constant size-limit enforcement + falcon_verify signature-type audit — #666
- sha512/sumhash512 opcode cost formula bugfix — #669
- gload/gloads nil-pastScratch fix — #670
- Assembler match-opcode type tracking + deadcode disassembly fix — #672
- SelectF128 sortition port (128-bit software-float binomial CDF) — #667
  — **highest consensus risk in this epic**: replaces the hardware-double
  binomial-CDF committee-selection weight function with a bit-identical
  pure-software 128-bit float implementation. A wrong port causes algod-rust
  to disagree with the network on committee membership once v42 activates.
- Application-update LocalStateSchema immutability check — #675

**api**
- Simulate API fee-usage reporting — #671
- GET /v2/node/peers + POST /v2/node/shutdown canonical route — #673
- Remove dryrun REST endpoint — #674

**behavioral-other**
- FNet consensus version table entries (robustness) — #676

**not-applicable** (reviewed, no algod-rust action needed)

| Upstream change | Justification |
|---|---|
| `interface{}` → `any` Go idiom sweep | Cosmetic lint, zero behavior change |
| OneTimeSignature always-batch-verify (#6635) | Perf-only; batch verify is mathematically equivalent to individual verify for correctly-parameterized ed25519, no consensus-semantics change |
| Network DNS bootstrap hardening (#6652) | Operational/logging robustness only, no wire-protocol change |
| Network DNS fallback-resolver panic fix (#6654) | Crash-prevention only, no observable behavior change |
| `goal` CLI: empty refs flag (#6633) | CLI/libgoal convenience; algod-rust has no `goal` CLI |
| `goal` CLI: asset-info reserve-holds-nothing fix (#6662) | CLI-only |
| `tealdbg` removal | algod-rust never implemented tealdbg; nothing to remove |
| Build/tooling: dependabot bumps (#6686, #6660), locate e2e binaries via `go env` (#6638), rebuild libsodium tree (#6616), fix allocbound directive lookup (#6615), bump msgp to v1.1.63 (#6647), default Cloudflare DNS TTL (#6630) | Pure Go build/CI/tooling, no runtime behavior to port |
| Catchup: log early-exit reason at Info level (#6655) | Log-level change only |
| Chore: export PQSig to SDK signature.go (#6683) | algosdk (client SDK) change, not algod itself |
| Chore: ensure heartbeat lsig is an invalid ed25519 point (#6628) | Node-local heartbeat-service key-generation robustness, not consensus-relevant |
| Crypto: use specific error assertions in tests (#6543) | go-algorand test-only change |
| Docs: add more data to langspec.json files (#6617) | Docs/metadata only, no semantic change |
| Docs: clarify MiMC/Poseidon2 input requirements (#6680) | Doc clarification, already reflected in #665's semantics |

## Non-goals

Everything in the not-applicable table above. In particular: algod-rust
will not implement a `goal` CLI or `tealdbg`, and will not port go-algorand
build-tooling/CI changes that have no runtime-behavior counterpart.

## Success criteria

- All 21 sub-issues under epic #678 merged (or honestly disposed per this
  repo's issue-disposition rules).
- Version pin swept to `v5.0.0-stable` across the repo.
- Full gate green on `main`; live mixed-cluster verification against
  go-algorand `v5.0.0-stable` Go nodes, with particular attention to
  `SelectF128` committee-selection agreement (#667).
- `docs/PHASE14_VALIDATION.md` written at close-out.
- Hard gate: `gh issue list --label "phase:14" --state open` empty before
  the epic closes.
