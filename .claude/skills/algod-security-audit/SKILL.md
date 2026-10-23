---
name: algod-security-audit
description: Execute a formal security, soundness and consensus-parity audit of algod-rust following audits/instructions.md (v2.0), write a chronologically ordered report in audits/reports/YYYY-MM-DD_HHMMSS_<auditor-tag>_<git-short-hash>.md, and update audits/risks.md and audits/coverage.md. Triggered whenever the user says "do new audit", "run a new audit", "perform security audit", or asks to execute an audit pass.
---

# Algod-Rust Security Audit Execution (`do new audit`)

Use this skill whenever the user says **"do new audit"** (or asks to run/perform a new security audit, optionally naming a scope such as a crate, area id `A-NN`, PR, or "delta").

The authoritative procedure is `audits/instructions.md` §10. This skill is a checklist for executing it; when the two differ, `audits/instructions.md` wins.

## Non-negotiables

- **You audit the code yourself.** Do not delegate the audit to a sub-agent. Read the Rust and the pinned go-algorand side by side.
- **Evidence only.** Every finding and every verified invariant cites a real `path:Lx-Ly` re-read from the working tree in this run, plus the go-algorand oracle location where parity is the question. No recalled line numbers, no fabricated commands or outputs.
- **Observe, don't modify.** Never edit `crates/`, `bin/`, `fuzz/`, or `docs/` during an audit. PoCs go in `audits/poc/<report-id>/`.
- **Confidence drives severity.** Critical requires a Confirmed PoC. High reported as Open requires Confirmed, or Likely with a line-by-line trace. Speculative items go to the report's §9, not to Findings.
- **Public repo — embargo rule.** If any finding is Critical or High with Confirmed confidence, write the report but **do not commit, push, or open a GitHub issue** for it. End your turn by telling the user which finding ids are embargoed and that they must deliver the report privately (instructions §8).

## Workflow

1. **Load state.** Read `audits/instructions.md`, `audits/risks.md`, `audits/coverage.md`; list `audits/reports/`; read the two most recent reports in full for de-duplication and the regression check.
2. **Provenance.** Record `git rev-parse --short HEAD`, `git rev-parse HEAD`, `git branch --show-current`, `git status -s`, `git -C ../go-algorand describe --tags --exact-match` (must be `v5.0.4-stable`; otherwise stop and report), `date -u +%Y-%m-%d_%H%M%S`, `rustc --version`. On Windows use the repo's MSVC environment notes in `CLAUDE.md` for cargo.
3. **Auditor tag.** Lowercase kebab-case identifying the model or person (e.g. `claude-fable-5-1`); never a generic tag. Use the user's tag if given.
4. **Scope.** Apply instructions §5 against `audits/coverage.md`: user-named scope, else 2–4 areas chosen by never-audited → changed-since-last-audit → oldest, Tier 1 first. Always include `A-00 Delta` (diff of `crates/core/**` since the last report's commit). Write the scope and justification down before deep reading.
5. **Audit.** Apply at least four of M1–M8 (M1 and M2 mandatory for Tier 1). For AVM/ledger areas walk the §3.2 smart-contract rule catalogue and classify each rule PASS (file:line) / finding / not examined. Trace panic/overflow candidates from ingress to sink. Run `cargo test -p <crate>` for the area and read what the tests actually assert. Check `docs/DIVERGENCES.md` before calling any difference a bug. Log every command and file range as you go.
6. **De-duplicate** candidates against prior reports and `risks.md` `Linked Audit Findings`.
7. **Write the report** at `audits/reports/YYYY-MM-DD_HHMMSS_<auditor-tag>_<git-short-hash>.md` with all nine sections of instructions §7.2, then check it against the §7.3 quality bar.
8. **Update `audits/risks.md`** (`Last Updated`, `Last Audited Commit`, new/adjusted `RISK-*` rows, `Linked Audit Findings`, Audit History row) and **`audits/coverage.md`** (only the `A-NN` rows and §3.2 rule rows you covered: date, commit, tag, methodologies, depth, report).
9. **Disclosure gate.** Embargoed findings (see Non-negotiables): stop, report to the user, do not commit. Otherwise file one GitHub issue per Medium+ finding via the `algod-issue-create` skill (label `security`, cite the `FIND-` id and report path) and record the numbers in the report.
10. **Final message.** Report path, severity table, embargo status, `A-NN` rows changed, and the single most valuable next scope.
