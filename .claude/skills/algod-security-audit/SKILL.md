---
name: algod-security-audit
description: Execute a formal security and consensus-parity audit of algod-rust following audits/instructions.md, write a chronologically ordered report in audits/reports/YYYY-MM-DD_HHMMSS_<auditor-tag>_<git-short-hash>.md, and update the risk registry in audits/risks.md. Triggered whenever the user says "do new audit", "run a new audit", "perform security audit", or asks to execute an audit pass.
---

# Algod-Rust Security Audit Execution (`do new audit`)

Use this skill whenever the user says **"do new audit"** (or asks to run/perform a new security audit).

## Mandatory Workflow

1. **Load Audit Instructions & Current Risk State**
   - Read `audits/instructions.md` to review the 5 core security properties, the Tier 1–3 crate scope matrix, the 6 audit methodologies (`M1`–`M6`), the industry-standard severity rubric (Critical / High / Medium / Low / Informational), and the mandatory report template.
   - Read `audits/risks.md` to review existing controllable (`RISK-INT-NNN`) and uncontrollable (`RISK-EXT-NNN`) risks and the **Audit History & Synchronization Log** table.
   - List existing files in `audits/reports/` to see what scopes and commits were covered in previous audit passes.

2. **Determine Audit Metadata & Target Scope**
   - Obtain the current git metadata:
     - Short commit hash: `git --no-pager rev-parse --short HEAD`
     - Full commit SHA: `git --no-pager rev-parse HEAD`
     - Working tree status: `git --no-pager status -s`
   - Obtain the current UTC timestamp formatted as `YYYY-MM-DD_HHMMSS` for the filename and `YYYY-MM-DDTHH:MM:SSZ` for the report metadata.
   - Choose an `<auditor-tag>` in lowercase kebab-case (e.g., `sec-audit-core`, `sec-audit-avm`, `sec-audit-consensus`, `sec-audit-network`, or a custom tag if specified by the user).
   - Select the target scope:
     - If the user named a specific crate, PR, or subsystem, audit that scope.
     - If the user simply said `"do new audit"`, select the highest-priority Tier 1 or Tier 2 crates that have not yet been audited (or have changed since the last audit commit in `audits/reports/`).

3. **Execute Multi-Methodology Security Audit (`M1`–`M6`)**
   - Apply **at least three** methodologies defined in `audits/instructions.md` Section 3:
     - **M1:** Differential specification analysis against `../go-algorand` (`v5.0.4-stable`).
     - **M2:** Static analysis, `unsafe` review, and panic/unwrap/indexing surface audit in non-test code.
     - **M3:** Cryptographic domain separation, canonicality, constant-time, and key zeroization audit.
     - **M4:** Fuzzing target coverage and boundary-value invariant analysis.
     - **M5:** Adversarial Byzantine (`BA*`) and P2P/gossip fault analysis.
     - **M6:** Economic, MBR, and AVM opcode resource-metering vs CPU/memory DoS analysis.
   - Check `docs/DIVERGENCES.md` (`DIV-001`, `DIV-002`, etc.) before classifying any intentional divergence as a bug; instead, verify that the divergence upholds its `"Wire / consensus impact: none"` invariant.
   - Every finding and every verified invariant **must** cite exact file paths and 1-based line numbers in the repository.

4. **Create the Chronological Audit Report in `audits/reports/`**
   - Create a new Markdown file at:
     `audits/reports/YYYY-MM-DD_HHMMSS_<auditor-tag>_<git-short-hash>.md`
   - Follow the exact 6-section template in `audits/instructions.md` Section 5.2:
     1. Audit Metadata & Provenance
     2. Executive Summary (with severity count table)
     3. Scope & Methodology Execution Log
     4. Detailed Findings (`[FIND-<hash>-NN]`)
     5. Invariant & Parity Verification Checklist
     6. Risk Registry Delta (`audits/risks.md` Updates)

5. **Update `audits/risks.md` (Mandatory)**
   - Update `Last Updated` and `Last Audited Commit` at the top of `audits/risks.md`.
   - For any new vulnerabilities or risk vectors identified, add or update the corresponding `RISK-INT-NNN` (controllable) or `RISK-EXT-NNN` (uncontrollable) row in `audits/risks.md`, linking the `FIND-<hash>-NN` IDs in the `Linked Audit Findings` column.
   - Append a new entry to **Section 4: Audit History & Synchronization Log** in `audits/risks.md` linking the newly created report file (`audits/reports/YYYY-MM-DD_HHMMSS_<auditor-tag>_<git-short-hash>.md`), auditor tag, git short hash, scope, finding counts, and risk changes.
