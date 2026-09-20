# Test-parity delta: go-algorand `v5.0.1-stable` → `v5.0.2-stable`

_Generated 2026-09-20 by `scripts/phase17_parity_delta.py report`._

| metric | count |
|---|---:|
| Go tests in `v5.0.1-stable` | 3177 |
| Go tests in `v5.0.2-stable` | 3190 |
| added | 14 |
| removed | 1 |
| moved (file rename, same name) | 0 |
| body changed (existing rows to re-verify) | 7 |

## Added in `v5.0.2-stable` (14)

Each needs a new row in the listed `parity_<area>.md` with an honest status. A `missing-test`/`not-implemented`/`partial` classification is a sub-issue of the upgrade epic, not a resting state.

| go-algorand test | package | area file |
|---|---|---|
| [TestBundleFreshDiscardsStaleCertBundle](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/bundleFresh_test.go#L33) | `agreement` | `parity_agreement.md` |
| [TestBundleVerifyRejectsStepAboveDown](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/bundle_test.go#L72) | `agreement` | `parity_agreement.md` |
| [TestCryptoRequestContextCleanupByRoundPinnedBundle](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/cryptoRequestContext_test.go#L263) | `agreement` | `parity_agreement.md` |
| [TestCryptoVerifierBundleContextIsolation](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/cryptoVerifier_test.go#L419) | `agreement` | `parity_agreement.md` |
| [TestCryptoVerifierBundleContextBound](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/cryptoVerifier_test.go#L479) | `agreement` | `parity_agreement.md` |
| [TestCryptoVerifierBundleContextCleanupByRound](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/cryptoVerifier_test.go#L503) | `agreement` | `parity_agreement.md` |
| [TestCryptoVerifierFutureBundleVerification](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/cryptoVerifier_test.go#L544) | `agreement` | `parity_agreement.md` |
| [TestProposalCarriesMalformedStateProofPath](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/message_test.go#L39) | `agreement` | `parity_agreement.md` |
| [TestDecodeRejectsStepAboveDown](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/message_test.go#L177) | `agreement` | `parity_agreement.md` |
| [TestVoteVerifyRejectsStepAboveDown](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/vote_test.go#L284) | `agreement` | `parity_agreement.md` |
| [TestVerifyRejectsOversizedPathElement](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/crypto/merklearray/merkle_test.go#L349) | `crypto/merklearray` | `parity_crypto.md` |
| [TestToBeHashedDoesNotEraseSibling](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/crypto/merklearray/merkle_test.go#L889) | `crypto/merklearray` | `parity_crypto.md` |
| [TestVerifyStateProofAlgorithms](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/crypto/stateproof/verifier_test.go#L193) | `crypto/stateproof` | `parity_crypto.md` |
| [TestCheckTxnGroupStateProofBasicSuite](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/data/transactions/checks_test.go#L53) | `data/transactions` | `parity_txn_core.md` |

## Removed in `v5.0.2-stable` (1)

Delete each row (the go test no longer exists at the pin). If the matched Rust test proved behavior go-algorand deliberately dropped, that is an upstream behavior change — make sure a Stage 2/3 issue covers it.

| go-algorand test (OLD) | row(s) |
|---|---|
| `agreement/cryptoRequestContext_test.go` `TestCryptoRequestContextCleanupByRoundPinnedCertify` | `docs/phase17/parity_agreement.md:35` |

## Moved (0)

`repin` rewrites these links automatically; listed for the record.

_none_

## Body changed — re-verify the mapped Rust test(s) (7)

For each: read `git -C ../go-algorand diff OLD NEW -- <file>` around the function. If go-algorand added/changed an assertion, the mapped Rust test must gain the same assertion (or the row honestly drops to `partial` and becomes a sub-issue). Update the row's notes with what was re-checked.

| go-algorand test | current status | row |
|---|---|---|
| [TestCryptoRequestContextAddCancelPeriod](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/cryptoRequestContext_test.go#L74) | matched-1:1 | `docs/phase17/parity_agreement.md:29` |
| [TestCryptoRequestContextAddCancelRound](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/cryptoRequestContext_test.go#L35) | matched-1:1 | `docs/phase17/parity_agreement.md:28` |
| [TestCryptoRequestContextCleanupByPeriod](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/cryptoRequestContext_test.go#L326) | matched-1:1 | `docs/phase17/parity_agreement.md:36` |
| [TestCryptoRequestContextCleanupByPeriodPinned](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/cryptoRequestContext_test.go#L388) | matched-many:1 | `docs/phase17/parity_agreement.md:37` |
| [TestCryptoRequestContextCleanupByRound](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/cryptoRequestContext_test.go#L210) | matched-1:1 | `docs/phase17/parity_agreement.md:34` |
| [TestCryptoVerifierVerificationErrs](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/cryptoVerifier_test.go#L395) | matched-1:many | `docs/phase17/parity_agreement.md:39` |
| [TestVoteValidationStepCertAndProposalBottom](https://github.com/algorand/go-algorand/blob/v5.0.2-stable/agreement/vote_test.go#L253) | matched-1:1 | `docs/phase17/parity_agreement.md:329` |

