# Test-parity delta: go-algorand `v5.0.5-stable` → `v5.1.1-stable`

_Generated 2026-11-22 by `scripts/phase17_parity_delta.py report`._

| metric | count |
|---|---:|
| Go tests in `v5.0.5-stable` | 3194 |
| Go tests in `v5.1.1-stable` | 3397 |
| added | 294 |
| removed | 91 |
| moved (file rename, same name) | 0 |
| body changed (existing rows to re-verify) | 234 |

## Added in `v5.1.1-stable` (294)

Each needs a new row in the listed `parity_<area>.md` with an honest status. A `missing-test`/`not-implemented`/`partial` classification is a sub-issue of the upgrade epic, not a resting state.

| go-algorand test | package | area file |
|---|---|---|
| [TestDemuxTokenizerRejectsStepAboveDown](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/demux_test.go#L739) | `agreement` | `parity_agreement.md` |
| [TestProposalQueueSourceIsRoutingAddr](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/gossip/proposalQueue_test.go#L41) | `agreement/gossip` | `parity_agreement.md` |
| [TestProposalGroupRuleFollowsProtocol](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/message_test.go#L283) | `agreement` | `parity_agreement.md` |
| [TestPlayerIgnoresStaleCertBundle](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/player_test.go#L4035) | `agreement` | `parity_agreement.md` |
| [TestPlayerConsumesCertBundleOnePeriodBehind](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/player_test.go#L4078) | `agreement` | `parity_agreement.md` |
| [TestRouterUpdateGarbageCollection](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/router_gc_test.go#L64) | `agreement` | `parity_agreement.md` |
| [TestRouterUpdateKeepsChildIdentity](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/router_gc_test.go#L139) | `agreement` | `parity_agreement.md` |
| [TestAgreementFutureBundlesDoNotCancelPayloadVerification](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/service_test.go#L2646) | `agreement` | `parity_agreement.md` |
| [TestVoteAggregatorFiltersStaleCertBundle](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/voteAggregator_test.go#L915) | `agreement` | `parity_agreement.md` |
| [TestMarshalUnmarshalsaltedPublicMaterial](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/msgp_gen_test.go#L16) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestRandomizedEncodingsaltedPublicMaterial](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/msgp_gen_test.go#L37) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestMarshalUnmarshalsaltedSigningMaterial](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/msgp_gen_test.go#L76) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestRandomizedEncodingsaltedSigningMaterial](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/msgp_gen_test.go#L97) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedKeySeedDerivationUsesDomainSchemeAndEntropy](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L89) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedGenerateUsesMnemonicSizedEntropy](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L110) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSigSchemeRegistriesConsistent](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L178) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSigSchemeKeySizes](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L192) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestParseSigSchemeAcceptsLongName](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L204) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestFormatSigScheme](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L233) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedPrivateKeyFileStoresKeysNotEntropy](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L243) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedKeyFileRejectsMalformedInputs](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L274) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedMnemonicImport](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L305) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedImportRejectsMalformedMnemonic](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L323) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedImportRejectsUnknownScheme](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L335) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedPrintMnemonic](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L351) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedCommandFlagShorthands](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L365) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedCommandKeepsPQAlias](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L393) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSigSchemeFlagHasNoDefault](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L404) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSigSchemeMustMatchKeySource](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L414) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedSignProducesVerifiableSaltedKeySig](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L437) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedSignAcceptsMnemonic](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L492) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedSignRejectsUnsupportedMnemonicScheme](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L529) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedSignRejectsEmptyInputFile](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L546) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedSignSetsAndClearsAuthAddr](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L569) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedSignRejectsMixedSignaturesUnlessOverwrite](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L628) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedSignRejectsOnCurveSalt](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L664) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedDecodePrivateKeyRejectsMnemonic](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L688) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedSignProgramProducesVerifiableDelegatedLogicSig](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L696) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedSignProgramAcceptsMnemonic](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L747) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedSignProgramRejectsMixedKeySources](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L787) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedSignProgramRejectsEmptyInputFile](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L808) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedSignProgramRejectsTealSource](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L827) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestSaltedCheckAddress](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/algokey/salted_test.go#L864) | `cmd/algokey` | `parity_tools_cmd.md` |
| [TestReadBlockFile](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/catchupsrv/main_test.go#L30) | `cmd/catchupsrv` | `parity_tools_cmd.md` |
| [TestIsPartkeyRegistered](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/goal/account_test.go#L28) | `cmd/goal` | `parity_tools_cmd.md` |
| [TestAuthorizeWithProgram](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/goal/clerk_test.go#L39) | `cmd/goal` | `parity_tools_cmd.md` |
| [TestEnsureAndResolveGenesisDirs_migrateRestart](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/config/config_test.go#L1045) | `config` | `parity_config_proto_sp.md` |
| [TestSigSchemeLogicSigParams](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/config/consensus_test.go#L66) | `config` | `parity_config_proto_sp.md` |
| [TestVerifyFalconRejectsMalformedInputs](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/falconWrapper_test.go#L168) | `crypto` | `parity_crypto.md` |
| [TestCommitmentFormatsAsHex](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/merklesignature/merkleSignatureScheme_test.go#L120) | `crypto/merklesignature` | `parity_crypto.md` |
| [TestMarshalUnmarshalFalcon1024PrivateKey](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L76) | `crypto` | `parity_crypto.md` |
| [TestRandomizedEncodingFalcon1024PrivateKey](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L97) | `crypto` | `parity_crypto.md` |
| [TestMarshalUnmarshalFalcon1024PublicKey](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L136) | `crypto` | `parity_crypto.md` |
| [TestRandomizedEncodingFalcon1024PublicKey](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L157) | `crypto` | `parity_crypto.md` |
| [TestMarshalUnmarshalFalcon1024Signer](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L196) | `crypto` | `parity_crypto.md` |
| [TestRandomizedEncodingFalcon1024Signer](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L217) | `crypto` | `parity_crypto.md` |
| [TestMarshalUnmarshalFalcon1024Verifier](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L256) | `crypto` | `parity_crypto.md` |
| [TestRandomizedEncodingFalcon1024Verifier](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L277) | `crypto` | `parity_crypto.md` |
| [TestMarshalUnmarshalFalcon512PrivateKey](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L316) | `crypto` | `parity_crypto.md` |
| [TestRandomizedEncodingFalcon512PrivateKey](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L337) | `crypto` | `parity_crypto.md` |
| [TestMarshalUnmarshalFalcon512PublicKey](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L376) | `crypto` | `parity_crypto.md` |
| [TestRandomizedEncodingFalcon512PublicKey](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L397) | `crypto` | `parity_crypto.md` |
| [TestMarshalUnmarshalFalcon512Signer](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L436) | `crypto` | `parity_crypto.md` |
| [TestRandomizedEncodingFalcon512Signer](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L457) | `crypto` | `parity_crypto.md` |
| [TestMarshalUnmarshalFalcon512Verifier](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L496) | `crypto` | `parity_crypto.md` |
| [TestRandomizedEncodingFalcon512Verifier](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L517) | `crypto` | `parity_crypto.md` |
| [TestMarshalUnmarshalOneTimeSignatureSecretsHeader](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L974) | `crypto` | `parity_crypto.md` |
| [TestRandomizedEncodingOneTimeSignatureSecretsHeader](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/msgp_gen_test.go#L995) | `crypto` | `parity_crypto.md` |
| [TestHeaderRoundTrip](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/onetimesigpersist_test.go#L48) | `crypto` | `parity_crypto.md` |
| [TestFromRowsValidation](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/onetimesigpersist_test.go#L94) | `crypto` | `parity_crypto.md` |
| [TestSnapshotStableUnderConcurrentDelete](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/onetimesigpersist_test.go#L145) | `crypto` | `parity_crypto.md` |
| [TestWordlist](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/passphrase/passphrase_test.go#L162) | `crypto/passphrase` | `parity_crypto.md` |
| [TestSigSchemeVerifierEd25519](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/sig_scheme_test.go#L27) | `crypto` | `parity_crypto.md` |
| [TestSigSchemeVerifierFalconRoundTrip](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/sig_scheme_test.go#L48) | `crypto` | `parity_crypto.md` |
| [TestStateProofString](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/stateproof/prover_test.go#L706) | `crypto/stateproof` | `parity_crypto.md` |
| [TestByteTypesFormatAsHex](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/util_test.go#L85) | `crypto` | `parity_crypto.md` |
| [TestJSONSerializer](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/server/json_test.go#L52) | `daemon/algod/api/server` | `parity_daemon_node.md` |
| [TestPostTransactionOffCurveAuthorizers](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/server/v2/test/handlers_test.go#L1297) | `daemon/algod/api/server/v2/test` | `parity_daemon_node.md` |
| [TestPostTransactionAsyncOffCurveAuthorizers](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/server/v2/test/handlers_test.go#L1502) | `daemon/algod/api/server/v2/test` | `parity_daemon_node.md` |
| [TestPostSimulateTransactionPlaceholderSaltedKeySignatureValidation](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/server/v2/test/handlers_test.go#L1657) | `daemon/algod/api/server/v2/test` | `parity_daemon_node.md` |
| [TestMarshalUnmarshalSimulateRequest](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/spec/v2/msgp_gen_test.go#L136) | `daemon/algod/api/spec/v2` | `parity_daemon_node.md` |
| [TestRandomizedEncodingSimulateRequest](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/spec/v2/msgp_gen_test.go#L157) | `daemon/algod/api/spec/v2` | `parity_daemon_node.md` |
| [TestMarshalUnmarshalSimulateRequestTraceConfig](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/spec/v2/msgp_gen_test.go#L196) | `daemon/algod/api/spec/v2` | `parity_daemon_node.md` |
| [TestRandomizedEncodingSimulateRequestTraceConfig](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/spec/v2/msgp_gen_test.go#L217) | `daemon/algod/api/spec/v2` | `parity_daemon_node.md` |
| [TestMarshalUnmarshalSimulateRequestTxnGroup](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/spec/v2/msgp_gen_test.go#L256) | `daemon/algod/api/spec/v2` | `parity_daemon_node.md` |
| [TestRandomizedEncodingSimulateRequestTxnGroup](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/spec/v2/msgp_gen_test.go#L277) | `daemon/algod/api/spec/v2` | `parity_daemon_node.md` |
| [TestMarshalUnmarshalSimulateRequestTxnGroups](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/spec/v2/msgp_gen_test.go#L316) | `daemon/algod/api/spec/v2` | `parity_daemon_node.md` |
| [TestRandomizedEncodingSimulateRequestTxnGroups](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/spec/v2/msgp_gen_test.go#L337) | `daemon/algod/api/spec/v2` | `parity_daemon_node.md` |
| [TestVersionsEndpoint](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/api_test.go#L58) | `daemon/kmd/api` | `parity_daemon_node.md` |
| [TestSwaggerEndpoint](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/api_test.go#L79) | `daemon/kmd/api` | `parity_daemon_node.md` |
| [TestOptionsAnyPath](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/api_test.go#L93) | `daemon/kmd/api` | `parity_daemon_node.md` |
| [TestCORS](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/api_test.go#L108) | `daemon/kmd/api` | `parity_daemon_node.md` |
| [TestPNA](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/api_test.go#L148) | `daemon/kmd/api` | `parity_daemon_node.md` |
| [TestRequestCallback](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/api_test.go#L177) | `daemon/kmd/api` | `parity_daemon_node.md` |
| [TestRequestCallbackNotCalledWithoutAuth](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/api_test.go#L195) | `daemon/kmd/api` | `parity_daemon_node.md` |
| [TestRouteStatusCodes](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/api_test.go#L216) | `daemon/kmd/api` | `parity_daemon_node.md` |
| [TestWalletInfoHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L205) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestWalletRenewHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L228) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestWalletReleaseHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L250) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestInvalidHandleToken](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L275) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestGenerateKeyHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L296) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestListKeysHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L319) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestImportKeyHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L345) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestExportKeyHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L372) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestDeleteKeyHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L399) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestExportMasterKeyHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L424) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestSignTransactionHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L450) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestSignProgramHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L487) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestMultisigListHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L518) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestMultisigImportHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L540) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestMultisigExportHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L572) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestDeleteMultisigHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L602) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestMultisigSignTransactionHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L627) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestMultisigSignProgramHandler](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L673) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestWalletErrorResponse](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L717) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestMalformedJSONBody](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L743) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestInvalidAddressFormat](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L762) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestInvalidTransactionEncoding](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L785) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestAuthRejectsNoToken](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L838) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestAuthRejectsWrongToken](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L853) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestAuthAcceptsValidToken](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L869) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestEmptyRequestBody](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L892) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestResponseContentType](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L908) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestErrorResponseContentType](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/kmd/api/v1/handlers_test.go#L926) | `daemon/kmd/api/v1` | `parity_daemon_node.md` |
| [TestRegistryMigrationV1ToV2](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/account/registryVotingRows_test.go#L69) | `data/account` | `parity_data_misc.md` |
| [TestFlushWithoutVotingSecrets](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/account/registryVotingRows_test.go#L178) | `data/account` | `parity_data_misc.md` |
| [TestRegistryKeyLifecycle](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/account/registryVotingRows_test.go#L217) | `data/account` | `parity_data_misc.md` |
| [TestRegisterStaleSnapshotDoesNotTouchVoting](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/account/registryVotingRows_test.go#L279) | `data/account` | `parity_data_misc.md` |
| [TestDeleteExpiredMergesOnlyVoting](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/account/registryVotingRows_test.go#L338) | `data/account` | `parity_data_misc.md` |
| [TestSyncVotingRows](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/account/votingRows_test.go#L80) | `data/account` | `parity_data_misc.md` |
| [TestRegistryWALHoldsNoRetiredSubkeys](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/account/walErase_test.go#L186) | `data/account` | `parity_data_misc.md` |
| [TestRegistryMigrationErasesWAL](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/account/walErase_test.go#L243) | `data/account` | `parity_data_misc.md` |
| [TestSaltedAddressPreimage](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/basics/salted_address_test.go#L49) | `data/basics` | `parity_data_misc.md` |
| [TestSaltedAddressKnownAnswers](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/basics/salted_address_test.go#L89) | `data/basics` | `parity_data_misc.md` |
| [TestCanonicalAddressSalt](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/basics/salted_address_test.go#L270) | `data/basics` | `parity_data_misc.md` |
| [TestLogicSigSaltedAddress](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/basics/salted_address_test.go#L317) | `data/basics` | `parity_data_misc.md` |
| [TestCanonicalAddressSaltDoesNotRequireRegisteredSchemeOrValidatedKey](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/basics/salted_address_test.go#L367) | `data/basics` | `parity_data_misc.md` |
| [TestSeedFormatsAsHex](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/committee/encoding_test.go#L37) | `data/committee` | `parity_data_misc.md` |
| [TestStatusCacheRoundTrip](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/pools/statusCache_test.go#L173) | `data/pools` | `parity_data_misc.md` |
| [TestPoolBlockGeneration](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/pools/transactionPool_generation_test.go#L77) | `data/pools` | `parity_data_misc.md` |
| [TestPoolParticipationChanges](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/pools/transactionPool_generation_test.go#L156) | `data/pools` | `parity_data_misc.md` |
| [TestPoolDevModeForcesGeneration](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/pools/transactionPool_generation_test.go#L210) | `data/pools` | `parity_data_misc.md` |
| [TestPoolSkippedAssemblyWakesWaiter](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/pools/transactionPool_generation_test.go#L229) | `data/pools` | `parity_data_misc.md` |
| [TestPoolAssemblyTimeoutClearsDeadline](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/pools/transactionPool_generation_test.go#L269) | `data/pools` | `parity_data_misc.md` |
| [TestCheckTxnGroupIDDuplicateTxn](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/checks_test.go#L260) | `data/transactions` | `parity_txn_core.md` |
| [TestFalconVerifyNeedsImmediate](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L580) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestFalconVerifyConfigMismatch](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L592) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestMLDSAVerify](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L1253) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestMLDSAVerifyExternalMu](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L1299) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestMLDSAVerifyStack](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L1331) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestMLDSAVerifyCost](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L1356) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestMLDSAVerifyInputs](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L1400) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestMLDSAVerifyVectors](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L1461) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestMLDSAFIPS140v1](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L1524) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestUnaccountedArg](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L299) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestUnaccountedArgFailedRead](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L382) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestEvalSignatureProgramArgs](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L630) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestRapidDivModw](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L1024) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestRapidExpw](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L1045) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestBranchOffsetTruncation](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L3893) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestBytesZeroShared](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5548) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestBytesModExp](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5775) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestCostByLongest](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5997) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestMulComplexity](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L6035) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestRapidAddSubBytes](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L6071) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestRapidBitwise](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L6114) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestRapidNonzero](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L6159) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestCostDynamic](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/opcodes_test.go#L43) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestSKsigDelegatedProgramToBeHashed](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/program_test.go#L29) | `data/transactions/logic` | `parity_txn_logic.md` |
| [TestLogicSigSaltedKeySigMsgpackRoundTrip](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logicsig_test.go#L84) | `data/transactions` | `parity_txn_core.md` |
| [TestLogicSigBlankSaltedKeySigOmitted](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logicsig_test.go#L104) | `data/transactions` | `parity_txn_core.md` |
| [TestMarshalUnmarshalLogicSigArgs](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/msgp_gen_test.go#L794) | `data/transactions` | `parity_txn_core.md` |
| [TestRandomizedEncodingLogicSigArgs](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/msgp_gen_test.go#L815) | `data/transactions` | `parity_txn_core.md` |
| [TestMarshalUnmarshalSaltedKeySig](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/msgp_gen_test.go#L1034) | `data/transactions` | `parity_txn_core.md` |
| [TestRandomizedEncodingSaltedKeySig](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/msgp_gen_test.go#L1055) | `data/transactions` | `parity_txn_core.md` |
| [TestSigSchemesMatchTestSchemes](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sig_scheme_test.go#L32) | `data/transactions` | `parity_txn_core.md` |
| [TestSigSchemeBoundsCoverSchemes](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sig_scheme_test.go#L57) | `data/transactions` | `parity_txn_core.md` |
| [TestSigSchemeLogicSigFee](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sig_scheme_test.go#L78) | `data/transactions` | `parity_txn_core.md` |
| [TestSignedTxnFeeFactorSaltedKeySignatureContribution](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/signedtxn_test.go#L121) | `data/transactions` | `parity_txn_core.md` |
| [TestLogicSigSaltedKeySigFee](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/signedtxn_test.go#L232) | `data/transactions` | `parity_txn_core.md` |
| [TestLogicSigArgsRoundTrip](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L108) | `data/transactions` | `parity_txn_core.md` |
| [TestLogicSigArgsRejectsNonCanonical](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L135) | `data/transactions` | `parity_txn_core.md` |
| [TestLogicSigArgsDecodeBounds](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L161) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigSchemeSizeLimits](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L177) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigDecodeBoundsFeedSignedTxnMaxSize](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L223) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigBlank](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L254) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigEqual](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L268) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigAuthorizerAddress](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L304) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigValidateEnvelope](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L315) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigLogicSigScheme](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L365) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigVerify](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L407) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigBatchPrep](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L417) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigBatchPrepMatchesVerifyEnvelopeErrors](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L435) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigVerifyAcceptsSignatureOverRawTxn](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L473) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigVerifyChecksConsensusParams](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L504) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigVerifyRejectsBlank](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L517) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigVerifyRejectsEmptySignature](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L527) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigVerifyRejectsUnsupportedScheme](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L540) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigVerifyRejectsAuthorizerMismatch](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L554) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigVerifyRejectsMalformedPublicKey](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L568) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigVerifyRejectsMalformedSignature](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L583) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigVerifyRejectsChangedTransaction](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L602) | `data/transactions` | `parity_txn_core.md` |
| [TestSaltedKeySigVerifyRejectsChangedSignature](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/sksig_test.go#L615) | `data/transactions` | `parity_txn_core.md` |
| [TestGetNumberOfBatchableSaltedKeySigs](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txnBatch_test.go#L359) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestNewBlockWatcher](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txnBatch_test.go#L543) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestNewBlockWatcherConcurrent](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txnBatch_test.go#L583) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestProcessBatchEd25519SaltedKeySigAttribution](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txnBatch_test.go#L1184) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnValidationSaltedKeySig](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L388) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnValidationEd25519SaltedKeySig](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L406) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnValidationEd25519SaltedKeySigDelegatedLogicSig](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L422) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnValidationMixedEd25519Batch](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L439) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnValidationEd25519SaltedKeySigRejectsWrongLengths](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L481) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnValidationSaltedKeySigSchemeBoundary](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L511) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnValidationLogicSigSaltedKeySig](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L595) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestLogicSigSaltedKeySigArgAccessGating](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L675) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestLogicSigSaltedKeySigBudget](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L706) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnValidationSaltedKeySigWithAuthAddr](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L738) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnValidationEd25519SigWithSaltedSenderAuthAddr](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L763) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnValidationSaltedKeySigEncodeDecode](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L784) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnValidationSaltedKeySigRejectsMalformedProof](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L802) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnValidationSaltedKeySigDelegatedLogicSig](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L828) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnValidationSaltedKeySigDelegatedLogicSigRejectsInvalidProof](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L846) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnValidationSaltedKeySigDelegatedLogicSigSignsRawProgram](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L931) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnGroupSaltedKeySigMixedSignatures](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L1594) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestLogicSigArgAccess](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L1963) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestVerifiedTxnCtxStaysInline](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/verifiedTxnCache_test.go#L41) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestAddingToCacheOutOfLineSigs](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/verifiedTxnCache_test.go#L81) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestGetUnverifiedTransactionGroupsSaltedKeySigProofChanges](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/verifiedTxnCache_test.go#L202) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestGetUnverifiedTransactionGroupsLogicSigSaltedKeySigChanges](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/verifiedTxnCache_test.go#L270) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestGetUnverifiedTransactionGroupsAuthChanges](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/verifiedTxnCache_test.go#L407) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestAddingToCacheBlankLsigNilVsEmpty](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/verifiedTxnCache_test.go#L538) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestAddingToCacheBlankMsigNilVsEmpty](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/verifiedTxnCache_test.go#L579) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestGetUnverifiedTransactionGroupsContextChanges](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/verifiedTxnCache_test.go#L618) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestTxnGroupRejectsDuplicateTxid](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/verifiedTxnCache_test.go#L756) | `data/transactions/verify` | `parity_txn_core.md` |
| [TestCheckCanonicalEncoding](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/txHandler_test.go#L690) | `data` | `parity_data_misc.md` |
| [TestTxHandlerRelayData](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/txHandler_test.go#L2528) | `data` | `parity_data_misc.md` |
| [TestTxHandlerDecodeMsgNoStaleFields](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/txHandler_test.go#L3518) | `data` | `parity_data_misc.md` |
| [TestHeartbeatAcceptingSenderIsOffEd25519Curve](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/heartbeat/service_test.go#L313) | `heartbeat` | `parity_tools_cmd.md` |
| [TestFamilyBoxReentrancyToggling](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/boxtxn_test.go#L1136) | `ledger` | `parity_ledger_core.md` |
| [TestBuildMerkleTrieDuplicateHash](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/catchupaccessor_test.go#L380) | `ledger` | `parity_ledger_core.md` |
| [TestCowBaseCrossTypeLookups](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/eval/eval_test.go#L1452) | `ledger/eval` | `parity_ledger_core.md` |
| [TestGroupChecksAgreeWithVerify](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/eval/eval_test.go#L2100) | `ledger/eval` | `parity_ledger_core.md` |
| [TestSaltedRekeyedAddressAuthorization](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/eval_simple_test.go#L1448) | `ledger` | `parity_ledger_core.md` |
| [TestSaltedLogicSigRekeyedAddressAuthorization](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/eval_simple_test.go#L1541) | `ledger` | `parity_ledger_core.md` |
| [TestSaltedChallengedAccountCanHeartbeatForZeroFee](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/eval_simple_test.go#L1648) | `ledger` | `parity_ledger_core.md` |
| [TestExtraBudgetWithInner](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/simulation/simulation_eval_test.go#L1764) | `ledger/simulation` | `parity_ledger_sim.md` |
| [TestPlaceholderSaltedKeySignatures](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/simulation/simulation_eval_test.go#L6839) | `ledger/simulation` | `parity_ledger_sim.md` |
| [TestDelegatedLogicSigSaltedKeySigNotPlaceholder](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/simulation/simulation_eval_test.go#L7280) | `ledger/simulation` | `parity_ledger_sim.md` |
| [TestIdentityTrackerHandlerDepartedPeer](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/netidentity_test.go#L381) | `network` | `parity_network.md` |
| [TestControllerRecoversAfterOutage](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2p/dnsaddr/resolveController_test.go#L96) | `network/p2p/dnsaddr` | `parity_network.md` |
| [TestControllerTriesEachResolverPerLookup](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2p/dnsaddr/resolveController_test.go#L120) | `network/p2p/dnsaddr` | `parity_network.md` |
| [TestControllerBackupAfterPrimaryFailure](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2p/dnsaddr/resolveController_test.go#L151) | `network/p2p/dnsaddr` | `parity_network.md` |
| [TestStream_CloseWaitsForHandlers](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2p/streams_test.go#L196) | `network/p2p` | `parity_network.md` |
| [TestStream_CloseTimeout](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2p/streams_test.go#L279) | `network/p2p` | `parity_network.md` |
| [TestP2PBootstrapPhonebook](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2pNetwork_test.go#L622) | `network` | `parity_network.md` |
| [TestP2PThrottleSlotNotLeakedOnIdentityDedup](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2pNetwork_test.go#L1932) | `network` | `parity_network.md` |
| [TestP2PPeerSweep](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2pNetwork_test.go#L1994) | `network` | `parity_network.md` |
| [TestP2PPeerRoutingAddr](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2pNetwork_test.go#L2039) | `network` | `parity_network.md` |
| [TestWebsocketNetworkStopEndsMessagesOfInterestThread](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L5153) | `network` | `parity_network.md` |
| [TestWebsocketNetworkThrottleSlotNotLeakedOnIdentityDedup](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L5181) | `network` | `parity_network.md` |
| [TestWebsocketPeerSweep](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L5241) | `network` | `parity_network.md` |
| [TestSigSchemes](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/protocol/sig_scheme_test.go#L27) | `protocol` | `parity_config_proto_sp.md` |
| [TestTxSyncResponseDecode](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/rpcs/httpTxSync_test.go#L34) | `rpcs` | `parity_daemon_node.md` |
| [TestLedgerServiceVersionErrors](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/rpcs/ledgerService_test.go#L176) | `rpcs` | `parity_daemon_node.md` |
| [TestMarshalUnmarshalPreEncodedBlockCert](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/rpcs/msgp_gen_test.go#L76) | `rpcs` | `parity_daemon_node.md` |
| [TestRandomizedEncodingPreEncodedBlockCert](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/rpcs/msgp_gen_test.go#L97) | `rpcs` | `parity_daemon_node.md` |
| [TestMarshalUnmarshaltxSyncResponse](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/rpcs/msgp_gen_test.go#L136) | `rpcs` | `parity_daemon_node.md` |
| [TestRandomizedEncodingtxSyncResponse](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/rpcs/msgp_gen_test.go#L157) | `rpcs` | `parity_daemon_node.md` |
| [TestServicePathsShareServeMux](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/rpcs/registrar_test.go#L34) | `rpcs` | `parity_daemon_node.md` |
| [TestSelectRRSet](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/client_test.go#L93) | `tools/network/dnssec` | `parity_tools_cmd.md` |
| [TestLookupRejectsSignedRRSetFromAnotherName](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/dnssec_test.go#L91) | `tools/network/dnssec` | `parity_tools_cmd.md` |
| [TestLookupIPAddrRejectsSignedRRSetFromAnotherName](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/dnssec_test.go#L112) | `tools/network/dnssec` | `parity_tools_cmd.md` |
| [TestLookupRejectsSignerOutsideOwnerZone](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/dnssec_test.go#L129) | `tools/network/dnssec` | `parity_tools_cmd.md` |
| [TestLookupRejectsDSFromAnotherName](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/dnssec_test.go#L154) | `tools/network/dnssec` | `parity_tools_cmd.md` |
| [TestLookupRejectsDNSKEYFromAnotherName](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/dnssec_test.go#L187) | `tools/network/dnssec` | `parity_tools_cmd.md` |
| [TestLookupRejectsUnprovedWildcardExpansion](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/dnssec_test.go#L210) | `tools/network/dnssec` | `parity_tools_cmd.md` |
| [TestLookupIPAddrIPv6Only](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/dnssec_test.go#L231) | `tools/network/dnssec` | `parity_tools_cmd.md` |
| [TestLookupCombinedSigningKey](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/dnssec_test.go#L436) | `tools/network/dnssec` | `parity_tools_cmd.md` |
| [TestLookupCollidingDNSKEYTags](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/dnssec_test.go#L494) | `tools/network/dnssec` | `parity_tools_cmd.md` |
| [TestMakeTrustedZoneIgnoresRSAMD5Key](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/trustedzone_test.go#L202) | `tools/network/dnssec` | `parity_tools_cmd.md` |
| [TestErasableAccessorTempStoreInMemory](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/db/dbutil_test.go#L439) | `util/db` | `parity_util.md` |
| [TestEraseWAL](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/db/walerase_test.go#L103) | `util/db` | `parity_util.md` |
| [TestEraseWALLargeLog](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/db/walerase_test.go#L158) | `util/db` | `parity_util.md` |
| [TestEraseWALLogAccounting](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/db/walerase_test.go#L198) | `util/db` | `parity_util.md` |
| [TestEraseWALOverwritesBeforeTruncate](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/db/walerase_test.go#L259) | `util/db` | `parity_util.md` |
| [TestEraseWALRefusesToTruncateAfterConcurrentWrite](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/db/walerase_test.go#L290) | `util/db` | `parity_util.md` |
| [TestEraseWALSpilledFrames](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/db/walerase_test.go#L326) | `util/db` | `parity_util.md` |
| [TestEraseWALDeferredUnderReader](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/db/walerase_test.go#L367) | `util/db` | `parity_util.md` |
| [TestFairQueueRoundRobin](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/fairqueue_test.go#L46) | `util` | `parity_util.md` |
| [TestFairQueueFull](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/fairqueue_test.go#L73) | `util` | `parity_util.md` |
| [TestFairQueueBoundedWait](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/fairqueue_test.go#L106) | `util` | `parity_util.md` |
| [TestFairQueueCapacityBelowOne](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/fairqueue_test.go#L147) | `util` | `parity_util.md` |
| [TestFairQueueEmptySource](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/fairqueue_test.go#L159) | `util` | `parity_util.md` |
| [TestFairQueueNext](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/fairqueue_test.go#L170) | `util` | `parity_util.md` |

## Removed in `v5.1.1-stable` (91)

Delete each row (the go test no longer exists at the pin). If the matched Rust test proved behavior go-algorand deliberately dropped, that is an upstream behavior change — make sure a Stage 2/3 issue covers it.

| go-algorand test (OLD) | row(s) |
|---|---|
| `cmd/algokey/msgp_gen_test.go` `TestMarshalUnmarshalpqPublicMaterial` | `docs/phase17/parity_tools_cmd.md:17` |
| `cmd/algokey/msgp_gen_test.go` `TestRandomizedEncodingpqPublicMaterial` | `docs/phase17/parity_tools_cmd.md:18` |
| `cmd/algokey/msgp_gen_test.go` `TestMarshalUnmarshalpqSigningMaterial` | `docs/phase17/parity_tools_cmd.md:19` |
| `cmd/algokey/msgp_gen_test.go` `TestRandomizedEncodingpqSigningMaterial` | `docs/phase17/parity_tools_cmd.md:20` |
| `cmd/algokey/pq_test.go` `TestPQKeySeedDerivationUsesDomainSchemeAndEntropy` | `docs/phase17/parity_tools_cmd.md:21` |
| `cmd/algokey/pq_test.go` `TestPQGenerateUsesMnemonicSizedEntropy` | `docs/phase17/parity_tools_cmd.md:22` |
| `cmd/algokey/pq_test.go` `TestPQSchemeRegistriesConsistent` | `docs/phase17/parity_tools_cmd.md:23` |
| `cmd/algokey/pq_test.go` `TestPQSchemeKeySizes` | `docs/phase17/parity_tools_cmd.md:24` |
| `cmd/algokey/pq_test.go` `TestParsePQSchemeAcceptsLongName` | `docs/phase17/parity_tools_cmd.md:25` |
| `cmd/algokey/pq_test.go` `TestPQPrivateKeyFileStoresKeysNotEntropy` | `docs/phase17/parity_tools_cmd.md:26` |
| `cmd/algokey/pq_test.go` `TestPQKeyFileRejectsMalformedInputs` | `docs/phase17/parity_tools_cmd.md:27` |
| `cmd/algokey/pq_test.go` `TestPQMnemonicImport` | `docs/phase17/parity_tools_cmd.md:28` |
| `cmd/algokey/pq_test.go` `TestPQImportRejectsMalformedMnemonic` | `docs/phase17/parity_tools_cmd.md:29` |
| `cmd/algokey/pq_test.go` `TestPQImportRejectsUnknownScheme` | `docs/phase17/parity_tools_cmd.md:30` |
| `cmd/algokey/pq_test.go` `TestPQPrintMnemonic` | `docs/phase17/parity_tools_cmd.md:31` |
| `cmd/algokey/pq_test.go` `TestPQCommandFlagShorthands` | `docs/phase17/parity_tools_cmd.md:32` |
| `cmd/algokey/pq_test.go` `TestPQSignProducesVerifiablePQEnvelope` | `docs/phase17/parity_tools_cmd.md:33` |
| `cmd/algokey/pq_test.go` `TestPQSignAcceptsMnemonic` | `docs/phase17/parity_tools_cmd.md:34` |
| `cmd/algokey/pq_test.go` `TestPQSignRejectsUnsupportedMnemonicScheme` | `docs/phase17/parity_tools_cmd.md:35` |
| `cmd/algokey/pq_test.go` `TestPQSignRejectsEmptyInputFile` | `docs/phase17/parity_tools_cmd.md:36` |
| `cmd/algokey/pq_test.go` `TestPQSignSetsAndClearsAuthAddr` | `docs/phase17/parity_tools_cmd.md:37` |
| `cmd/algokey/pq_test.go` `TestPQSignRejectsMixedSignaturesUnlessOverwrite` | `docs/phase17/parity_tools_cmd.md:38` |
| `cmd/algokey/pq_test.go` `TestPQSignRejectsNonCompliantSalt` | `docs/phase17/parity_tools_cmd.md:39` |
| `cmd/algokey/pq_test.go` `TestPQDecodePrivateKeyRejectsMnemonic` | `docs/phase17/parity_tools_cmd.md:40` |
| `cmd/algokey/pq_test.go` `TestPQSignProgramProducesVerifiableDelegatedLogicSig` | `docs/phase17/parity_tools_cmd.md:41` |
| `cmd/algokey/pq_test.go` `TestPQSignProgramAcceptsMnemonic` | `docs/phase17/parity_tools_cmd.md:42` |
| `cmd/algokey/pq_test.go` `TestPQSignProgramRejectsMixedKeySources` | `docs/phase17/parity_tools_cmd.md:43` |
| `cmd/algokey/pq_test.go` `TestPQSignProgramRejectsEmptyInputFile` | `docs/phase17/parity_tools_cmd.md:44` |
| `cmd/algokey/pq_test.go` `TestPQSignProgramRejectsTealSource` | `docs/phase17/parity_tools_cmd.md:45` |
| `cmd/algokey/pq_test.go` `TestPQCheckAddress` | `docs/phase17/parity_tools_cmd.md:46` |
| `crypto/falconWrapper_test.go` `TestVerifyFalcon1024RejectsMalformedInputs` | `docs/phase17/parity_crypto.md:22` |
| `crypto/msgp_gen_test.go` `TestMarshalUnmarshalFalconPrivateKey` | `docs/phase17/parity_crypto.md:37` |
| `crypto/msgp_gen_test.go` `TestRandomizedEncodingFalconPrivateKey` | `docs/phase17/parity_crypto.md:38` |
| `crypto/msgp_gen_test.go` `TestMarshalUnmarshalFalconPublicKey` | `docs/phase17/parity_crypto.md:39` |
| `crypto/msgp_gen_test.go` `TestRandomizedEncodingFalconPublicKey` | `docs/phase17/parity_crypto.md:40` |
| `crypto/msgp_gen_test.go` `TestMarshalUnmarshalFalconSigner` | `docs/phase17/parity_crypto.md:41` |
| `crypto/msgp_gen_test.go` `TestRandomizedEncodingFalconSigner` | `docs/phase17/parity_crypto.md:42` |
| `crypto/msgp_gen_test.go` `TestMarshalUnmarshalFalconVerifier` | `docs/phase17/parity_crypto.md:43` |
| `crypto/msgp_gen_test.go` `TestRandomizedEncodingFalconVerifier` | `docs/phase17/parity_crypto.md:44` |
| `crypto/pq_scheme_test.go` `TestLookupPQScheme` | `docs/phase17/parity_crypto.md:109` |
| `crypto/pq_scheme_test.go` `TestPQBoundsCoverFalcon1024` | `docs/phase17/parity_crypto.md:110` |
| `crypto/pq_scheme_test.go` `TestPQVerifierFalcon1024RoundTrip` | `docs/phase17/parity_crypto.md:111` |
| `daemon/algod/api/server/v2/test/handlers_test.go` `TestPostTransactionPQAuthorizerCompliance` | `docs/phase17/parity_daemon_node.md:51` |
| `daemon/algod/api/server/v2/test/handlers_test.go` `TestPostTransactionAsyncPQAuthorizerCompliance` | `docs/phase17/parity_daemon_node.md:54` |
| `daemon/algod/api/server/v2/test/handlers_test.go` `TestPostSimulateTransactionPlaceholderPQSignatureValidation` | `docs/phase17/parity_daemon_node.md:57` |
| `data/basics/pq_address_test.go` `TestPQAddressPreimage` | `docs/phase17/parity_data_misc.md:104` |
| `data/basics/pq_address_test.go` `TestPQAddressKnownAnswers` | `docs/phase17/parity_data_misc.md:105` |
| `data/basics/pq_address_test.go` `TestCanonicalPQAddressSalt` | `docs/phase17/parity_data_misc.md:106` |
| `data/basics/pq_address_test.go` `TestCanonicalPQAddressSaltDoesNotRequireRegisteredSchemeOrValidatedKey` | `docs/phase17/parity_data_misc.md:107` |
| `data/transactions/checks_test.go` `TestCheckTxnGroupApplicationBoxIndex` | `docs/phase17/parity_txn_core.md:17` |
| `data/transactions/checks_test.go` `TestCheckPaysetGroupApplicationBoxIndex` | `docs/phase17/parity_txn_core.md:18` |
| `data/transactions/logic/eval_test.go` `TestUint128` | `docs/phase17/parity_txn_logic.md:302` |
| `data/transactions/logic/program_test.go` `TestPQDelegatedProgramToBeHashed` | `docs/phase17/parity_txn_logic.md:109` |
| `data/transactions/logicsig_test.go` `TestLogicSigPQSigMsgpackRoundTrip` | `docs/phase17/parity_txn_core.md:31` |
| `data/transactions/logicsig_test.go` `TestLogicSigBlankPQSigOmitted` | `docs/phase17/parity_txn_core.md:32` |
| `data/transactions/msgp_gen_test.go` `TestMarshalUnmarshalPQSig` | `docs/phase17/parity_txn_core.md:59` |
| `data/transactions/msgp_gen_test.go` `TestRandomizedEncodingPQSig` | `docs/phase17/parity_txn_core.md:60` |
| `data/transactions/pqsig_test.go` `TestPQDecodeBoundsFeedSignedTxnMaxSize` | `docs/phase17/parity_txn_core.md:84` |
| `data/transactions/pqsig_test.go` `TestPQSigBlank` | `docs/phase17/parity_txn_core.md:85` |
| `data/transactions/pqsig_test.go` `TestPQSigEqual` | `docs/phase17/parity_txn_core.md:86` |
| `data/transactions/pqsig_test.go` `TestPQSigAuthorizerAddress` | `docs/phase17/parity_txn_core.md:87` |
| `data/transactions/pqsig_test.go` `TestPQSigValidateEnvelope` | `docs/phase17/parity_txn_core.md:88` |
| `data/transactions/pqsig_test.go` `TestPQSigVerify` | `docs/phase17/parity_txn_core.md:89` |
| `data/transactions/pqsig_test.go` `TestPQSigVerifyAcceptsSignatureOverRawTxn` | `docs/phase17/parity_txn_core.md:90` |
| `data/transactions/pqsig_test.go` `TestPQSigVerifyChecksConsensusParams` | `docs/phase17/parity_txn_core.md:91` |
| `data/transactions/pqsig_test.go` `TestPQSigVerifyRejectsBlank` | `docs/phase17/parity_txn_core.md:92` |
| `data/transactions/pqsig_test.go` `TestPQSigVerifyRejectsEmptySignature` | `docs/phase17/parity_txn_core.md:93` |
| `data/transactions/pqsig_test.go` `TestPQSigVerifyRejectsUnsupportedScheme` | `docs/phase17/parity_txn_core.md:94` |
| `data/transactions/pqsig_test.go` `TestPQSigVerifyRejectsAuthorizerMismatch` | `docs/phase17/parity_txn_core.md:95` |
| `data/transactions/pqsig_test.go` `TestPQSigVerifyRejectsMalformedPublicKey` | `docs/phase17/parity_txn_core.md:96` |
| `data/transactions/pqsig_test.go` `TestPQSigVerifyRejectsMalformedSignature` | `docs/phase17/parity_txn_core.md:97` |
| `data/transactions/pqsig_test.go` `TestPQSigVerifyRejectsChangedTransaction` | `docs/phase17/parity_txn_core.md:98` |
| `data/transactions/pqsig_test.go` `TestPQSigVerifyRejectsChangedSignature` | `docs/phase17/parity_txn_core.md:99` |
| `data/transactions/signedtxn_test.go` `TestSignedTxnFeeFactorPQSignatureContribution` | `docs/phase17/parity_txn_core.md:104` |
| `data/transactions/verify/txnBatch_test.go` `TestStreamToBatchBlockWatcher` | `docs/phase17/parity_txn_core.md:133` |
| `data/transactions/verify/txn_test.go` `TestTxnValidationPQSig` | `docs/phase17/parity_txn_core.md:145` |
| `data/transactions/verify/txn_test.go` `TestTxnValidationPQSigWithAuthAddr` | `docs/phase17/parity_txn_core.md:146` |
| `data/transactions/verify/txn_test.go` `TestTxnValidationEd25519SigWithPQSenderAuthAddr` | `docs/phase17/parity_txn_core.md:147` |
| `data/transactions/verify/txn_test.go` `TestTxnValidationPQSigEncodeDecode` | `docs/phase17/parity_txn_core.md:148` |
| `data/transactions/verify/txn_test.go` `TestTxnValidationPQSigRejectsMalformedProof` | `docs/phase17/parity_txn_core.md:149` |
| `data/transactions/verify/txn_test.go` `TestTxnValidationPQDelegatedLogicSig` | `docs/phase17/parity_txn_core.md:150` |
| `data/transactions/verify/txn_test.go` `TestTxnValidationPQDelegatedLogicSigRejectsInvalidProof` | `docs/phase17/parity_txn_core.md:151` |
| `data/transactions/verify/txn_test.go` `TestTxnValidationPQDelegatedLogicSigSignsRawProgram` | `docs/phase17/parity_txn_core.md:152` |
| `data/transactions/verify/txn_test.go` `TestTxnGroupPQSigMixedSignatures` | `docs/phase17/parity_txn_core.md:160` |
| `data/transactions/verify/txn_test.go` `TestOrphanLsigPQSigGatedByConsensus` | `docs/phase17/parity_txn_core.md:170` |
| `data/transactions/verify/verifiedTxnCache_test.go` `TestGetUnverifiedTransactionGroupsPQSigProofChanges` | `docs/phase17/parity_txn_core.md:178` |
| `heartbeat/service_test.go` `TestHeartbeatAcceptingSenderIsPQCompliant` | `docs/phase17/parity_tools_cmd.md:166` |
| `ledger/eval_simple_test.go` `TestPQRekeyedAddressAuthorization` | `docs/phase17/parity_ledger_core.md:170` |
| `ledger/eval_simple_test.go` `TestPQChallengedAccountCanHeartbeatForZeroFee` | `docs/phase17/parity_ledger_core.md:171` |
| `ledger/simulation/simulation_eval_test.go` `TestPlaceholderPQSignatures` | `docs/phase17/parity_ledger_sim.md:49` |
| `protocol/pq_scheme_test.go` `TestPQSchemes` | `docs/phase17/parity_config_proto_sp.md:66` |

## Moved (0)

`repin` rewrites these links automatically; listed for the record.

_none_

## Body changed — re-verify the mapped Rust test(s) (234)

For each: read `git -C ../go-algorand diff OLD NEW -- <file>` around the function. If go-algorand added/changed an assertion, the mapped Rust test must gain the same assertion (or the row honestly drops to `partial` and becomes a sub-issue). Update the row's notes with what was re-checked.

| go-algorand test | current status | row |
|---|---|---|
| [TestCryptoRequestContextAddCancelPinnedProposal](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/cryptoRequestContext_test.go#L136) | matched-1:1 | `docs/phase17/parity_agreement.md:32` |
| [TestCryptoRequestContextAddCancelProposal](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/cryptoRequestContext_test.go#L109) | matched-many:1 | `docs/phase17/parity_agreement.md:31` |
| [TestDemuxNext](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/demux_test.go#L420) | matched-1:many | `docs/phase17/parity_agreement.md:45` |
| [TestDecodeRejectsStepAboveDown](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/message_test.go#L180) | matched-1:many | `docs/phase17/parity_agreement.md:75` |
| [TestProposalCarriesMalformedStateProofPath](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/message_test.go#L40) | matched-1:1 | `docs/phase17/parity_agreement.md:72` |
| [TestProposalCarriesOversizedTxnGroup](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/message_test.go#L139) | matched-1:1 | `docs/phase17/parity_agreement.md:74` |
| [TestAgreementSnapshotCompression](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/persistence_test.go#L238) | matched-1:1 | `docs/phase17/parity_agreement.md:357` |
| [TestRandomizedEncodingFullDiskState](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/persistence_test.go#L209) | matched-1:1 | `docs/phase17/parity_agreement.md:166` |
| [TestPlayerRetainsReceivedValidatedAtAVPPHistoryWindow](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/player_test.go#L3821) | matched-1:1 | `docs/phase17/parity_agreement.md:236` |
| [TestProposalStoreRegressionWrongPipelinePeriodBug_39387501](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/proposalStore_test.go#L824) | matched-1:1 | `docs/phase17/parity_agreement.md:257` |
| [TestAgreementLargePeriods](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/service_test.go#L2214) | matched-1:1 | `docs/phase17/parity_agreement.md:290` |
| [TestAgreementServiceStartDeadline](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/service_test.go#L2581) | matched-1:1 | `docs/phase17/parity_agreement.md:293` |
| [TestVoteAggregatorOldVote](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/agreement/voteAggregator_test.go#L870) | matched-1:1 | `docs/phase17/parity_agreement.md:306` |
| [TestCatchupUnmatchedCertificate](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/catchup/service_test.go#L908) | matched-1:many | `docs/phase17/parity_catchup.md:46` |
| [TestOnSwitchToUnSupportedProtocol1](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/catchup/service_test.go#L580) | matched-1:1 | `docs/phase17/parity_catchup.md:42` |
| [TestOnSwitchToUnSupportedProtocol2](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/catchup/service_test.go#L598) | matched-1:1 | `docs/phase17/parity_catchup.md:43` |
| [TestOnSwitchToUnSupportedProtocol3](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/catchup/service_test.go#L619) | matched-1:1 | `docs/phase17/parity_catchup.md:44` |
| [TestOnSwitchToUnSupportedProtocol4](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/catchup/service_test.go#L644) | matched-1:1 | `docs/phase17/parity_catchup.md:45` |
| [TestProcessBlockBytesErrors](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/catchup/universalFetcher_test.go#L150) | matched-1:many | `docs/phase17/parity_catchup.md:57` |
| [TestRequestBlockBytesErrors](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/catchup/universalFetcher_test.go#L182) | matched-1:many | `docs/phase17/parity_catchup.md:58` |
| [TestUGetBlockWs](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/catchup/universalFetcher_test.go#L42) | matched-1:many | `docs/phase17/parity_catchup.md:54` |
| [TestInspect](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/cmd/goal/inspect_test.go#L31) | matched-1:many | `docs/phase17/parity_tools_cmd.md:64` |
| [TestEnsureAndResolveGenesisDirs_migrateSPErr](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/config/config_test.go#L1011) | out-of-scope | `docs/phase17/parity_config_proto_sp.md:35` |
| [TestConsensusParams](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/config/consensus_test.go#L27) | matched-1:many | `docs/phase17/parity_config_proto_sp.md:41` |
| [TestFalconCanHandleNilSignature](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/falconWrapper_test.go#L227) | matched-1:1 | `docs/phase17/parity_crypto.md:23` |
| [TestFalconSignature_ValidateVersion](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/falconWrapper_test.go#L291) | matched-1:1 | `docs/phase17/parity_crypto.md:26` |
| [TestFalconsFormatConversion](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/falconWrapper_test.go#L263) | matched-1:1 | `docs/phase17/parity_crypto.md:25` |
| [TestSignAndVerifyFalcon](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/falconWrapper_test.go#L124) | matched-1:many | `docs/phase17/parity_crypto.md:20` |
| [TestSignAndVerifyFalconHashable](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/falconWrapper_test.go#L146) | matched-1:1 | `docs/phase17/parity_crypto.md:21` |
| [TestVerificationBytes](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/falconWrapper_test.go#L245) | matched-1:1 | `docs/phase17/parity_crypto.md:24` |
| [TestNonEmptyDisposableKeys](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/merklesignature/merkleSignatureScheme_test.go#L207) | matched-1:1 | `docs/phase17/parity_crypto.md:172` |
| [TestUint11Array](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/passphrase/passphrase_test.go#L98) | matched-1:1 | `docs/phase17/parity_crypto.md:229` |
| [TestBuilder_StateProofTopVoters](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/stateproof/prover_test.go#L637) | matched-many:1 | `docs/phase17/parity_crypto.md:267` |
| [TestVerifyStateProofAlgorithms](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/stateproof/verifier_test.go#L193) | matched-1:many | `docs/phase17/parity_crypto.md:274` |
| [TestHashRepToBuff](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/crypto/util_test.go#L66) | matched-1:1 | `docs/phase17/parity_crypto.md:114` |
| [TestAccount](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/server/v2/account_test.go#L34) | matched-1:many | `docs/phase17/parity_daemon_node.md:13` |
| [TestApplicationBoxesMaxKeys](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/server/v2/handlers_test.go#L33) | matched-1:many | `docs/phase17/parity_daemon_node.md:15` |
| [TestGenesisTypeCompatibility](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/server/v2/test/genesis_types_test.go#L49) | out-of-scope | `docs/phase17/parity_daemon_node.md:20` |
| [TestAppendParticipationKeys](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/server/v2/test/handlers_test.go#L2380) | matched-1:many | `docs/phase17/parity_daemon_node.md:66` |
| [TestPendingTransactionsByAddress](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/server/v2/test/handlers_test.go#L1119) | matched-1:1 | `docs/phase17/parity_daemon_node.md:49` |
| [TestPostTransactionLogicSigCurveCheck](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/server/v2/test/handlers_test.go#L1422) | matched-1:1 | `docs/phase17/parity_daemon_node.md:52` |
| [TestRandomizedEncodingAccountAssetModel](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/daemon/algod/api/spec/v2/msgp_gen_test.go#L97) | matched-1:1 | `docs/phase17/parity_daemon_node.md:89` |
| [TestParticipation_CleanupTablesAfterDeleteExpired](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/account/participationRegistry_test.go#L321) | matched-1:1 | `docs/phase17/parity_data_misc.md:15` |
| [TestParticipation_NoKeyToUpdate](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/account/participationRegistry_test.go#L680) | matched-many:1 | `docs/phase17/parity_data_misc.md:25` |
| [TestAccountManagerKeysRegistry](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/accountManager_test.go#L91) | matched-many:1 | `docs/phase17/parity_data_misc.md:51` |
| [TestNewWithPairs](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/basics/serr_test.go#L37) | matched-1:many | `docs/phase17/parity_data_misc.md:109` |
| [TestEmptyEncoding](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/committee/encoding_test.go#L30) | matched-1:many | `docs/phase17/parity_data_misc.md:208` |
| [TestClassifyTxPoolErrorGeneralCoverage](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/pools/errors_test.go#L37) | matched-1:1 | `docs/phase17/parity_data_misc.md:223` |
| [TestStateProofLogging](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/pools/transactionPool_test.go#L1295) | matched-1:many | `docs/phase17/parity_data_misc.md:241` |
| [TestTransactionPool_CurrentFeePerByte](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/pools/transactionPool_test.go#L877) | matched-1:1 | `docs/phase17/parity_data_misc.md:239` |
| [TestCheckPaysetGroupID](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/checks_test.go#L138) | matched-1:many | `docs/phase17/parity_txn_core.md:19` |
| [TestCheckTxnGroupStateProofBasicSuite](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/checks_test.go#L55) | matched-1:many | `docs/phase17/parity_txn_core.md:12` |
| [TestCheckTxnGroupUnknownType](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/checks_test.go#L217) | matched-1:many | `docs/phase17/parity_txn_core.md:21` |
| [TestBackwardCompatGlobalFields](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/backwardCompat_test.go#L339) | matched-1:many | `docs/phase17/parity_txn_logic.md:95` |
| [TestBackwardCompatTEALv1](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/backwardCompat_test.go#L253) | matched-1:many | `docs/phase17/parity_txn_logic.md:94` |
| [TestBackwardCompatTxnFields](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/backwardCompat_test.go#L381) | matched-1:many | `docs/phase17/parity_txn_logic.md:96` |
| [TestEcdsaWithSecp256k1](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L656) | matched-1:many | `docs/phase17/parity_txn_logic.md:157` |
| [TestEcdsaWithSecp256r1](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L812) | matched-1:many | `docs/phase17/parity_txn_logic.md:158` |
| [TestFalconVerify](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L520) | matched-1:many | `docs/phase17/parity_txn_logic.md:155` |
| [TestHashCosts](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L997) | matched-1:many | `docs/phase17/parity_txn_logic.md:161` |
| [TestMimc](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L145) | matched-1:many | `docs/phase17/parity_txn_logic.md:150` |
| [TestPoseidon2](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L223) | matched-1:many | `docs/phase17/parity_txn_logic.md:151` |
| [TestVrfVerify](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/crypto_test.go#L316) | matched-1:many | `docs/phase17/parity_txn_logic.md:152` |
| [TestBigApplCreation](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/evalAppTxn_test.go#L1330) | matched-1:1 | `docs/phase17/parity_txn_logic.md:204` |
| [TestPooledAppCallsVerifyOp](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/evalStateful_test.go#L3821) | matched-1:many | `docs/phase17/parity_txn_logic.md:269` |
| [TestReturnTypes](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/evalStateful_test.go#L3283) | out-of-scope | `docs/phase17/parity_txn_logic.md:259` |
| [TestAddOverflow](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L931) | matched-1:many | `docs/phase17/parity_txn_logic.md:297` |
| [TestArgTooFar](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L1255) | matched-1:1 | `docs/phase17/parity_txn_logic.md:314` |
| [TestArgTooLarge](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L277) | matched-1:1 | `docs/phase17/parity_txn_logic.md:277` |
| [TestAssert](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5153) | matched-1:many | `docs/phase17/parity_txn_logic.md:380` |
| [TestBitLen](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5608) | matched-1:many | `docs/phase17/parity_txn_logic.md:397` |
| [TestBits](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5164) | matched-1:many | `docs/phase17/parity_txn_logic.md:381` |
| [TestBranchEnd](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L666) | matched-1:many | `docs/phase17/parity_txn_logic.md:287` |
| [TestBranchTooLarge](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L3837) | matched-1:1 | `docs/phase17/parity_txn_logic.md:369` |
| [TestBtoiTooLong](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L849) | matched-1:many | `docs/phase17/parity_txn_logic.md:292` |
| [TestBytes](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5210) | matched-1:many | `docs/phase17/parity_txn_logic.md:382` |
| [TestBytesBits](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L6245) | matched-1:1 | `docs/phase17/parity_txn_logic.md:400` |
| [TestBytesCompare](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L6185) | matched-1:many | `docs/phase17/parity_txn_logic.md:399` |
| [TestBytesMath](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5875) | matched-1:many | `docs/phase17/parity_txn_logic.md:398` |
| [TestConsOverflow](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L2801) | matched-1:1 | `docs/phase17/parity_txn_logic.md:335` |
| [TestCover](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5304) | matched-1:many | `docs/phase17/parity_txn_logic.md:388` |
| [TestDig](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5273) | matched-1:many | `docs/phase17/parity_txn_logic.md:386` |
| [TestDivModw](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L1070) | matched-1:many | `docs/phase17/parity_txn_logic.md:303` |
| [TestDivZero](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L1199) | matched-1:many | `docs/phase17/parity_txn_logic.md:306` |
| [TestDivw](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L998) | matched-1:many | `docs/phase17/parity_txn_logic.md:301` |
| [TestDup](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L4710) | matched-1:many | `docs/phase17/parity_txn_logic.md:372` |
| [TestErr](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L1213) | matched-1:many | `docs/phase17/parity_txn_logic.md:308` |
| [TestExp](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5503) | matched-1:many | `docs/phase17/parity_txn_logic.md:395` |
| [TestExpw](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5520) | matched-1:many | `docs/phase17/parity_txn_logic.md:396` |
| [TestGloadNoProgram](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L3215) | matched-1:1 | `docs/phase17/parity_txn_logic.md:346` |
| [TestGtxn](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L2286) | matched-1:many | `docs/phase17/parity_txn_logic.md:328` |
| [TestLoop](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5357) | matched-1:many | `docs/phase17/parity_txn_logic.md:391` |
| [TestMatch](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L7071) | matched-1:many | `docs/phase17/parity_txn_logic.md:411` |
| [TestModZero](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L1206) | matched-1:many | `docs/phase17/parity_txn_logic.md:307` |
| [TestMulOverflow](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L938) | matched-1:many | `docs/phase17/parity_txn_logic.md:298` |
| [TestOpJSONRef](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L6536) | matched-1:many | `docs/phase17/parity_txn_logic.md:407` |
| [TestPanic](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L3667) | out-of-scope | `docs/phase17/parity_txn_logic.md:363` |
| [TestRapidMath](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L576) | matched-1:many | `docs/phase17/parity_txn_logic.md:285` |
| [TestRekeyErrsOnOldVersion](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L4994) | matched-1:1 | `docs/phase17/parity_txn_logic.md:379` |
| [TestReplace](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L2937) | matched-1:many | `docs/phase17/parity_txn_logic.md:340` |
| [TestSelect](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5261) | matched-1:many | `docs/phase17/parity_txn_logic.md:385` |
| [TestSha256EqArg](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L602) | matched-1:many | `docs/phase17/parity_txn_logic.md:286` |
| [TestShifts](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5456) | matched-1:many | `docs/phase17/parity_txn_logic.md:393` |
| [TestSimpleMath](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L561) | matched-many:1 | `docs/phase17/parity_txn_logic.md:284` |
| [TestStackBytesLeftover](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L1241) | matched-1:1 | `docs/phase17/parity_txn_logic.md:312` |
| [TestStackEmpty](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L1248) | matched-1:many | `docs/phase17/parity_txn_logic.md:313` |
| [TestStackLeftover](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L1234) | matched-1:1 | `docs/phase17/parity_txn_logic.md:311` |
| [TestStackOverflow](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L4698) | matched-1:1 | `docs/phase17/parity_txn_logic.md:371` |
| [TestSubUnderflow](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L924) | matched-1:many | `docs/phase17/parity_txn_logic.md:296` |
| [TestSubroutine](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5370) | matched-1:many | `docs/phase17/parity_txn_logic.md:392` |
| [TestSubstringFlop](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L2820) | matched-1:many | `docs/phase17/parity_txn_logic.md:336` |
| [TestSubstringRange](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L2854) | matched-1:1 | `docs/phase17/parity_txn_logic.md:337` |
| [TestSwap](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5253) | matched-1:1 | `docs/phase17/parity_txn_logic.md:384` |
| [TestSwitchInt](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L6956) | matched-1:many | `docs/phase17/parity_txn_logic.md:409` |
| [TestTLHC](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L738) | matched-1:1 | `docs/phase17/parity_txn_logic.md:288` |
| [TestTooManyArgs](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L259) | matched-1:1 | `docs/phase17/parity_txn_logic.md:276` |
| [TestUncover](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L5315) | matched-1:many | `docs/phase17/parity_txn_logic.md:389` |
| [TestWideMath](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/eval_test.go#L1120) | matched-1:many | `docs/phase17/parity_txn_logic.md:304` |
| [TestTxnEffectsAvailable](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/fields_test.go#L296) | matched-1:many | `docs/phase17/parity_txn_logic.md:422` |
| [TestDupPopN](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/frames_test.go#L42) | matched-1:many | `docs/phase17/parity_txn_logic.md:429` |
| [TestFrameAccessAboveStack](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/frames_test.go#L391) | matched-1:1 | `docs/phase17/parity_txn_logic.md:437` |
| [TestVoidSub](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/frames_test.go#L185) | matched-1:1 | `docs/phase17/parity_txn_logic.md:433` |
| [TestParseRawNonUnicodeChar](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/jsonspec_test.go#L325) | matched-1:1 | `docs/phase17/parity_txn_logic.md:128` |
| [TestOpSpecs](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/opcodes_test.go#L30) | matched-1:1 | `docs/phase17/parity_txn_logic.md:105` |
| [TestOpcodesVersioningV2](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/opcodes_test.go#L160) | matched-1:many | `docs/phase17/parity_txn_logic.md:108` |
| [TestLinearFieldCost](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logic/pairing_test.go#L847) | out-of-scope | `docs/phase17/parity_txn_logic.md:176` |
| [TestLogicSigBlankAndHasProgram](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/logicsig_test.go#L31) | matched-1:many | `docs/phase17/parity_txn_core.md:30` |
| [TestSignedTxnHasSignature](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/signedtxn_test.go#L94) | matched-1:many | `docs/phase17/parity_txn_core.md:103` |
| [TestSignedTxnInBlockHash](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/signedtxn_test.go#L83) | matched-1:1 | `docs/phase17/parity_txn_core.md:102` |
| [TestProcessBatchSkippedGroupDoesNotMisattributeSigs](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txnBatch_test.go#L1065) | out-of-scope | `docs/phase17/parity_txn_core.md:142` |
| [TestStreamToBatchRestart](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txnBatch_test.go#L476) | out-of-scope | `docs/phase17/parity_txn_core.md:132` |
| [TestBigLogicSigProgramSize](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L2150) | matched-1:1 | `docs/phase17/parity_txn_core.md:169` |
| [TestTxnGroupCacheUpdateLogicWithMultiSig](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L1865) | matched-1:1 | `docs/phase17/parity_txn_core.md:167` |
| [TestTxnGroupLogicOnlyAccountRemainsUnchanged](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L1643) | matched-1:1 | `docs/phase17/parity_txn_core.md:161` |
| [TestTxnGroupMixedSignatures](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/txn_test.go#L1456) | matched-1:many | `docs/phase17/parity_txn_core.md:159` |
| [TestAddingToCache](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/verifiedTxnCache_test.go#L48) | matched-1:1 | `docs/phase17/parity_txn_core.md:175` |
| [TestPinningTransactions](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/transactions/verify/verifiedTxnCache_test.go#L383) | matched-1:1 | `docs/phase17/parity_txn_core.md:180` |
| [TestTxHandlerSaltedCacheScheduled](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/txDupCache_test.go#L200) | matched-1:1 | `docs/phase17/parity_data_misc.md:252` |
| [TestTxHandlerIncomingTxHandleDrops](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/txHandler_test.go#L1327) | matched-many:1 | `docs/phase17/parity_data_misc.md:264` |
| [TestTxHandlerNilTxPool](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/txHandler_test.go#L3486) | out-of-scope | `docs/phase17/parity_data_misc.md:279` |
| [TestTxHandlerProcessIncomingCensoring](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/txHandler_test.go#L844) | matched-1:many | `docs/phase17/parity_data_misc.md:257` |
| [TestTxHandlerProcessIncomingGroup](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/txHandler_test.go#L618) | matched-many:1 | `docs/phase17/parity_data_misc.md:256` |
| [TestTxHandlerRememberReportErrorsWithTxPool](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/data/txHandler_test.go#L2271) | matched-many:1 | `docs/phase17/parity_data_misc.md:268` |
| [TestAcctOnline_ExpiredOnlineCirculation](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/acctonline_test.go#L1926) | matched-many:1 | `docs/phase17/parity_ledger_core.md:403` |
| [TestAppEmptyBox](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/applications_test.go#L1361) | matched-1:many | `docs/phase17/parity_ledger_core.md:112` |
| [TestPayAction](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/apptxn_test.go#L41) | matched-1:many | `docs/phase17/parity_ledger_core.md:5` |
| [TestFamilyBoxReentrancy](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/boxtxn_test.go#L1018) | matched-1:many | `docs/phase17/parity_ledger_core.md:100` |
| [TestNewAppBoxCreate](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/boxtxn_test.go#L746) | matched-1:1 | `docs/phase17/parity_ledger_core.md:99` |
| [TestBuildMerkleTrie](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/catchupaccessor_test.go#L283) | out-of-scope | `docs/phase17/parity_ledger_core.md:215` |
| [TestApplyChild](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/eval/appcow_test.go#L697) | out-of-scope | `docs/phase17/parity_ledger_core.md:426` |
| [TestCowStorage](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/eval/appcow_test.go#L224) | matched-1:many | `docs/phase17/parity_ledger_core.md:423` |
| [TestComputeLoad](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/eval/eval_test.go#L2068) | matched-1:many | `docs/phase17/parity_ledger_core.md:454` |
| [TestCowBaseCreatorsCache](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/eval/eval_test.go#L1381) | out-of-scope | `docs/phase17/parity_ledger_core.md:448` |
| [TestEvaluatorPrefetcherAlignmentCreateApplication](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/eval/prefetcher/prefetcher_alignment_test.go#L936) | out-of-scope | `docs/phase17/parity_ledger_core.md:464` |
| [TestEvaluatorPrefetcherAlignmentCreateAsset](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/eval/prefetcher/prefetcher_alignment_test.go#L440) | out-of-scope | `docs/phase17/parity_ledger_core.md:456` |
| [TestRekeying](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/eval_simple_test.go#L1332) | matched-1:many | `docs/phase17/parity_ledger_core.md:169` |
| [TestLedgerRegressionFaultyLeaseFirstValidCheckFuture](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/ledger_test.go#L1421) | matched-many:1 | `docs/phase17/parity_ledger_core.md:69` |
| [TestLedgerReloadShrinkDeltas](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/ledger_test.go#L2150) | out-of-scope | `docs/phase17/parity_ledger_core.md:76` |
| [TestLedgerReloadTxTailHistoryAccess](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/ledger_test.go#L2386) | matched-1:many | `docs/phase17/parity_ledger_core.md:77` |
| [TestLedgerVerifiesOldStateProofs](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/ledger_test.go#L1723) | matched-1:many | `docs/phase17/parity_ledger_core.md:72` |
| [TestVotersReloadFromDisk](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/ledger_test.go#L3058) | matched-1:many | `docs/phase17/parity_ledger_core.md:81` |
| [TestAppAtBudget](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/simulation/simulation_eval_test.go#L1671) | matched-1:many | `docs/phase17/parity_ledger_sim.md:26` |
| [TestFixSigners](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/simulation/simulation_eval_test.go#L10240) | matched-1:many | `docs/phase17/parity_ledger_sim.md:67` |
| [TestInnerTxnNonAppCallErr](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/simulation/simulation_eval_test.go#L7779) | matched-1:many | `docs/phase17/parity_ledger_sim.md:56` |
| [TestLogicSig](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/simulation/simulation_eval_test.go#L615) | matched-1:many | `docs/phase17/parity_ledger_sim.md:13` |
| [TestMaxDepthAppWithPCTrace](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/simulation/simulation_eval_test.go#L2313) | matched-1:1 | `docs/phase17/parity_ledger_sim.md:32` |
| [TestNonAppCallInnerTxnApplyDataOnErr](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/simulation/simulation_eval_test.go#L7676) | matched-1:many | `docs/phase17/parity_ledger_sim.md:55` |
| [TestOptionalSignatures](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/simulation/simulation_eval_test.go#L6708) | matched-1:1 | `docs/phase17/parity_ledger_sim.md:48` |
| [TestUnnamedResources](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/simulation/simulation_eval_test.go#L7957) | matched-1:many | `docs/phase17/parity_ledger_sim.md:58` |
| [TestTrackerScheduleCommit](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/tracker_test.go#L64) | out-of-scope | `docs/phase17/parity_ledger_core.md:344` |
| [TestTrackers_BusyCommitting](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/tracker_test.go#L410) | out-of-scope | `docs/phase17/parity_ledger_core.md:347` |
| [TestTrackers_InitializeMaxAccountDeltas](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/ledger/tracker_test.go#L461) | out-of-scope | `docs/phase17/parity_ledger_core.md:348` |
| [TestParseHostOrURL](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/addr/addr_test.go#L33) | matched-1:many | `docs/phase17/parity_network.md:5` |
| [TestMakeWsPeerMsgCodec_StatefulRequiresStateless](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/msgCompressor_test.go#L139) | matched-1:many | `docs/phase17/parity_network.md:30` |
| [TestWsPeerMsgDataConverterConvert](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/msgCompressor_test.go#L111) | matched-1:many | `docs/phase17/parity_network.md:29` |
| [TestZstdCompressMsg](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/msgCompressor_test.go#L87) | matched-1:many | `docs/phase17/parity_network.md:28` |
| [TestZstdDecompress](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/msgCompressor_test.go#L67) | matched-1:many | `docs/phase17/parity_network.md:27` |
| [TestIdentityTrackerHandlerGuard](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/netidentity_test.go#L368) | out-of-scope | `docs/phase17/parity_network.md:66` |
| [TestIdentityTrackerSetIdentity](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/netidentity_test.go#L340) | matched-1:1 | `docs/phase17/parity_network.md:65` |
| [TestDnsAddrResolveController](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2p/dnsaddr/resolveController_test.go#L34) | out-of-scope | `docs/phase17/parity_network.md:76` |
| [TestMultiaddrsFromResolverDnsErr](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2p/dnsaddr/resolve_test.go#L88) | matched-1:1 | `docs/phase17/parity_network.md:79` |
| [TestStreamNonDialedOutgoingConnection](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2p/streams_test.go#L111) | matched-1:many | `docs/phase17/parity_network.md:125` |
| [TestP2PBootstrapFunc](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2pNetwork_test.go#L591) | matched-1:many | `docs/phase17/parity_network.md:133` |
| [TestP2PGetPeersTransportConnections](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2pNetwork_test.go#L1712) | matched-1:1 | `docs/phase17/parity_network.md:150` |
| [TestP2PMetainfoExchange](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2pNetwork_test.go#L1656) | matched-1:many | `docs/phase17/parity_network.md:149` |
| [TestP2PSubmitWS](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2pNetwork_test.go#L261) | matched-1:1 | `docs/phase17/parity_network.md:130` |
| [TestP2PVoteCompression](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/p2pNetwork_test.go#L1826) | matched-1:many | `docs/phase17/parity_network.md:152` |
| [TestUncompressedMsgpackDetection](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/vpack/parse_test.go#L194) | matched-1:1 | `docs/phase17/parity_network.md:189` |
| [TestWebsocketProxyWsNet](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/websocketProxy_test.go#L247) | out-of-scope | `docs/phase17/parity_network.md:196` |
| [TestAddrToGossipAddr](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L887) | matched-1:many | `docs/phase17/parity_network.md:209` |
| [TestDiscardUnrequestedBlockResponse](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L4259) | matched-1:many | `docs/phase17/parity_network.md:246` |
| [TestDupFilter](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L1210) | matched-1:many | `docs/phase17/parity_network.md:213` |
| [TestFloodingPeer](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L1027) | out-of-scope | `docs/phase17/parity_network.md:211` |
| [TestHTTPPAddressBoundTransport](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L4843) | out-of-scope | `docs/phase17/parity_network.md:255` |
| [TestNumOutgoingPending](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L5087) | out-of-scope | `docs/phase17/parity_network.md:259` |
| [TestPeeringWithBadIdentityVerification](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L2232) | matched-1:1 | `docs/phase17/parity_network.md:222` |
| [TestPeeringWithIdentityChallenge](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L1486) | matched-1:1 | `docs/phase17/parity_network.md:216` |
| [TestPreparePeerData](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L3949) | matched-1:many | `docs/phase17/parity_network.md:242` |
| [TestSendMessageCallbackDrain](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L4776) | matched-1:many | `docs/phase17/parity_network.md:253` |
| [TestSlowHandlers](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L950) | out-of-scope | `docs/phase17/parity_network.md:210` |
| [TestSlowOutboundPeer](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L1123) | out-of-scope | `docs/phase17/parity_network.md:212` |
| [TestTestingPublicAddress](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L1382) | out-of-scope | `docs/phase17/parity_network.md:215` |
| [TestWebsocketDisconnection](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L3644) | matched-1:many | `docs/phase17/parity_network.md:239` |
| [TestWebsocketProposalPayloadCompression](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsNetwork_test.go#L453) | matched-1:1 | `docs/phase17/parity_network.md:202` |
| [TestPeerReadLoopSwitchAllTags](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/network/wsPeer_test.go#L185) | matched-1:many | `docs/phase17/parity_network.md:266` |
| [TestMaxSizesCorrect](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/node/node_test.go#L841) | matched-1:1 | `docs/phase17/parity_daemon_node.md:118` |
| [TestNodeP2PRelays](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/node/node_test.go#L1066) | matched-1:many | `docs/phase17/parity_daemon_node.md:120` |
| [TestNodeP2P_NetProtoVersions](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/node/node_test.go#L1359) | matched-1:many | `docs/phase17/parity_daemon_node.md:123` |
| [TestSimpleUpgrade](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/node/node_test.go#L399) | matched-1:1 | `docs/phase17/parity_daemon_node.md:111` |
| [TestSyncingFullNode](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/node/node_test.go#L299) | matched-1:many | `docs/phase17/parity_daemon_node.md:109` |
| [TestBlockServiceShutdown](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/rpcs/blockService_test.go#L194) | matched-1:1 | `docs/phase17/parity_daemon_node.md:128` |
| [TestRedirectOnFullCapacity](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/rpcs/blockService_test.go#L252) | matched-1:many | `docs/phase17/parity_daemon_node.md:129` |
| [TestLedgerService](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/rpcs/ledgerService_test.go#L76) | matched-1:many | `docs/phase17/parity_daemon_node.md:134` |
| [TestLedgerServiceP2P](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/rpcs/ledgerService_test.go#L238) | matched-1:1 | `docs/phase17/parity_daemon_node.md:135` |
| [TestRandomizedEncodingEncodedBlockCert](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/rpcs/msgp_gen_test.go#L37) | matched-1:many | `docs/phase17/parity_daemon_node.md:137` |
| [TestMain](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/rpcs/txService_test.go#L40) | out-of-scope | `docs/phase17/parity_daemon_node.md:138` |
| [TestChallenges](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/test/e2e-go/features/incentives/challenge_test.go#L46) | out-of-scope | `docs/phase17/parity_e2e.md:52` |
| [TestBasicPayouts](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/test/e2e-go/features/incentives/payouts_test.go#L42) | out-of-scope | `docs/phase17/parity_e2e.md:53` |
| [TestRekeyUpgrade](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/test/e2e-go/upgrades/rekey_support_test.go#L34) | matched-1:many | `docs/phase17/parity_e2e.md:204` |
| [TestAccountsCanSendMoneyAcrossUpgradeV32toV35](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/test/e2e-go/upgrades/send_receive_upgrade_test.go#L82) | out-of-scope | `docs/phase17/parity_e2e.md:210` |
| [TestEmptyClient](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/client_test.go#L32) | out-of-scope | `docs/phase17/parity_tools_cmd.md:124` |
| [TestLookup](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/dnssec_test.go#L257) | out-of-scope | `docs/phase17/parity_tools_cmd.md:133` |
| [TestLookupAux](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/dnssec_test.go#L533) | out-of-scope | `docs/phase17/parity_tools_cmd.md:134` |
| [TestAuthenticate](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/trustedchain_test.go#L327) | out-of-scope | `docs/phase17/parity_tools_cmd.md:142` |
| [TestEnsureTrustChain](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/trustedchain_test.go#L61) | out-of-scope | `docs/phase17/parity_tools_cmd.md:140` |
| [TestEnsureTrustChainError](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/trustedchain_test.go#L276) | out-of-scope | `docs/phase17/parity_tools_cmd.md:141` |
| [TestTrustChainBasic](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/trustedchain_test.go#L31) | out-of-scope | `docs/phase17/parity_tools_cmd.md:139` |
| [TestMakeTrustedZone](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/trustedzone_test.go#L106) | out-of-scope | `docs/phase17/parity_tools_cmd.md:145` |
| [TestMatchKSKDigest](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/trustedzone_test.go#L286) | out-of-scope | `docs/phase17/parity_tools_cmd.md:147` |
| [TestTrustedZone](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/trustedzone_test.go#L32) | out-of-scope | `docs/phase17/parity_tools_cmd.md:144` |
| [TestVerifyRRSig](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/network/dnssec/trustedzone_test.go#L240) | out-of-scope | `docs/phase17/parity_tools_cmd.md:146` |
| [TestDiffErrors](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/tools/x-repo-types/typeAnalyzer/typeAnalyzer_test.go#L213) | out-of-scope | `docs/phase17/parity_tools_cmd.md:161` |
| [TestLockingTableWhileWritingJournal](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/db/dbutil_test.go#L507) | out-of-scope | `docs/phase17/parity_util.md:30` |
| [TestSetSynchronousMode](https://github.com/algorand/go-algorand/blob/v5.1.1-stable/util/db/dbutil_test.go#L402) | out-of-scope | `docs/phase17/parity_util.md:27` |

