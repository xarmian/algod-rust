// Golden vector generator for algo-agreement Rust conformance tests.
//
// This program cannot be compiled standalone because it references unexported
// types from go-algorand's agreement and committee packages. Instead, the
// actual Go test files have been created inside the go-algorand source tree
// and were run to produce real output:
//
//   # For selector, rawVote, proposerSeed, seedInput, seed:
//   cd ../go-algorand && go test -run TestGoldenVectors -v ./agreement/
//
//   # For hashableCredential:
//   cd ../go-algorand && go test -run TestGoldenHashableCredential -v ./data/committee/
//
// The Go test files live at:
//   ../go-algorand/agreement/golden_vectors_test.go
//   ../go-algorand/data/committee/golden_vectors_test.go
//
// These files were created and run on 2026-03-16 against go-algorand v4.6.0-stable.
// All output was captured and verified against the Rust constants in:
//   crates/core/algo-agreement/src/golden_vectors.rs
//
// To regenerate, re-run the go test commands above and compare the output
// hex strings against the Rust constants.
//
// ============================================================================
// Captured Go output (2026-03-16, go-algorand v4.6.0-stable):
// ============================================================================
//
// === From: go test -run TestGoldenVectors -v ./agreement/ ===
//
// SELECTOR_ENCODING=84a370657201a3726e642aa473656564c4200101010101010101010101010101010101010101010101010101010101010101a47374657002
// SELECTOR_DIGEST=7c8b20aa6c626486d0ff1102373608105a18cf493c07ab21e72e0c1e71fd61d1
// RAWVOTE_ENCODING=85a370657201a470726f7084a3646967c420aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa6656e63646967c420bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbba46f70657201a56f70726f70c4204242424242424242424242424242424242424242424242424242424242424242a3726e6464a3736e64c4204242424242424242424242424242424242424242424242424242424242424242a47374657002
// RAWVOTE_DIGEST=657761e958a6a140e8637f727bc5d0eb0e13a6cd823f0be2f87418093ca8ef4c
// PROPOSERSEED_ENCODING=82a461646472c4201111111111111111111111111111111111111111111111111111111111111111a3767266c44022222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222
// PROPOSERSEED_DIGEST=828ecad04bad2b25f907593d67d3d49df57c8ff397b61a97f9cc0485618d0889
// SEEDINPUT_ENCODING=82a5616c706861c4203333333333333333333333333333333333333333333333333333333333333333a468697374c4204444444444444444444444444444444444444444444444444444444444444444
// SEEDINPUT_DIGEST=eb82d92e7351392da0390d314f83a69bd9f269486e34b93dcf2bbe27a3d7e64f
// SEED_ENCODING=7777777777777777777777777777777777777777777777777777777777777777
// SEED_DIGEST=718a907fa3addcd56ca30ba5768b49b6e4b47dea6c1805be214db6c01c689745
//
// === From: go test -run TestGoldenHashableCredential -v ./data/committee/ ===
//
// CREDENTIAL_ENCODING=83a16901a16dc4206666666666666666666666666666666666666666666666666666666666666666a176c44055555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555
// CREDENTIAL_DIGEST=c278c090d775282c0346c3c1b2ba904e82eea9622ed201780c0ace5e14427bad
//
// ============================================================================
// Go test source (agreement/golden_vectors_test.go):
// ============================================================================
//
// package agreement
//
// import (
//     "encoding/hex"
//     "fmt"
//     "testing"
//     "github.com/algorand/go-algorand/crypto"
//     "github.com/algorand/go-algorand/data/basics"
//     "github.com/algorand/go-algorand/data/committee"
//     "github.com/algorand/go-algorand/protocol"
// )
//
// func TestGoldenVectors(t *testing.T) {
//     // Selector: Seed=[0x01;32], Round=42, Period=1, Step=2
//     var selSeed committee.Seed
//     for i := range selSeed { selSeed[i] = 0x01 }
//     sel := selector{
//         Seed:   selSeed,
//         Round:  basics.Round(42),
//         Period: period(1),
//         Step:   step(2),
//     }
//     selEnc := protocol.Encode(&sel)
//     selDigest := crypto.HashObj(sel)
//     fmt.Printf("SELECTOR_ENCODING=%s\n", hex.EncodeToString(selEnc))
//     fmt.Printf("SELECTOR_DIGEST=%s\n", hex.EncodeToString(selDigest[:]))
//
//     // RawVote: Sender=[0x42;32], Round=100, Period=1, Step=2
//     var sender basics.Address
//     for i := range sender { sender[i] = 0x42 }
//     var blockDigest crypto.Digest
//     for i := range blockDigest { blockDigest[i] = 0xaa }
//     var encDigest crypto.Digest
//     for i := range encDigest { encDigest[i] = 0xbb }
//     rv := rawVote{
//         Sender: sender, Round: basics.Round(100), Period: period(1), Step: step(2),
//         Proposal: proposalValue{
//             OriginalPeriod: period(1), OriginalProposer: sender,
//             BlockDigest: blockDigest, EncodingDigest: encDigest,
//         },
//     }
//     rvEnc := protocol.Encode(&rv)
//     rvDigest := crypto.HashObj(rv)
//     fmt.Printf("RAWVOTE_ENCODING=%s\n", hex.EncodeToString(rvEnc))
//     fmt.Printf("RAWVOTE_DIGEST=%s\n", hex.EncodeToString(rvDigest[:]))
//
//     // ProposerSeed: Addr=[0x11;32], VRF=[0x22;64]
//     var psAddr basics.Address
//     for i := range psAddr { psAddr[i] = 0x11 }
//     var psVrf crypto.VrfOutput
//     for i := range psVrf { psVrf[i] = 0x22 }
//     ps := proposerSeed{Addr: psAddr, VRF: psVrf}
//     psEnc := protocol.Encode(&ps)
//     psDigest := crypto.HashObj(ps)
//     fmt.Printf("PROPOSERSEED_ENCODING=%s\n", hex.EncodeToString(psEnc))
//     fmt.Printf("PROPOSERSEED_DIGEST=%s\n", hex.EncodeToString(psDigest[:]))
//
//     // SeedInput: Alpha=[0x33;32], History=[0x44;32]
//     var alpha crypto.Digest
//     for i := range alpha { alpha[i] = 0x33 }
//     var hist crypto.Digest
//     for i := range hist { hist[i] = 0x44 }
//     si := seedInput{Alpha: alpha, History: hist}
//     siEnc := protocol.Encode(&si)
//     siDigest := crypto.HashObj(si)
//     fmt.Printf("SEEDINPUT_ENCODING=%s\n", hex.EncodeToString(siEnc))
//     fmt.Printf("SEEDINPUT_DIGEST=%s\n", hex.EncodeToString(siDigest[:]))
//
//     // Seed: [0x77;32]
//     var seedVal committee.Seed
//     for i := range seedVal { seedVal[i] = 0x77 }
//     seedDigest := crypto.HashObj(seedVal)
//     fmt.Printf("SEED_ENCODING=%s\n", hex.EncodeToString(seedVal[:]))
//     fmt.Printf("SEED_DIGEST=%s\n", hex.EncodeToString(seedDigest[:]))
// }
//
// ============================================================================
// Go test source (data/committee/golden_vectors_test.go):
// ============================================================================
//
// package committee
//
// import (
//     "encoding/hex"
//     "fmt"
//     "testing"
//     "github.com/algorand/go-algorand/crypto"
//     "github.com/algorand/go-algorand/data/basics"
//     "github.com/algorand/go-algorand/protocol"
// )
//
// func TestGoldenHashableCredential(t *testing.T) {
//     var rawOut crypto.VrfOutput
//     for i := range rawOut { rawOut[i] = 0x55 }
//     var member basics.Address
//     for i := range member { member[i] = 0x66 }
//     hc := hashableCredential{RawOut: rawOut, Member: member, Iter: 1}
//     enc := protocol.Encode(&hc)
//     digest := crypto.HashObj(hc)
//     fmt.Printf("CREDENTIAL_ENCODING=%s\n", hex.EncodeToString(enc))
//     fmt.Printf("CREDENTIAL_DIGEST=%s\n", hex.EncodeToString(digest[:]))
// }

package main

func main() {
	// This file is documentation only. The actual Go test files live at:
	//   ../go-algorand/agreement/golden_vectors_test.go
	//   ../go-algorand/data/committee/golden_vectors_test.go
	// See comments above for how to run them.
	panic("This program cannot be compiled standalone. See comments for instructions.")
}
