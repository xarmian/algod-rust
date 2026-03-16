// Golden vector generator for algo-agreement Rust conformance tests.
//
// This program cannot be compiled standalone because it references unexported
// types from go-algorand's agreement and committee packages. Instead, it was
// placed inside the go-algorand source tree as test files and run with:
//
//   # For selector, rawVote, proposerSeed, seedInput:
//   cd ../go-algorand && go test -run TestGoldenVectors -v ./agreement/
//
//   # For hashableCredential:
//   cd ../go-algorand && go test -run TestGoldenHashableCredential -v ./data/committee/
//
// The test files used are shown below. Generated output (hex encodings and
// SHA-512/256 digests) is captured in the Rust test file:
//   crates/core/algo-agreement/src/golden_vectors.rs
//
// ============================================================================
// agreement/golden_vectors_test.go
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
//     sel := selector{Seed: selSeed, Round: 42, Period: 1, Step: 2}
//     fmt.Printf("selector_encoding: %s\n", hex.EncodeToString(protocol.Encode(&sel)))
//     fmt.Printf("selector_digest: %s\n", hex.EncodeToString(crypto.HashObj(sel)[:]))
//
//     // RawVote: Sender=[0x42;32], Round=100, Period=1, Step=2,
//     //   Proposal{OriginalPeriod=1, OriginalProposer=[0x42;32],
//     //            BlockDigest=[0xaa;32], EncodingDigest=[0xbb;32]}
//     var sender basics.Address
//     for i := range sender { sender[i] = 0x42 }
//     var blockDig, encDig crypto.Digest
//     for i := range blockDig { blockDig[i] = 0xaa }
//     for i := range encDig { encDig[i] = 0xbb }
//     rv := rawVote{Sender: sender, Round: 100, Period: 1, Step: 2,
//         Proposal: proposalValue{OriginalPeriod: 1, OriginalProposer: sender,
//             BlockDigest: blockDig, EncodingDigest: encDig}}
//     fmt.Printf("raw_vote_encoding: %s\n", hex.EncodeToString(protocol.Encode(&rv)))
//     fmt.Printf("raw_vote_digest: %s\n", hex.EncodeToString(crypto.HashObj(rv)[:]))
//
//     // ProposerSeed: Addr=[0x11;32], VRF=[0x22;64]
//     var psAddr basics.Address
//     for i := range psAddr { psAddr[i] = 0x11 }
//     var psVrf crypto.VrfOutput
//     for i := range psVrf { psVrf[i] = 0x22 }
//     ps := proposerSeed{Addr: psAddr, VRF: psVrf}
//     fmt.Printf("proposer_seed_encoding: %s\n", hex.EncodeToString(protocol.Encode(&ps)))
//     fmt.Printf("proposer_seed_digest: %s\n", hex.EncodeToString(crypto.HashObj(ps)[:]))
//
//     // SeedInput: Alpha=[0x33;32], History=[0x44;32]
//     var alpha, hist crypto.Digest
//     for i := range alpha { alpha[i] = 0x33 }
//     for i := range hist { hist[i] = 0x44 }
//     si := seedInput{Alpha: alpha, History: hist}
//     fmt.Printf("seed_input_encoding: %s\n", hex.EncodeToString(protocol.Encode(&si)))
//     fmt.Printf("seed_input_digest: %s\n", hex.EncodeToString(crypto.HashObj(si)[:]))
//
//     // Seed: [0x77;32]
//     var seed committee.Seed
//     for i := range seed { seed[i] = 0x77 }
//     fmt.Printf("seed_encoding: %s\n", hex.EncodeToString(seed[:]))
//     fmt.Printf("seed_digest: %s\n", hex.EncodeToString(crypto.HashObj(seed)[:]))
// }
//
// ============================================================================
// data/committee/golden_vectors_test.go
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
//     fmt.Printf("hashable_credential_encoding: %s\n", hex.EncodeToString(protocol.Encode(&hc)))
//     fmt.Printf("hashable_credential_digest: %s\n", hex.EncodeToString(crypto.HashObj(hc)[:]))
// }

package main

func main() {
	// This file is documentation only. The actual test code must be run
	// inside the go-algorand source tree as shown above.
	panic("This program cannot be compiled standalone. See comments for instructions.")
}
