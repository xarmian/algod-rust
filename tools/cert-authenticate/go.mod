module github.com/xarmian/algod-rust/tools/cert-authenticate

go 1.25.0

// go-algorand is pinned to v4.6.0-stable via the `replace` directive below.
// The `v0.0.0` placeholder matches the pattern used by the sibling capture
// tools (avm-opcode-capture, go-trie-replay-bench, …) and has no effect once
// the replace fires.
//
// NOTE: building this tool links go-algorand's vendored libsodium fork via
// cgo, so `make libsodium` must have been run in the sibling go-algorand
// checkout first. `run-in-docker.sh` does that inside a Linux container,
// which is the only supported path on Windows.
require github.com/algorand/go-algorand v0.0.0

replace github.com/algorand/go-algorand => ../../../go-algorand
