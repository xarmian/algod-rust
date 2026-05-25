// kmd-api-wire-capture emits a snapshot of go-algorand's kmd v1 JSON
// wire format for a representative set of request and response shapes.
// The output is consumed by `algo-kmd-api-types`' integration test
// (TASK-209), which parses each section into the Rust struct and
// asserts semantic round-trip equality.
//
// The exact bytes matter — Go's `protocol.EncodeJSON` uses go-codec's
// JsonHandle with `Canonical=true`, `Indent=2`, and HTML-chars-as-is.
// The Rust crate's responsibility is "parses cleanly and round-trips
// to the same Value", not byte-equality (canonical pretty-printing
// happens at the server response writer in TASK-213).
//
// Regenerate with:
//
//	cd tools/kmd-api-wire-capture && go run . \
//	    > ../../crates/node/algo-kmd-api-types/tests/fixtures/go_wire_samples.txt
//
// Each section is delimited by a `# <name>` header line so the Rust
// test can split on those headers.
package main

import (
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/kmd/lib/kmdapi"
	"github.com/algorand/go-algorand/protocol"
)

func main() {
	var mdk crypto.MasterDerivationKey
	for i := range mdk {
		mdk[i] = byte(i + 1)
	}
	var pk crypto.PublicKey
	for i := range pk {
		pk[i] = byte(0x40 + i)
	}
	var sk crypto.PrivateKey
	for i := range sk {
		sk[i] = byte(i)
	}

	emit("masterkey-export-response", kmdapi.APIV1POSTMasterKeyExportResponse{
		MasterDerivationKey: mdk,
	})

	emit("list-wallets-response", kmdapi.APIV1GETWalletsResponse{
		Wallets: []kmdapi.APIV1Wallet{
			{
				ID:                    "wid-1",
				Name:                  "alpha",
				DriverName:            "sqlite",
				DriverVersion:         1,
				SupportsMnemonicUX:    false,
				SupportedTransactions: []protocol.TxType{"pay", "keyreg"},
			},
		},
	})

	emit("init-wallet-error-response", kmdapi.APIV1POSTWalletInitResponse{
		APIV1ResponseEnvelope: kmdapi.APIV1ResponseEnvelope{Error: true, Message: "wrong password"},
	})

	emit("key-export-response", kmdapi.APIV1POSTKeyExportResponse{PrivateKey: sk})

	emit("multisig-export-response", kmdapi.APIV1POSTMultisigExportResponse{
		Version:   1,
		Threshold: 2,
		PKs:       []kmdapi.APIV1PublicKey{pk, pk},
	})

	emit("versions-response", kmdapi.VersionsResponse{Versions: []string{"v1"}})
}

func emit(name string, v interface{}) {
	fmt.Printf("# %s\n%s\n", name, string(protocol.EncodeJSON(v)))
}
