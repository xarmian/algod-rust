package main

import (
	"os"
	"path/filepath"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-codec/codec"
)

func enc(h codec.Handle, v interface{}) []byte { var o []byte; codec.NewEncoderBytes(&o, h).MustEncode(v); return o }

func main() {
	out := os.Args[1]
	addr := func(b byte) (a basics.Address) { a[0] = b; a[31] = b ^ 0xff; return }
	d32 := func(b byte) (d [32]byte) { d[0] = b; return }

	// Standalone asset (GET /v2/assets/{id}) — same params as the with_assets account fixture.
	ap := basics.AssetParams{
		Total: 1000000, Decimals: 6, UnitName: "TST", AssetName: "Test Asset",
		URL: "https://x.io", MetadataHash: d32(0xAB),
		Manager: addr(0x33), Reserve: addr(0x44), Freeze: addr(0x55), Clawback: addr(0x66),
		DefaultFrozen: true,
	}
	asset := v2.AssetParamsToAsset(addr(0x33).String(), 7, &ap)
	os.WriteFile(filepath.Join(out, "asset.json"), enc(protocol.JSONStrictHandle, &asset), 0644)

	// Standalone application (GET /v2/applications/{id}) — same params as with_apps.
	app := basics.AppParams{
		ApprovalProgram: []byte{0x06, 0x81, 0x01}, ClearStateProgram: []byte{0x06, 0x81, 0x01},
		GlobalState: basics.TealKeyValue{"g": {Type: basics.TealUintType, Uint: 7}},
		StateSchemas: basics.StateSchemas{
			LocalStateSchema:  basics.StateSchema{NumUint: 1},
			GlobalStateSchema: basics.StateSchema{NumByteSlice: 1}},
		ExtraProgramPages: 1,
	}
	application := v2.AppParamsToApplication(addr(0x44).String(), 8, &app)
	os.WriteFile(filepath.Join(out, "application.json"), enc(protocol.JSONStrictHandle, &application), 0644)
	println("generated standalone asset + app")
}
