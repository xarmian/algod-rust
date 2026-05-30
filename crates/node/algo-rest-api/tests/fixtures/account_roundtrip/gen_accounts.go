package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand/config"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-codec/codec"
)

func enc(h codec.Handle, v interface{}) []byte { var o []byte; codec.NewEncoderBytes(&o, h).MustEncode(v); return o }

type spec struct {
	name    string
	addr    basics.Address
	round   basics.Round
	awpr    uint64 // amountWithoutPendingRewards
	rec     basics.AccountData
}

func main() {
	out := os.Args[1]
	cons := config.Consensus[protocol.ConsensusCurrentVersion]

	addr := func(b byte) (a basics.Address) { a[0] = b; a[31] = b ^ 0xff; return }
	d32 := func(b byte) (d [32]byte) { d[0] = b; return }

	specs := []spec{
		{
			name: "offline_minimal", addr: addr(0x11), round: 100, awpr: 1000000,
			rec: basics.AccountData{MicroAlgos: basics.MicroAlgos{Raw: 1000000}, Status: basics.Offline},
		},
		{
			name: "online_participation", addr: addr(0x22), round: 5000, awpr: 4999000,
			rec: basics.AccountData{
				MicroAlgos: basics.MicroAlgos{Raw: 5000000}, Status: basics.Online,
				RewardedMicroAlgos: basics.MicroAlgos{Raw: 1234}, RewardsBase: 7,
				VoteID: d32(0x01), SelectionID: d32(0x02), StateProofID: [64]byte{0x03},
				VoteFirstValid: 1, VoteLastValid: 10000, VoteKeyDilution: 100,
				IncentiveEligible: true,
			},
		},
		{
			name: "with_assets", addr: addr(0x33), round: 200, awpr: 2000000,
			rec: basics.AccountData{
				MicroAlgos: basics.MicroAlgos{Raw: 2000000}, Status: basics.Offline,
				AuthAddr: addr(0x99),
				Assets: map[basics.AssetIndex]basics.AssetHolding{
					10: {Amount: 500, Frozen: true},
					2:  {Amount: 9, Frozen: false},
				},
				AssetParams: map[basics.AssetIndex]basics.AssetParams{
					7: {Total: 1000000, Decimals: 6, UnitName: "TST", AssetName: "Test Asset",
						URL: "https://x.io", MetadataHash: d32(0xAB),
						Manager: addr(0x33), Reserve: addr(0x44), Freeze: addr(0x55), Clawback: addr(0x66),
						DefaultFrozen: true},
				},
			},
		},
		{
			name: "with_apps", addr: addr(0x44), round: 300, awpr: 3000000,
			rec: basics.AccountData{
				MicroAlgos: basics.MicroAlgos{Raw: 3000000}, Status: basics.Offline,
				TotalAppSchema: basics.StateSchema{NumUint: 3, NumByteSlice: 2}, TotalExtraAppPages: 1,
				AppLocalStates: map[basics.AppIndex]basics.AppLocalState{
					5: {Schema: basics.StateSchema{NumUint: 1}, KeyValue: basics.TealKeyValue{
						"k": {Type: basics.TealUintType, Uint: 9},
						"b": {Type: basics.TealBytesType, Bytes: "v"},
					}},
				},
				AppParams: map[basics.AppIndex]basics.AppParams{
					8: {ApprovalProgram: []byte{0x06, 0x81, 0x01}, ClearStateProgram: []byte{0x06, 0x81, 0x01},
						GlobalState: basics.TealKeyValue{"g": {Type: basics.TealUintType, Uint: 7}},
						StateSchemas: basics.StateSchemas{
							LocalStateSchema:  basics.StateSchema{NumUint: 1},
							GlobalStateSchema: basics.StateSchema{NumByteSlice: 1}},
						ExtraProgramPages: 1},
				},
			},
		},
	}

	for _, s := range specs {
		acct, err := v2.AccountDataToAccount(s.addr.String(), &s.rec, s.round, &cons, basics.MicroAlgos{Raw: s.awpr})
		if err != nil { panic(err) }
		os.WriteFile(filepath.Join(out, s.name+".account.json"), enc(protocol.JSONStrictHandle, &acct), 0644)
		os.WriteFile(filepath.Join(out, s.name+".accountdata.msgpack"), enc(protocol.CodecHandle, &s.rec), 0644)
		meta, _ := json.Marshal(map[string]interface{}{"address": s.addr.String(), "round": s.round, "amount_without_pending_rewards": s.awpr})
		os.WriteFile(filepath.Join(out, s.name+".meta.json"), meta, 0644)
	}
	println("generated", len(specs), "account fixtures")
}
