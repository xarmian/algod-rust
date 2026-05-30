package main

import (
	"os"
	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-codec/codec"
)

type EncodedBlockCert struct {
	Block bookkeeping.Block     `codec:"block"`
	Cert  agreement.Certificate `codec:"cert"`
}
type BlockResponseJSON struct {
	Block bookkeeping.Block `codec:"block"`
}

func main() {
	raw, _ := os.ReadFile(os.Args[1])
	var ebc EncodedBlockCert
	codec.NewDecoderBytes(raw, protocol.CodecHandle).Decode(&ebc)

	var snd, rcv basics.Address
	snd[0], snd[31] = 0x11, 0x22
	rcv[0], rcv[31] = 0x33, 0x44

	// App-call txn with a rich EvalDelta: global+local deltas, logs, inner txn.
	appl := transactions.SignedTxnInBlock{
		SignedTxnWithAD: transactions.SignedTxnWithAD{
			SignedTxn: transactions.SignedTxn{
				Txn: transactions.Transaction{
					Type:   protocol.ApplicationCallTx,
					Header: transactions.Header{Sender: snd, Fee: basics.MicroAlgos{Raw: 1000}, FirstValid: 1, LastValid: 1001, Note: []byte{0xCA, 0xFE}},
					ApplicationCallTxnFields: transactions.ApplicationCallTxnFields{
						ApplicationID: 555,
						Accounts:      []basics.Address{rcv},
						ApplicationArgs: [][]byte{{0x01, 0x02}, []byte("arg")},
					},
				},
			},
			ApplyData: transactions.ApplyData{
				EvalDelta: transactions.EvalDelta{
					GlobalDelta: basics.StateDelta{
						"gkey":   {Action: basics.SetBytesAction, Bytes: "gval"},
						"cnt":    {Action: basics.SetUintAction, Uint: 9},
						"z\xff": {Action: basics.SetUintAction, Uint: 1},
					},
					LocalDeltas: map[uint64]basics.StateDelta{
						1:  {"lk": {Action: basics.SetUintAction, Uint: 3}},
						2:  {"lk": {Action: basics.SetUintAction, Uint: 4}},
						10: {"lk": {Action: basics.SetUintAction, Uint: 5}},
						11: {"lk": {Action: basics.SetUintAction, Uint: 6}},
					},
					Logs: []string{"log-a", "\x00\xff"},
					InnerTxns: []transactions.SignedTxnWithAD{
						{SignedTxn: transactions.SignedTxn{Txn: transactions.Transaction{
							Type:             protocol.PaymentTx,
							Header:           transactions.Header{Sender: snd, Fee: basics.MicroAlgos{Raw: 1000}},
							PaymentTxnFields: transactions.PaymentTxnFields{Receiver: rcv, Amount: basics.MicroAlgos{Raw: 7}},
						}}},
					},
				},
				ApplicationID: 555,
			},
		},
		HasGenesisID: true,
	}
	ebc.Block.Payset = transactions.Payset{appl}

	// msgpack input ({block, cert})
	var mp []byte
	codec.NewEncoderBytes(&mp, protocol.CodecHandle).MustEncode(&ebc)
	os.WriteFile(os.Args[2], mp, 0644)
	// JSON golden
	var js []byte
	codec.NewEncoderBytes(&js, protocol.JSONStrictHandle).MustEncode(&BlockResponseJSON{Block: ebc.Block})
	os.WriteFile(os.Args[3], js, 0644)
}
