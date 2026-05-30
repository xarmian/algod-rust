package main

import (
	"fmt"
	"os"
	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-codec/codec"
)

type EncodedBlockCert struct {
	Block bookkeeping.Block   `codec:"block"`
	Cert  agreement.Certificate `codec:"cert"`
}
type BlockResponseJSON struct {
	Block bookkeeping.Block `codec:"block"`
}

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil { panic(err) }
	var ebc EncodedBlockCert
	dec := codec.NewDecoderBytes(raw, protocol.CodecHandle)
	if err := dec.Decode(&ebc); err != nil { panic(err) }
	var out []byte
	enc := codec.NewEncoderBytes(&out, protocol.JSONStrictHandle)
	if err := enc.Encode(&BlockResponseJSON{Block: ebc.Block}); err != nil { panic(err) }
	fmt.Print(string(out))
}
