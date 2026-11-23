// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command dt-nesting-oracle is the parity oracle of algod-rust issue #2539:
// it decodes a block whose one transaction carries an eval delta (`dt`)
// nested N inner-transaction levels deep (`dt` -> `itx` -> `dt` -> ...), as
// go-algorand v5.1.1-stable's protocol.Decode does, and prints the error (or
// null) and go's canonical re-encode of what it decoded. The deepest delta
// holds a non-UTF-8 `gd` key (a msgpack `bin`) so that a path that stops
// re-typing `str` positions at some depth shows up as different bytes.
//
// Output: JSON lines {"depth": N, "body": <base64>, "err": string|null,
// "reencoded": <base64>|null}, written to
// crates/core/algo-codec/tests/fixtures/dt_nesting_go.jsonl, which
// tests/dt_nesting_go_parity.rs (algo-codec) compares the Rust decoders against.
//
// Build inside a go-algorand checkout (`make libsodium` first):
//
//	mkdir -p ../go-algorand/cmd/dt-nesting-oracle
//	cp tools/dt-nesting-oracle/main.go ../go-algorand/cmd/dt-nesting-oracle/
//	(cd ../go-algorand && go build -o /tmp/dt-nesting-oracle ./cmd/dt-nesting-oracle)
//	/tmp/dt-nesting-oracle > crates/core/algo-codec/tests/fixtures/dt_nesting_go.jsonl
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/msgp/msgp"
)

var depths = []int{0, 1, 2, 8, 20, 40, 60, 63, 64, 65, 66, 70, 85, 100, 110, 118, 119, 120, 121, 122, 123, 124, 125, 150, 300}

func str(b []byte, s string) []byte { return msgp.AppendString(b, s) }

// txn appends the `txn` entry go requires on every (inner) transaction.
func txn(b []byte) []byte {
	b = str(b, "txn")
	b = msgp.AppendMapHeader(b, 2)
	b = str(b, "snd")
	b = msgp.AppendBytes(b, bytes.Repeat([]byte{7}, 32))
	b = str(b, "type")
	return str(b, "pay")
}

// delta returns a dt holding n further levels below it.
func delta(n int) []byte {
	var b []byte
	if n == 0 {
		b = msgp.AppendMapHeader(b, 1)
		b = str(b, "gd")
		b = msgp.AppendMapHeader(b, 1)
		b = msgp.AppendBytes(b, []byte{0xff, 0xfe}) // a bin key where go has a str
		b = msgp.AppendMapHeader(b, 2)
		b = str(b, "at")
		b = msgp.AppendUint64(b, 1)
		b = str(b, "bs")
		b = msgp.AppendBytes(b, []byte{0x80})
		return b
	}
	b = msgp.AppendMapHeader(b, 1)
	b = str(b, "itx")
	b = msgp.AppendArrayHeader(b, 1)
	b = msgp.AppendMapHeader(b, 2)
	b = txn(b)
	b = str(b, "dt")
	return append(b, delta(n-1)...)
}

func body(n int) []byte {
	var b []byte
	b = msgp.AppendMapHeader(b, 1)
	b = str(b, "txns")
	b = msgp.AppendArrayHeader(b, 1)
	b = msgp.AppendMapHeader(b, 2)
	b = txn(b)
	b = str(b, "dt")
	return append(b, delta(n)...)
}

func main() {
	enc := json.NewEncoder(os.Stdout)
	for _, n := range depths {
		in := body(n)
		var blk bookkeeping.Block
		row := map[string]any{"depth": n, "body": base64.StdEncoding.EncodeToString(in), "err": nil, "reencoded": nil}
		if err := protocol.Decode(in, &blk); err != nil {
			row["err"] = err.Error()
		} else {
			row["reencoded"] = base64.StdEncoding.EncodeToString(protocol.Encode(&blk))
		}
		if err := enc.Encode(row); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
