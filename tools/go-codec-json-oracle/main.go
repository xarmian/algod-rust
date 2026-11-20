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

// Command go-codec-json-oracle is the parity oracle of algod-rust issue
// #2466: it decodes algod answer bodies exactly as go-algorand
// v5.0.5-stable's restClient.submitForm does
// (protocol.NewJSONDecoder over an http.MaxBytesReader, Decode(&response)
// with response an `any` holding a pointer to the answer type) and prints
// what that made of each.
//
// Input: JSON lines {"ty": "account"|"version"|"status"|"supply",
// "body": <base64>}. Output: the same lines plus "err" (go-codec's error
// text, or null) and "value" (the decoded struct as encoding/json prints
// it, or null on an error). It writes
// crates/tools/goal-rust/tests/fixtures/go_codec_json_decode.jsonl, which
// tests/go_codec_json_parity.rs compares goal-rust's port against.
//
// Build inside a go-algorand checkout (its crypto package needs the
// vendored libsodium: `make libsodium` first):
//
//	mkdir -p ../go-algorand/cmd/go-codec-json-oracle
//	cp tools/go-codec-json-oracle/main.go ../go-algorand/cmd/go-codec-json-oracle/
//	(cd ../go-algorand && go build -o /tmp/go-codec-json-oracle ./cmd/go-codec-json-oracle)
//	/tmp/go-codec-json-oracle < crates/tools/goal-rust/tests/fixtures/go_codec_json_decode.jsonl > /tmp/out.jsonl
//
// A body go-codec never finishes decoding (an array cut after a comma:
// each element reads the comma again, the slice grows until the process
// runs out of memory) makes the oracle hang; keep such bodies out of the
// corpus.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/daemon/algod/api/spec/common"
	"github.com/algorand/go-algorand/protocol"
)

type row struct {
	Ty    string          `json:"ty"`
	Body  string          `json:"body"`
	Err   *string         `json:"err"`
	Value json.RawMessage `json:"value"`
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		var in row
		if err := json.Unmarshal(sc.Bytes(), &in); err != nil {
			panic(err)
		}
		body, err := base64.StdEncoding.DecodeString(in.Body)
		if err != nil {
			panic(err)
		}
		var target any
		switch in.Ty {
		case "account":
			target = &model.Account{}
		case "version":
			target = &common.Version{}
		case "status":
			target = &model.NodeStatusResponse{}
		case "supply":
			target = &model.SupplyResponse{}
		default:
			panic(in.Ty)
		}
		// as restClient.submitForm: the body behind a MaxBytesReader (no
		// io.ByteScanner, so go-codec reads it one byte at a time)
		response := target
		r := http.MaxBytesReader(nil, io.NopCloser(bytes.NewReader(body)), 50e6)
		out := row{Ty: in.Ty, Body: in.Body}
		if err := protocol.NewJSONDecoder(r).Decode(&response); err != nil {
			s := err.Error()
			out.Err = &s
		} else {
			out.Value, _ = json.Marshal(target)
		}
		b, _ := json.Marshal(out)
		w.Write(b)
		w.WriteByte('\n')
		w.Flush()
	}
}
