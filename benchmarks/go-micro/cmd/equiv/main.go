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

// Command equiv runs every micro pair's operation once on its fixture with
// go-algorand and prints a JSON object {pair id: output digest} (issue
// #2103). The Rust counterpart is `cargo run -p algo-bench-pairs --bin
// micro-equiv`; scripts/bench/micro_equiv.py compares the two and the micro
// tier fails on any difference. -write also stores the result as the
// expected digests the Rust unit test checks against
// (benchmarks/fixtures/micro/go-digests.json).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/xarmian/algod-rust/benchmarks/go-micro/micro"
)

func main() {
	dir := flag.String("fixtures", "../fixtures/micro", "fixture directory")
	write := flag.String("write", "", "also write the digests to this file")
	flag.Parse()

	out := map[string]string{}
	failed := false
	for _, id := range micro.IDs() {
		c, err := micro.Build(*dir, id)
		if err == nil {
			out[id], err = c.Digest()
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "equiv: %s: %v\n", id, err)
			out[id] = "error:" + err.Error()
			failed = true
		}
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		panic(err)
	}
	b = append(b, '\n')
	os.Stdout.Write(b)
	if *write != "" {
		if err := os.WriteFile(*write, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if failed {
		os.Exit(1)
	}
}
