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

// avm-op-protos dumps go-algorand's per-opcode `proto` argument types
// (`data/transactions/logic/opcodes.go`) for every opcode, across EVERY AVM
// version, as JSON lines, so algod-rust's argument gate table
// (`crates/core/algo-avm/src/arg_gate.rs`, issue #2225) and its opcode version
// table are checked against go instead of typed by hand.
//
// One object per opcode name:
//
//	{"opcode": 8, "name": "+", "version": 1, "modes": 3, "stable": true,
//	 "args": [{"avm": "uint64", "name": "uint64"}, ...]}
//
// `version` is the lowest AVM version that has the opcode, `modes` go's
// `RunMode` bit set (1 = LogicSig, 2 = application, 3 = both) and `args` the
// argument types, both as of the newest version (`logic.LogicVersion`). `avm`
// is the AVM type the gate compares (`any`, `uint64`, `[]byte`) and `name` the
// `StackType.String()` go prints in `<op> arg <i> wanted <name> but got <type>`.
// `stable` is true when the mode set AND the argument types are identical in
// every version that has the opcode. Otherwise `variants` lists the distinct
// (modes, args) from the version each starts at (`ed25519verify` is LogicSig
// only before v5), because a program of an older version meets the older spec.
//
// Regenerate (go-algorand pin v5.0.5-stable, deterministic):
//
//	cd tools/avm-op-protos && go run . > ../../crates/core/algo-avm/tests/fixtures/go_op_protos.jsonl
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/algorand/go-algorand/data/transactions/logic"
)

type arg struct {
	AVM  string `json:"avm"`
	Name string `json:"name"`
}

type variant struct {
	From  uint64 `json:"from"`
	Modes int    `json:"modes"`
	Args  []arg  `json:"args"`
}

type row struct {
	Opcode  int    `json:"opcode"`
	Name    string `json:"name"`
	Version uint64 `json:"version"`
	// Modes is go's `RunMode` bit set: 1 = LogicSig only, 2 = application
	// only, 3 = both.
	Modes    int       `json:"modes"`
	Stable   bool      `json:"stable"`
	Args     []arg     `json:"args"`
	Variants []variant `json:"variants,omitempty"`
}

func argsOf(s logic.OpSpec) []arg {
	out := []arg{}
	for _, t := range s.Arg.Types {
		out = append(out, arg{AVM: t.AVMType.String(), Name: t.String()})
	}
	return out
}

func signature(s logic.OpSpec) string {
	parts := []string{fmt.Sprint(int(s.Modes))}
	for _, a := range argsOf(s) {
		parts = append(parts, a.AVM+"/"+a.Name)
	}
	return strings.Join(parts, " ")
}

func main() {
	latest := logic.OpsByName[logic.LogicVersion]
	names := make([]string, 0, len(latest))
	for n := range latest {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		a, b := latest[names[i]], latest[names[j]]
		if a.Opcode != b.Opcode {
			return a.Opcode < b.Opcode
		}
		return names[i] < names[j]
	})
	enc := json.NewEncoder(os.Stdout)
	for _, n := range names {
		s := latest[n]
		r := row{Opcode: int(s.Opcode), Name: n, Modes: int(s.Modes), Stable: true, Args: argsOf(s)}
		var last string
		for v := uint64(1); v <= logic.LogicVersion; v++ {
			spec, ok := logic.OpsByName[v][n]
			if !ok {
				continue
			}
			if r.Version == 0 {
				r.Version = v
			}
			sig := signature(spec)
			if sig != last {
				r.Variants = append(r.Variants, variant{From: v, Modes: int(spec.Modes), Args: argsOf(spec)})
				last = sig
			}
		}
		if len(r.Variants) <= 1 {
			r.Variants = nil
		} else {
			r.Stable = false
		}
		if err := enc.Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
