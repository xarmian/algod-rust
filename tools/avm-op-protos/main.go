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

// avm-op-protos: dump go-algorand's per-opcode `proto` argument types
// (`data/transactions/logic/opcodes.go`) for AVM version 13 (the newest algod-rust implements), as JSON
// lines, so algod-rust's argument gate table (`crates/core/algo-avm/src/
// arg_gate.rs`, issue #2225) is checked against go instead of being typed by
// hand. Output: one object per opcode of `OpcodesByVersion(13)`:
//
//	{"opcode": 8, "name": "+", "version": 1, "modes": 3, "args": [{"avm": "uint64", "name": "uint64"}, ...]}
//
// `avm` is the AVM type the gate compares (`any`, `uint64`, `[]byte`); `name`
// is `StackType.String()`, what go prints in `<op> arg <i> wanted <name> but
// got <type>`. Regenerate (pin v5.0.4-stable, deterministic):
//
//	cd tools/avm-op-protos && go run . > ../../crates/core/algo-avm/tests/fixtures/go_op_protos.jsonl
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/algorand/go-algorand/data/transactions/logic"
)

// avmVersion is the newest AVM version algod-rust implements
// (`algo_avm::opcode::MAX_AVM_VERSION`); go at the pin is one ahead (14).
const avmVersion = 13

type arg struct {
	AVM  string `json:"avm"`
	Name string `json:"name"`
}

type row struct {
	Opcode  int    `json:"opcode"`
	Name    string `json:"name"`
	Version uint64 `json:"version"`
	// Modes is go's `RunMode` bit set: 1 = LogicSig only, 2 = application
	// only, 3 = both.
	Modes int   `json:"modes"`
	Args  []arg `json:"args"`
}

func main() {
	specs := logic.OpcodesByVersion(avmVersion)
	sort.Slice(specs, func(i, j int) bool {
		if specs[i].Opcode != specs[j].Opcode {
			return specs[i].Opcode < specs[j].Opcode
		}
		return specs[i].Name < specs[j].Name
	})
	enc := json.NewEncoder(os.Stdout)
	for _, s := range specs {
		r := row{Opcode: int(s.Opcode), Name: s.Name, Version: s.Version, Modes: int(s.Modes), Args: []arg{}}
		for _, t := range s.Arg.Types {
			r.Args = append(r.Args, arg{AVM: t.AVMType.String(), Name: t.String()})
		}
		if err := enc.Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
