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

// avm-op-types dumps go-algorand's assembler type-tracking inputs
// (`data/transactions/logic/opcodes.go`, `fields.go`) as JSON lines, so algod-rust's
// stack-type tracker (`crates/core/algo-avm/src/type_track.rs`, issue #2368) is
// generated from go instead of typed by hand:
//
//	{"kind":"op","name":"+","opcode":8,"version":1,"deadens":false,
//	 "imms":[{"name":"f","group":"txn/1a2b3c4d"}],
//	 "variants":[{"from":1,"args":[T..],"returns":[T..],"refine":"typeEquals"}]}
//	{"kind":"field","group":"txn/1a2b3c4d","field":"Sender","version":1,"type":T}
//
// where T is `{"avm":"uint64","min":0,"max":18446744073709551615,"name":"uint64"}`
// (go's `StackType`: AVM type, bound and the `String()` it prints in
// `<op> arg <i> wanted type <T> got <T>`). `variants` lists the distinct
// (args, returns, refine) from the version each starts at, per `OpsByName[v]`.
// `refine` is the Go function name of the op's `typed(...)` refine function
// (empty when none); the tracker ports each by hand and a test keeps that
// list in sync with this dump.
//
// Regenerate (go-algorand pin v5.1.1-stable, deterministic):
//
//	cd tools/avm-op-types && go run . > ../../crates/core/algo-avm/tests/fixtures/go_op_types.jsonl
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/algorand/go-algorand/data/transactions/logic"
)

type typ struct {
	AVM  string `json:"avm"`
	Min  uint64 `json:"min"`
	Max  uint64 `json:"max"`
	Name string `json:"name"`
}

type variant struct {
	From    uint64 `json:"from"`
	Args    []typ  `json:"args"`
	Returns []typ  `json:"returns"`
	Refine  string `json:"refine,omitempty"`
	// Imms are this version's immediates, since go v5.1 an opcode's immediates
	// may change with the version (falcon_verify gains `f` in v14).
	Imms []immRow `json:"imms,omitempty"`
}

type immRow struct {
	Name  string `json:"name"`
	Group string `json:"group,omitempty"`
}

type opRow struct {
	Kind     string    `json:"kind"`
	Name     string    `json:"name"`
	Opcode   int       `json:"opcode"`
	Sub      int       `json:"sub,omitempty"`
	Version  uint64    `json:"version"`
	// LatestVersion is the Version of the spec at logic.LogicVersion: the spec an
	// assembler falls back to for a version the opcode does not exist at
	// (prepareVersionedPseudoTable), which differs from Version for opcodes with
	// several specs (replace3: v7, then v14 for its length-based cost).
	LatestVersion uint64 `json:"latest_version"`
	Deadens  bool      `json:"deadens,omitempty"`
	Imms     []immRow  `json:"imms,omitempty"`
	Variants []variant `json:"variants"`
}

type fieldRow struct {
	Kind    string `json:"kind"`
	Group   string `json:"group"`
	Field   string `json:"field"`
	Version uint64 `json:"version"`
	Type    typ    `json:"type"`
}

func conv(ts logic.StackTypes) []typ {
	out := []typ{}
	for _, t := range ts {
		out = append(out, typ{AVM: t.AVMType.String(), Min: t.Bound[0], Max: t.Bound[1], Name: t.Name})
	}
	return out
}

func refineName(spec logic.OpSpec) string {
	f := reflect.ValueOf(spec).FieldByName("OpDetails").FieldByName("refine")
	if f.IsNil() {
		return ""
	}
	name := runtime.FuncForPC(f.Pointer()).Name()
	name = name[strings.LastIndex(name, "/")+1:]
	name = strings.TrimPrefix(name, "logic.")
	// A closure's compiler-assigned name differs between Go versions
	// (`init.typeByteMath.func1` vs `glob..func3`); only typeByteMath makes them.
	if strings.Contains(name, "typeByteMath") {
		return "typeByteMath"
	}
	return name
}

func sig(v variant) string {
	b, _ := json.Marshal(v.Args)
	c, _ := json.Marshal(v.Returns)
	d, _ := json.Marshal(v.Imms)
	return string(b) + string(c) + v.Refine + string(d)
}

// groupID names a field group by its go name plus a digest of its contents:
// several groups share a name (`txn` is both TxnFields and TxnScalarFields).
func groupID(g *logic.FieldGroup) string {
	h := sha256.New()
	for _, n := range g.Names {
		fs, ok := g.SpecByName(n)
		if !ok {
			continue
		}
		t := fs.Type()
		fmt.Fprintf(h, "%s|%d|%s|%d|%d|%s\n", n, fs.Version(), t.AVMType, t.Bound[0], t.Bound[1], t.Name)
	}
	return g.Name + "/" + hex.EncodeToString(h.Sum(nil))[:8]
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
		if a.SubOpcode != b.SubOpcode {
			return a.SubOpcode < b.SubOpcode
		}
		return names[i] < names[j]
	})
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	groups := map[string]*logic.FieldGroup{}
	for _, n := range names {
		s := latest[n]
		r := opRow{Kind: "op", Name: n, Opcode: int(s.Opcode), Sub: int(s.SubOpcode), LatestVersion: s.Version}
		immRows := func(sp logic.OpSpec) []immRow {
			var rows []immRow
			for _, im := range sp.Immediates {
				ir := immRow{Name: im.Name}
				if im.Group != nil {
					ir.Group = groupID(im.Group)
					groups[ir.Group] = im.Group
				}
				rows = append(rows, ir)
			}
			return rows
		}
		r.Imms = immRows(s)
		last := ""
		for v := uint64(1); v <= logic.LogicVersion; v++ {
			spec, ok := logic.OpsByName[v][n]
			if !ok {
				continue
			}
			if r.Version == 0 {
				r.Version = v
			}
			if spec.Name == "b" || spec.Name == "callsub" || spec.Name == "retsub" || spec.Name == "err" || spec.Name == "return" {
				r.Deadens = true
			}
			vr := variant{From: v, Args: conv(spec.Arg.Types), Returns: conv(spec.Return.Types), Refine: refineName(spec), Imms: immRows(spec)}
			if s := sig(vr); s != last {
				r.Variants = append(r.Variants, vr)
				last = s
			}
		}
		if err := enc.Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	gnames := make([]string, 0, len(groups))
	for g := range groups {
		gnames = append(gnames, g)
	}
	sort.Strings(gnames)
	for _, g := range gnames {
		grp := groups[g]
		for _, fname := range grp.Names {
			fs, ok := grp.SpecByName(fname)
			if !ok {
				continue
			}
			t := fs.Type()
			fr := fieldRow{Kind: "field", Group: g, Field: fname, Version: fs.Version(),
				Type: typ{AVM: t.AVMType.String(), Min: t.Bound[0], Max: t.Bound[1], Name: t.Name}}
			if err := enc.Encode(fr); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
	}
}
