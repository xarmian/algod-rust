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

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixtureDir = "../../crates/tools/teal-corpus/tests/fixtures/small"

const (
	validPushint = "231654048e28b40e1a7d043b5ebd2f998843458fba11c2bc5891bb97bfc27c0b"
	truncated    = "f65d31940ec0553eeda1a41574387df924e010d8acfad07b2253a9a06b5e7370"
	srcValid     = "c33e255c1323f8168bcee5936ac3f79729e11dd92628df5747d470a1b94ad53c"
	srcInvalid   = "bad152c46a63b97f51bdf42c6b038ffcee6ece1f1aa52c0c5a8b25f19ce40b42"
	srcWarning   = "dadd1391b887de52fc570557bcd6b89b17fd6a306afc852b98a807a68383c67a"
)

func runFixture(t *testing.T, op string, jobs int) []row {
	t.Helper()
	dir := filepath.Join(fixtureDir, inputSubdir(op))
	inputs, err := loadInputs(dir, inputExt(op))
	if err != nil {
		t.Fatalf("loadInputs: %v", err)
	}
	return runBatch(inputs, jobs, 10*time.Second, func(in input) row { return process(op, in) })
}

func rowFor(t *testing.T, rows []row, sha string) row {
	t.Helper()
	for _, r := range rows {
		if r.Sha256 == sha {
			return r
		}
	}
	t.Fatalf("no row for %s", sha)
	return row{}
}

func TestDisassembleFixtureRows(t *testing.T) {
	rows := runFixture(t, "disassemble", 2)
	if len(rows) != 4 {
		t.Fatalf("want 4 rows, got %d", len(rows))
	}
	ok := rowFor(t, rows, validPushint)
	if !ok.Ok || ok.Text == nil || *ok.Text != "#pragma version 8\npushint 1\n" {
		t.Fatalf("valid program row: %+v", ok)
	}
	bad := rowFor(t, rows, truncated)
	if bad.Ok || bad.Error == nil || *bad.Error == "" || bad.Text != nil {
		t.Fatalf("invalid program row: %+v", bad)
	}
}

func TestAssembleFixtureRows(t *testing.T) {
	rows := runFixture(t, "assemble", 2)
	if len(rows) != 4 {
		t.Fatalf("want 4 rows, got %d", len(rows))
	}
	ok := rowFor(t, rows, srcValid)
	if !ok.Ok || ok.BytecodeB64 == nil || *ok.BytecodeB64 != "CIEBQw==" || len(ok.Hash) != 58 || ok.Sourcemap == nil || len(ok.Warnings) != 0 {
		t.Fatalf("valid source row: %+v", ok)
	}
	bad := rowFor(t, rows, srcInvalid)
	if bad.Ok || len(bad.Errors) < 2 || bad.Errors[0].Line != 3 || !strings.Contains(bad.Errors[0].Message, "frobnicate") || bad.BytecodeB64 != nil {
		t.Fatalf("invalid source row: %+v", bad)
	}
	warn := rowFor(t, rows, srcWarning)
	if !warn.Ok || len(warn.Warnings) == 0 || warn.Warnings[0].Line != 2 || !strings.Contains(warn.Warnings[0].Message, "autosalt") {
		t.Fatalf("warning source row: %+v", warn)
	}
}

// The committed expected/go.*.jsonl files are this driver's own output on the
// fixture (rows only; the header carries the go-algorand commit).
func TestFixtureMatchesPinnedRows(t *testing.T) {
	for _, op := range []string{"disassemble", "assemble"} {
		rows := runFixture(t, op, 3)
		got := string(renderOutput(op, rows, header{Impl: "go-algorand"}))
		gotRows := got[strings.Index(got, "\n")+1:]
		want, err := os.ReadFile(filepath.Join(fixtureDir, "expected", "go."+op+".jsonl"))
		if err != nil {
			t.Fatalf("read pinned rows: %v", err)
		}
		wantRows := string(want)[strings.Index(string(want), "\n")+1:]
		if gotRows != wantRows {
			t.Fatalf("%s: rows differ from pinned expected/go.%s.jsonl\n got: %s\nwant: %s", op, op, gotRows, wantRows)
		}
	}
}

func TestOutputIsDeterministicAcrossJobs(t *testing.T) {
	for _, op := range []string{"disassemble", "assemble"} {
		a := renderOutput(op, runFixture(t, op, 1), header{Impl: "go-algorand"})
		b := renderOutput(op, runFixture(t, op, 16), header{Impl: "go-algorand"})
		if len(a) == 0 || !bytes.Equal(a, b) {
			t.Fatalf("%s: output differs across thread counts", op)
		}
	}
}

func TestHeaderNamesImplementationPinAndOperation(t *testing.T) {
	out := renderOutput("assemble", nil, header{Impl: "go-algorand", GoAlgorandTag: "v5.0.5-stable", GoAlgorandCommit: "abc"})
	var h struct {
		Header map[string]any `json:"header"`
	}
	if err := json.Unmarshal(bytes.SplitN(out, []byte("\n"), 2)[0], &h); err != nil {
		t.Fatal(err)
	}
	if h.Header["impl"] != "go-algorand" || h.Header["operation"] != "assemble" || h.Header["go_algorand_tag"] != "v5.0.5-stable" || h.Header["go_algorand_commit"] != "abc" || h.Header["schema"].(float64) != 1 || h.Header["count"].(float64) != 0 {
		t.Fatalf("header: %v", h.Header)
	}
}

func inputsNamed(names ...string) []input {
	var in []input
	for _, n := range names {
		in = append(in, input{Sha256: n, Bytes: []byte(n)})
	}
	return in
}

func TestPanickingInputIsRecordedAndBatchContinues(t *testing.T) {
	rows := runBatch(inputsNamed("c", "a", "boom", "b"), 2, 5*time.Second, func(in input) row {
		if in.Sha256 == "boom" {
			panic("kaboom")
		}
		return row{Ok: true, Sha256: in.Sha256}
	})
	if len(rows) != 4 || rows[0].Sha256 != "a" || rows[1].Sha256 != "b" || rows[2].Sha256 != "boom" || rows[3].Sha256 != "c" {
		t.Fatalf("rows: %+v", rows)
	}
	if rows[2].Ok || rows[2].Panic == nil || *rows[2].Panic != "kaboom" {
		t.Fatalf("panic row: %+v", rows[2])
	}
	if !hasRobustnessFailure(rows) || hasRobustnessFailure(rows[:2]) {
		t.Fatal("robustness failure detection")
	}
}

func TestHangingInputTimesOutAndBatchContinues(t *testing.T) {
	start := time.Now()
	rows := runBatch(inputsNamed("a", "hang", "b"), 2, 200*time.Millisecond, func(in input) row {
		if in.Sha256 == "hang" {
			time.Sleep(30 * time.Second)
		}
		return row{Ok: true, Sha256: in.Sha256}
	})
	if time.Since(start) > 10*time.Second {
		t.Fatal("waited for the hung input")
	}
	if len(rows) != 3 || rows[2].Sha256 != "hang" || rows[2].Ok || !rows[2].Timeout || !rows[0].Ok || !rows[1].Ok {
		t.Fatalf("rows: %+v", rows)
	}
}
