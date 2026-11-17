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

// teal-corpus: the go-algorand half of the Phase 25 TEAL corpus parity check
// (issue #2366, epic #2364).
//
//	teal-corpus disassemble --corpus DIR [--input-dir D] [--out F] [--jobs N] [--timeout-ms N]
//	teal-corpus assemble    --corpus DIR [--input-dir D] [--out F] [--jobs N] [--timeout-ms N]
//
// It reads a corpus laid out by scripts/teal-corpus/extract.py
// (programs/<sha256>.bin, sources/<sha256>.teal) and runs go-algorand's own
// logic.Disassemble / logic.AssembleString over every input exactly as the REST
// handlers TealDisassemble / TealCompile
// (daemon/algod/api/server/v2/handlers.go) do, writing JSONL rows keyed by the
// sha256 of the input bytes. crates/tools/teal-corpus (Rust) emits the identical
// schema and owns the `diff` command; see its lib.rs for the row schema.
//
// The first output line is a header naming the go-algorand tag and commit this
// binary was built against (injected by build.sh with -ldflags -X).
//
// Exit codes: 0 success, 2 usage or I/O error, 3 a panic or timeout was
// recorded for at least one input (the batch still ran to completion).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions/logic"
)

// Set by build.sh via -ldflags "-X main.goAlgorandTag=... -X main.goAlgorandCommit=...".
var (
	goAlgorandTag    = "unknown"
	goAlgorandCommit = "unknown"
)

const schemaVersion = 1

type diag struct {
	Col     int    `json:"col"`
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// row is one output line. Field order is alphabetical to match the Rust driver.
type row struct {
	BytecodeB64 *string          `json:"bytecode_b64,omitempty"`
	Error       *string          `json:"error,omitempty"`
	Errors      []diag           `json:"errors,omitempty"`
	Hash        string           `json:"hash,omitempty"`
	Ok          bool             `json:"ok"`
	Panic       *string          `json:"panic,omitempty"`
	Sha256      string           `json:"sha256"`
	Sourcemap   *logic.SourceMap `json:"sourcemap,omitempty"`
	Text        *string          `json:"text,omitempty"`
	Timeout     bool             `json:"timeout,omitempty"`
	Warnings    []diag           `json:"warnings,omitempty"`
}

type input struct {
	Sha256 string
	Bytes  []byte
}

type header struct {
	Impl             string
	GoAlgorandTag    string
	GoAlgorandCommit string
}

func inputSubdir(op string) string {
	if op == "disassemble" {
		return "programs"
	}
	return "sources"
}

func inputExt(op string) string {
	if op == "disassemble" {
		return "bin"
	}
	return "teal"
}

// loadInputs reads every *.<ext> regular file of dir keyed by the sha256 of its
// content (never trusting the file name), de-duplicated, sorted by sha256.
func loadInputs(dir, ext string) ([]input, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	bySha := map[string]input{}
	for _, e := range entries {
		if filepath.Ext(e.Name()) != "."+ext || !e.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		sha := hex.EncodeToString(sum[:])
		if _, dup := bySha[sha]; !dup {
			bySha[sha] = input{Sha256: sha, Bytes: b}
		}
	}
	out := make([]input, 0, len(bySha))
	for _, in := range bySha {
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sha256 < out[j].Sha256 })
	return out, nil
}

// process runs op on one input through go-algorand's logic package, shaping
// errors and warnings as TealCompile / TealDisassemble do.
func process(op string, in input) row {
	r := row{Sha256: in.Sha256}
	if op == "disassemble" {
		text, err := logic.Disassemble(in.Bytes)
		if err != nil {
			msg := err.Error()
			r.Error = &msg
			return r
		}
		r.Ok = true
		r.Text = &text
		return r
	}
	ops, err := logic.AssembleString(string(in.Bytes))
	if err != nil {
		for _, e := range ops.Errors {
			r.Errors = append(r.Errors, diag{Col: e.Column, Line: e.Line, Message: e.Err.Error()})
		}
		if len(r.Errors) == 0 {
			r.Errors = []diag{{Message: err.Error()}}
		}
		return r
	}
	b64 := base64.StdEncoding.EncodeToString(ops.Program)
	sm := logic.GetSourceMap([]string{"<body>"}, ops.OffsetToSource)
	r.Ok = true
	r.BytecodeB64 = &b64
	r.Hash = basics.Address(logic.HashProgram(ops.Program)).String()
	r.Sourcemap = &sm
	for _, w := range ops.Warnings {
		r.Warnings = append(r.Warnings, diag{Col: w.Column, Line: w.Line, Message: w.Err.Error()})
	}
	return r
}

func runOne(f func(input) row, in input, timeout time.Duration) row {
	done := make(chan row, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				msg := fmt.Sprint(p)
				done <- row{Sha256: in.Sha256, Panic: &msg}
			}
		}()
		done <- f(in)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-done:
		return r
	case <-timer.C:
		// The overrunning goroutine cannot be killed; it is abandoned and the
		// process exits once the batch is written.
		return row{Sha256: in.Sha256, Timeout: true}
	}
}

// runBatch runs f over every input on `jobs` workers, each input in its own
// goroutine with recover and a per-input timeout. Rows come back sorted by
// sha256, independent of scheduling.
func runBatch(inputs []input, jobs int, timeout time.Duration, f func(input) row) []row {
	if jobs < 1 {
		jobs = 1
	}
	rows := make([]row, len(inputs))
	idx := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < jobs; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				rows[i] = runOne(f, inputs[i], timeout)
			}
		}()
	}
	for i := range inputs {
		idx <- i
	}
	close(idx)
	wg.Wait()
	sort.Slice(rows, func(i, j int) bool { return rows[i].Sha256 < rows[j].Sha256 })
	return rows
}

func hasRobustnessFailure(rows []row) bool {
	for _, r := range rows {
		if r.Panic != nil || r.Timeout {
			return true
		}
	}
	return false
}

func encodeLine(buf *bytes.Buffer, v any) {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err) // rows and the header always marshal
	}
}

// renderOutput is the header line followed by one line per row.
func renderOutput(op string, rows []row, h header) []byte {
	var buf bytes.Buffer
	hdr := map[string]any{
		"count":     len(rows),
		"impl":      h.Impl,
		"operation": op,
		"schema":    schemaVersion,
	}
	if h.GoAlgorandTag != "" {
		hdr["go_algorand_tag"] = h.GoAlgorandTag
	}
	if h.GoAlgorandCommit != "" {
		hdr["go_algorand_commit"] = h.GoAlgorandCommit
	}
	encodeLine(&buf, map[string]any{"header": hdr})
	for _, r := range rows {
		encodeLine(&buf, r)
	}
	return buf.Bytes()
}

// opcodeTable is every opcode name of go-algorand's opcode table
// (logic.OpSpecs) with the first AVM version that has it. The same name at
// several versions keeps the lowest. Issue #2371: the corpus statistics list
// the table opcodes no corpus program uses.
func opcodeTable() map[string]uint64 {
	t := map[string]uint64{}
	for _, s := range logic.OpSpecs {
		if v, ok := t[s.Name]; !ok || s.Version < v {
			t[s.Name] = s.Version
		}
	}
	return t
}

// renderOpcodes is the `opcodes` command's JSON document (json.Marshal sorts
// the map keys).
func renderOpcodes(tag, commit string) []byte {
	doc := map[string]any{
		"schema":             "teal-corpus-opcodes/v1",
		"go_algorand_tag":    tag,
		"go_algorand_commit": commit,
		"opcodes":            opcodeTable(),
	}
	var buf bytes.Buffer
	encodeLine(&buf, doc)
	return buf.Bytes()
}

// timings records the per-input processing time of a batch (issue #2371).
type timings struct {
	mu  sync.Mutex
	per map[string]int64
}

// wrap measures f around the work itself, inside the worker, so the goroutine
// hand-off and the timeout timer are not part of it.
func (t *timings) wrap(f func(input) row) func(input) row {
	return func(in input) row {
		start := time.Now()
		r := f(in)
		ns := time.Since(start).Nanoseconds()
		t.mu.Lock()
		t.per[in.Sha256] = ns
		t.mu.Unlock()
		return r
	}
}

func (t *timings) render(op string, jobs, inputs, inputBytes int, wall time.Duration) []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	doc := map[string]any{
		"schema":         "teal-corpus-timings/v1",
		"impl":           "go-algorand",
		"operation":      op,
		"jobs":           jobs,
		"inputs":         inputs,
		"input_bytes":    inputBytes,
		"wall_ns":        wall.Nanoseconds(),
		"per_program_ns": t.per,
	}
	var buf bytes.Buffer
	encodeLine(&buf, doc)
	return buf.Bytes()
}

func run(op string, args []string) int {
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	corpus := fs.String("corpus", "", "corpus directory produced by scripts/teal-corpus/extract.py")
	inputDir := fs.String("input-dir", "", "override the input directory (default <corpus>/programs or <corpus>/sources)")
	out := fs.String("out", "", "output JSONL file (default stdout)")
	jobs := fs.Int("jobs", runtime.NumCPU(), "parallel workers")
	timeoutMs := fs.Int("timeout-ms", 10000, "per-input time budget in milliseconds")
	timingsOut := fs.String("timings", "", "also write per-input processing times, batch wall clock and input size as JSON (use with --jobs 1)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *corpus == "" {
		fmt.Fprintln(os.Stderr, "error: --corpus is required")
		return 2
	}
	dir := *inputDir
	if dir == "" {
		dir = filepath.Join(*corpus, inputSubdir(op))
	}
	inputs, err := loadInputs(dir, inputExt(op))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", dir, err)
		return 2
	}
	work := func(in input) row { return process(op, in) }
	tm := &timings{per: map[string]int64{}}
	if *timingsOut != "" {
		work = tm.wrap(work)
	}
	inputBytes := 0
	for _, in := range inputs {
		inputBytes += len(in.Bytes)
	}
	started := time.Now()
	rows := runBatch(inputs, *jobs, time.Duration(*timeoutMs)*time.Millisecond, work)
	wall := time.Since(started)
	if *timingsOut != "" {
		if err := os.WriteFile(*timingsOut, tm.render(op, *jobs, len(inputs), inputBytes, wall), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing timings: %v\n", err)
			return 2
		}
	}
	data := renderOutput(op, rows, header{Impl: "go-algorand", GoAlgorandTag: goAlgorandTag, GoAlgorandCommit: goAlgorandCommit})
	if *out == "" {
		_, err = os.Stdout.Write(data)
	} else {
		err = os.WriteFile(*out, data, 0o644)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: writing output: %v\n", err)
		return 2
	}
	ok, panics, timeouts := 0, 0, 0
	for _, r := range rows {
		switch {
		case r.Ok:
			ok++
		case r.Panic != nil:
			panics++
		case r.Timeout:
			timeouts++
		}
	}
	fmt.Fprintf(os.Stderr, "%s: %d inputs, %d ok, %d error, %d panic, %d timeout\n",
		op, len(rows), ok, len(rows)-ok-panics-timeouts, panics, timeouts)
	if hasRobustnessFailure(rows) {
		return 3
	}
	return 0
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "opcodes" {
		// teal-corpus opcodes: go-algorand's opcode table as JSON on stdout (#2371).
		if _, err := os.Stdout.Write(renderOpcodes(goAlgorandTag, goAlgorandCommit)); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	if len(os.Args) < 2 || (os.Args[1] != "disassemble" && os.Args[1] != "assemble") {
		fmt.Fprintf(os.Stderr, "usage: %s disassemble|assemble --corpus DIR [--out FILE] [--jobs N] [--timeout-ms N] [--timings FILE]\n       %s opcodes\n", filepath.Base(os.Args[0]), filepath.Base(os.Args[0]))
		os.Exit(2)
	}
	// Hung goroutines cannot be joined; exit without waiting for them.
	os.Exit(run(os.Args[1], os.Args[2:]))
}
