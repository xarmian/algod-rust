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
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The tests run goreplay's main() in a child process of the test binary
// (GOREPLAY_AS_MAIN), so its exit status is observable.
const argSep = "\x1f"

func TestMain(m *testing.M) {
	if os.Getenv("GOREPLAY_AS_MAIN") == "1" {
		os.Args = append([]string{"goreplay"}, strings.Split(os.Getenv("GOREPLAY_ARGS"), argSep)...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

const smallCorpus = "../corpus/small"

func runReplay(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "GOREPLAY_AS_MAIN=1", "GOREPLAY_ARGS="+strings.Join(args, argSep))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, stderr.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), stderr.String()
	default:
		t.Fatalf("running goreplay: %v", err)
		return -1, ""
	}
}

// copyCorpus copies the small corpus into a temp dir.
func copyCorpus(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "corpus")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(smallCorpus)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(smallCorpus, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// The go replay of the small corpus reaches corpus.json's final state, and
// exactly the full state recorded in testdata/small-final-state.json, which
// the Rust replay is held to as well
// (bin/algod-rust/src/commands/bench_replay.rs).
func TestSmallCorpusFinalStateMatchesRecorded(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "result.json")
	code, stderr := runReplay(t, "-corpus", smallCorpus, "-data", filepath.Join(dir, "node"), "-out", out)
	if code != 0 {
		t.Fatalf("goreplay exited %d:\n%s", code, stderr)
	}
	var res struct {
		FinalState  map[string]any `json:"final_state"`
		CorpusMatch *bool          `json:"corpus_match"`
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	if res.CorpusMatch == nil || !*res.CorpusMatch {
		t.Fatalf("final state does not match corpus.json")
	}
	var want map[string]any
	rec, err := os.ReadFile("testdata/small-final-state.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rec, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.FinalState, want) {
		got, _ := json.MarshalIndent(res.FinalState, "", "  ")
		t.Fatalf("final state differs from testdata/small-final-state.json:\n%s", got)
	}
}

// A flipped byte in a txn note breaks the block's payset commitment:
// ContentsMatchHeader refuses the block and the replay fails.
func TestCorruptedTxnFailsTheReplay(t *testing.T) {
	corpus := copyCorpus(t)
	path := filepath.Join(corpus, "blocks.bin")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// msgpack: "note" (fixstr 4) then bin8 of 10 bytes; flip its last byte.
	needle := []byte{0xa4, 'n', 'o', 't', 'e', 0xc4, 10}
	i := bytes.Index(b, needle)
	if i < 0 {
		t.Fatal("no txn note in blocks.bin")
	}
	b[i+len(needle)+9] ^= 1
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	code, stderr := runReplay(t, "-corpus", corpus, "-data", filepath.Join(dir, "node"), "-out", filepath.Join(dir, "r.json"))
	if code != 1 || !strings.Contains(stderr, "contents do not match header") {
		t.Fatalf("want exit 1 on a corrupted txn, got %d:\n%s", code, stderr)
	}
}

// A wrong expected state in corpus.json replays fine but fails the
// corpus.json comparison with exit status 3.
func TestWrongExpectedStateExits3(t *testing.T) {
	corpus := copyCorpus(t)
	path := filepath.Join(corpus, "corpus.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.Replace(b, []byte(`"accounts_sha256": "d`), []byte(`"accounts_sha256": "e`), 1)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	code, stderr := runReplay(t, "-corpus", corpus, "-data", filepath.Join(dir, "node"), "-out", filepath.Join(dir, "r.json"))
	if code != 3 || !strings.Contains(stderr, "accounts_sha256") {
		t.Fatalf("want exit 3 on a wrong expected state, got %d:\n%s", code, stderr)
	}
}
