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
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/data/basics"
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

// testnetPrefix holds rounds 0..50 of the real testnet: real certificates, so
// the replay takes the non-DevMode branch and runs cert.Authenticate.
const testnetPrefix = "../corpus/testnet-prefix50"

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
	return copyCorpusFrom(t, smallCorpus)
}

func copyCorpusFrom(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "corpus")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
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
	// json.Number on both sides: an exact comparison, not float64 maps.
	if err := decodeJSON(raw, &res); err != nil {
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
	if err := decodeJSON(rec, &want); err != nil {
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

// The testnet prefix replays through cert.Authenticate (its certificates
// hold the committee's votes) to the state corpus.json records, and the
// recorded block hash is the one the archival endpoint attested.
func TestTestnetPrefixAuthenticatesEveryCertificate(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "result.json")
	code, stderr := runReplay(t, "-corpus", testnetPrefix, "-data", filepath.Join(dir, "node"), "-out", out)
	if code != 0 {
		t.Fatalf("goreplay exited %d:\n%s", code, stderr)
	}
	var res struct {
		Config      map[string]any `json:"config"`
		CorpusMatch *bool          `json:"corpus_match"`
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeJSON(raw, &res); err != nil {
		t.Fatal(err)
	}
	if res.CorpusMatch == nil || !*res.CorpusMatch {
		t.Fatalf("final state does not match corpus.json")
	}
	if res.Config["DevMode"] != false {
		t.Fatalf("the testnet prefix must not be replayed as DevMode: %v", res.Config["DevMode"])
	}
}

// lastRecord returns the offset and length of the last record's payload in a
// blocks.bin (magic, then round u64 | length u32 | payload records).
func lastRecord(t *testing.T, b []byte) (round uint64, off, n int) {
	t.Helper()
	if string(b[:len(blocksMagic)]) != blocksMagic {
		t.Fatal("bad blocks.bin magic")
	}
	i := len(blocksMagic)
	for i < len(b) {
		round = binary.BigEndian.Uint64(b[i : i+8])
		n = int(binary.BigEndian.Uint32(b[i+8 : i+12]))
		off = i + 12
		i = off + n
	}
	if i != len(b) {
		t.Fatal("truncated blocks.bin")
	}
	return round, off, n
}

// A flipped bit in one vote's ephemeral signature fails cert.Authenticate.
// The flip is anchored to a specific vote: the "s" key (fixstr 1, bin8 of 64
// bytes) last in the last record's payload, which holds the block first and
// the certificate after it, and the decoded certificate before and after
// must differ in the last byte of its last vote's signature and nowhere else.
func TestTestnetPrefixTamperedVoteFailsAuthentication(t *testing.T) {
	corpus := copyCorpusFrom(t, testnetPrefix)
	path := filepath.Join(corpus, "blocks.bin")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	round, off, n := lastRecord(t, b)
	payload := b[off : off+n]
	_, certBefore, err := processBlockBytes(append([]byte(nil), payload...), basics.Round(round))
	if err != nil {
		t.Fatal(err)
	}
	needle := []byte{0xa1, 's', 0xc4, 64}
	i := bytes.LastIndex(payload, needle)
	if i < 0 {
		t.Fatal("no vote signature in the last record")
	}
	pos := i + len(needle) + 63
	payload[pos] ^= 1
	_, certAfter, err := processBlockBytes(payload, basics.Round(round))
	if err != nil {
		t.Fatalf("the tampered record must still decode: %v", err)
	}
	nv := len(certBefore.Votes)
	if nv == 0 || nv != len(certAfter.Votes) {
		t.Fatalf("votes: %d before, %d after", nv, len(certAfter.Votes))
	}
	if !reflect.DeepEqual(certBefore.Votes[:nv-1], certAfter.Votes[:nv-1]) {
		t.Fatal("the flip changed a vote other than the last")
	}
	sb, sa := certBefore.Votes[nv-1].Sig.Sig, certAfter.Votes[nv-1].Sig.Sig
	if !bytes.Equal(sb[:63], sa[:63]) || sb[63]^sa[63] != 1 {
		t.Fatalf("the flip is not the last byte of the last vote's signature: %x vs %x", sb, sa)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	code, stderr := runReplay(t, "-corpus", corpus, "-data", filepath.Join(dir, "node"), "-out", filepath.Join(dir, "r.json"))
	if code != 1 || !strings.Contains(stderr, "did not authenticate block") {
		t.Fatalf("want exit 1 on a tampered vote, got %d:\n%s", code, stderr)
	}
}

// A replay limited to a few rounds (the bisecting mode) of a chain that has
// created no box reads its final state: go's box scan reports a stale database
// round for a ledger without KV rows (boxKeys), which is not a failure.
func TestShortBoxFreeReplayReadsItsFinalState(t *testing.T) {
	for _, rounds := range []string{"3", "20"} {
		dir := t.TempDir()
		out := filepath.Join(dir, "result.json")
		code, stderr := runReplay(t, "-corpus", testnetPrefix, "-data", filepath.Join(dir, "node"),
			"-out", out, "-rounds", rounds)
		if code != 0 {
			t.Fatalf("-rounds %s: goreplay exited %d:\n%s", rounds, code, stderr)
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var res struct {
			FinalState struct {
				Round uint64         `json:"round"`
				KV    map[string]any `json:"kv"`
			} `json:"final_state"`
			CorpusMatch *bool `json:"corpus_match"`
		}
		if err := decodeJSON(raw, &res); err != nil {
			t.Fatal(err)
		}
		if strconv.FormatUint(res.FinalState.Round, 10) != rounds {
			t.Fatalf("-rounds %s: final round %d", rounds, res.FinalState.Round)
		}
		if n, _ := res.FinalState.KV["count"].(json.Number); n.String() != "0" {
			t.Fatalf("-rounds %s: kv count %v, want 0 (no box in the prefix)", rounds, res.FinalState.KV["count"])
		}
		if res.CorpusMatch != nil {
			t.Fatalf("-rounds %s: a partial replay has no corpus.json comparison", rounds)
		}
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
	// Flip the first hex digit, whatever it is (as replay.py's corrupt_corpus).
	key := []byte(`"accounts_sha256": "`)
	i := bytes.Index(b, key)
	if i < 0 {
		t.Fatal("no accounts_sha256 in corpus.json")
	}
	j := i + len(key)
	if b[j] == '0' {
		b[j] = '1'
	} else {
		b[j] = '0'
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	code, stderr := runReplay(t, "-corpus", corpus, "-data", filepath.Join(dir, "node"), "-out", filepath.Join(dir, "r.json"))
	if code != 3 || !strings.Contains(stderr, "accounts_sha256") {
		t.Fatalf("want exit 3 on a wrong expected state, got %d:\n%s", code, stderr)
	}
}

// corpus.json numbers above 2^53 must compare exactly: decoded as float64,
// 9007199254740993 would round to ...992 and a one-microalgo divergence
// would pass the gate.
func TestCompareWithCorpusIsExactAbove2Pow53(t *testing.T) {
	const odd = uint64(9007199254740993) // 2^53 + 1, not a float64
	var want map[string]any
	raw := []byte(`{"round": 9007199254740993, "txn_counter": 9007199254740993,
		"total_money": 9007199254740993, "online_money": 9007199254740993,
		"accounts": 9007199254740993, "accounts_microalgos": 9007199254740993,
		"block_hash": "blk-X", "accounts_sha256": "ab"}`)
	if err := decodeJSON(raw, &want); err != nil {
		t.Fatal(err)
	}
	fs := finalState{Round: odd, TxnCounter: odd, TotalMoney: odd, OnlineMoney: odd, BlockHash: "blk-X"}
	fs.Known = digest{Count: odd, MicroAlgos: odd, SHA256: "ab"}
	if mm := compareWithCorpus(fs, want); len(mm) != 0 {
		t.Fatalf("exact values reported as mismatches: %v", mm)
	}
	fs.TotalMoney = odd - 1
	mm := compareWithCorpus(fs, want)
	if len(mm) != 1 || !strings.Contains(mm[0], "total_money") {
		t.Fatalf("a one-unit difference above 2^53 must be caught, got %v", mm)
	}
}
