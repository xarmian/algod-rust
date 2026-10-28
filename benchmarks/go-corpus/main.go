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

// corpusgen builds the deterministic workload block corpus of issue #2104
// (epic #2101) by driving a single-node go-algorand DevMode network.
//
//	corpusgen genesis -seed S -accounts A -out DATADIR
//	corpusgen drive   -data DATADIR -seed S -accounts A -rounds N -txns-per-round K -out CORPUS
//	corpusgen verify  -corpus CORPUS
//
// scripts/bench/corpus/generate.py runs the three steps (and algod) for you.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

// generatorVersion changes whenever the same seed would produce different
// bytes (workload mix, key derivation, genesis, node config).
const generatorVersion = "1"

const (
	corpusSchema = "algod-corpus/v1"
	blocksFile   = "blocks.bin"
)

type corpusJSON struct {
	Schema     string            `json:"schema"`
	Name       string            `json:"name"`
	Generator  generatorInfo     `json:"generator"`
	GoAlgorand goAlgorandInfo    `json:"go_algorand"`
	Network    networkInfo       `json:"network"`
	Files      map[string]string `json:"files"`
	Rounds     roundsInfo        `json:"rounds"`
	Txns       uint64            `json:"txns"`
	TxidsSHA   string            `json:"txids_sha256"`
	Histogram  *histogram        `json:"histogram"`
	Final      finalState        `json:"final_state"`
}

type generatorInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Seed         string `json:"seed"`
	Accounts     int    `json:"accounts"`
	TxnsPerRound int    `json:"txns_per_round"`
	TSOffset     uint64 `json:"timestamp_offset_s"`
}

type goAlgorandInfo struct {
	Tag    string `json:"tag"`
	Commit string `json:"commit"`
}

type networkInfo struct {
	GenesisID        string `json:"genesis_id"`
	GenesisHash      string `json:"genesis_hash"`
	ConsensusVersion string `json:"consensus_version"`
	DevMode          bool   `json:"devmode"`
	GenesisTimestamp int64  `json:"genesis_timestamp"`
}

type roundsInfo struct {
	First uint64 `json:"first"`
	Last  uint64 `json:"last"`
	Count uint64 `json:"count"`
}

type finalState struct {
	Round          uint64 `json:"round"`
	BlockHash      string `json:"block_hash"`
	TxnCounter     uint64 `json:"txn_counter"`
	TotalMoney     uint64 `json:"total_money"`
	OnlineMoney    uint64 `json:"online_money"`
	Accounts       int    `json:"accounts"`
	AccountsAlgos  uint64 `json:"accounts_microalgos"`
	AccountsSHA256 string `json:"accounts_sha256"`
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "corpusgen: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		die("usage: corpusgen genesis|drive|verify [flags]")
	}
	switch os.Args[1] {
	case "genesis":
		cmdGenesis(os.Args[2:])
	case "drive":
		cmdDrive(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	default:
		die("unknown command %q", os.Args[1])
	}
}

func cmdGenesis(args []string) {
	fs := flag.NewFlagSet("genesis", flag.ExitOnError)
	seed := fs.String("seed", "", "corpus seed")
	accounts := fs.Int("accounts", 64, "workload accounts")
	out := fs.String("out", "", "node data directory to create")
	fs.Parse(args)
	if *seed == "" || *out == "" || *accounts < 8 {
		die("genesis needs -seed, -out and -accounts >= 8")
	}
	if err := writeDataDir(newNetwork(*seed, *accounts), *out); err != nil {
		die("%v", err)
	}
}

func writeJSON(path string, v interface{}) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}

func cmdDrive(args []string) {
	fs := flag.NewFlagSet("drive", flag.ExitOnError)
	data := fs.String("data", "", "running node's data directory (algod.net, algod.admin.token)")
	seed := fs.String("seed", "", "corpus seed (same as genesis)")
	accounts := fs.Int("accounts", 64, "workload accounts (same as genesis)")
	rounds := fs.Uint64("rounds", 100, "rounds to generate")
	tpr := fs.Int("txns-per-round", 6, "target top-level txns per round")
	tsOffset := fs.Uint64("ts-offset", 3, "DevMode block timestamp offset (seconds)")
	out := fs.String("out", "", "corpus directory to write")
	name := fs.String("name", "custom", "corpus name")
	goTag := fs.String("go-tag", "", "go-algorand tag of the algod binary")
	goCommit := fs.String("go-commit", "", "go-algorand commit of the algod binary")
	fs.Parse(args)
	if *data == "" || *seed == "" || *out == "" || *rounds < 10 || *tpr < 1 {
		die("drive needs -data, -seed, -out, -rounds >= 10, -txns-per-round >= 1")
	}
	if *tsOffset == 0 || *tsOffset > 25 {
		die("-ts-offset must be 1..25 (MaxTimestampIncrement)")
	}
	n := newNetwork(*seed, *accounts)
	g := n.genesis()
	ghash := g.Hash()
	{ // the node must run exactly this genesis
		onDisk, err := bookkeeping.LoadGenesisFromFile(filepath.Join(*data, config.GenesisJSONFile))
		if err != nil {
			die("%v", err)
		}
		if onDisk.Hash() != ghash {
			die("genesis in %s does not match -seed/-accounts", *data)
		}
	}
	progs, err := assemblePrograms()
	if err != nil {
		die("%v", err)
	}
	cl, err := newClientFromDataDir(*data)
	if err != nil {
		die("%v", err)
	}
	if err := cl.waitReady(60 * time.Second); err != nil {
		die("%v", err)
	}
	if last, err := cl.lastRound(); err != nil || last != 0 {
		die("node must be fresh (last round %d, err %v)", last, err)
	}
	if err := cl.setTimestampOffset(*tsOffset); err != nil {
		die("%v", err)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		die("%v", err)
	}
	bw, err := createBlockWriter(filepath.Join(*out, blocksFile))
	if err != nil {
		die("%v", err)
	}

	p := params{rounds: *rounds, accounts: *accounts, txnsPerRound: *tpr, tsOffset: *tsOffset, seed: *seed}
	w := newWorkload(p, n, progs, g.ID(), ghash)
	setup := w.setupSteps()
	hist := newHistogram()
	txh := newTxidHasher()

	raw0, err := cl.rawBlock(0)
	if err != nil {
		die("%v", err)
	}
	prev, _, err := decodeBlockCert(raw0)
	if err != nil {
		die("round 0: %v", err)
	}
	if err := bw.write(0, raw0); err != nil {
		die("%v", err)
	}
	start := time.Now()
	for r := uint64(1); r <= *rounds; r++ {
		w.round = r
		groups := w.planRound(setup)
		var planned []transactions.Txid
		var signed [][]transactions.SignedTxn
		inPool := 0
		for _, gp := range groups {
			st, err := w.sign(gp)
			if err != nil {
				die("round %d: %v", r, err)
			}
			signed = append(signed, st)
			for i := range st {
				planned = append(planned, st[i].ID())
			}
		}
		for i, st := range signed {
			if i == len(signed)-1 {
				err = cl.submitSync(st)
			} else {
				inPool += len(st)
				err = cl.submitAsync(st, inPool)
			}
			if err != nil {
				die("round %d group %d: %v", r, i, err)
			}
		}
		raw, err := cl.rawBlock(r)
		if err != nil {
			die("%v", err)
		}
		blk, payset, err := decodeBlockCert(raw)
		if err != nil {
			die("round %d: %v", r, err)
		}
		if uint64(blk.Round()) != r {
			die("asked for round %d, got %d", r, blk.Round())
		}
		if blk.Branch != prev.Hash() {
			die("round %d: prev hash mismatch", r)
		}
		ids := hist.addBlock(payset)
		if len(ids) != len(planned) {
			die("round %d: block has %d txns, planned %d (the pool held unplanned txns, or dropped some)", r, len(ids), len(planned))
		}
		for i := range ids {
			if ids[i] != planned[i] {
				die("round %d: txn %d is %s, planned %s (payset order differs from the plan)", r, i, ids[i], planned[i])
			}
		}
		// Hand each group its ApplyData (created asset/app ids).
		off := 0
		for _, gp := range groups {
			k := len(gp.txns)
			if gp.onCommit != nil {
				ads := make([]transactions.ApplyData, k)
				for j := 0; j < k; j++ {
					ads[j] = payset[off+j].ApplyData
				}
				gp.onCommit(ads)
			}
			off += k
		}
		txh.add(ids)
		if err := bw.write(r, raw); err != nil {
			die("%v", err)
		}
		prev = blk
		if r%1000 == 0 {
			el := time.Since(start).Seconds()
			fmt.Fprintf(os.Stderr, "corpusgen: round %d/%d, %d txns, %.0f txn/s, %.0f rounds/s\n",
				r, *rounds, txh.count, float64(txh.count)/el, float64(r)/el)
		}
	}
	if err := bw.close(); err != nil {
		die("%v", err)
	}
	el := time.Since(start).Seconds()
	fmt.Fprintf(os.Stderr, "corpusgen: done: %d rounds, %d txns in %.1fs (%.0f txn/s)\n",
		*rounds, txh.count, el, float64(txh.count)/el)

	final, err := w.finalState(cl, prev)
	if err != nil {
		die("final state: %v", err)
	}
	cj := corpusJSON{
		Schema: corpusSchema,
		Name:   *name,
		Generator: generatorInfo{Name: "benchmarks/go-corpus", Version: generatorVersion, Seed: *seed,
			Accounts: *accounts, TxnsPerRound: *tpr, TSOffset: *tsOffset},
		GoAlgorand: goAlgorandInfo{Tag: *goTag, Commit: *goCommit},
		Network: networkInfo{GenesisID: g.ID(), GenesisHash: base64.StdEncoding.EncodeToString(ghash[:]),
			ConsensusVersion: string(g.Proto), DevMode: g.DevMode, GenesisTimestamp: g.Timestamp},
		Files: map[string]string{"blocks": blocksFile, "genesis": "genesis.json",
			"node_config": "node-config.json", "consensus": "consensus.json"},
		Rounds:    roundsInfo{First: 0, Last: *rounds, Count: *rounds + 1},
		Txns:      txh.count,
		TxidsSHA:  txh.hex(),
		Histogram: hist,
		Final:     final,
	}
	if err := copyFile(filepath.Join(*data, config.GenesisJSONFile), filepath.Join(*out, "genesis.json")); err != nil {
		die("%v", err)
	}
	if err := copyFile(filepath.Join(*data, config.ConfigFilename), filepath.Join(*out, "node-config.json")); err != nil {
		die("%v", err)
	}
	if err := writeJSON(filepath.Join(*out, "consensus.json"), consensusDump(g.Proto)); err != nil {
		die("%v", err)
	}
	if err := writeJSON(filepath.Join(*out, "corpus.json"), cj); err != nil {
		die("%v", err)
	}
}

// consensusDump is the full ConsensusParams of the genesis protocol, so a
// replayer can check it runs the same rules.
func consensusDump(v protocol.ConsensusVersion) map[string]interface{} {
	return map[string]interface{}{"version": string(v), "params": config.Consensus[v]}
}

func (w *workload) finalState(cl *algodClient, last bookkeeping.Block) (finalState, error) {
	sup, err := cl.supply()
	if err != nil {
		return finalState{}, err
	}
	if sup.Round != uint64(last.Round()) {
		return finalState{}, fmt.Errorf("supply at round %d, last block %d", sup.Round, last.Round())
	}
	addrs := make([]string, 0, len(w.known))
	seen := map[string]bool{}
	for _, a := range w.known {
		s := a.String()
		if !seen[s] {
			seen[s] = true
			addrs = append(addrs, s)
		}
	}
	sort.Strings(addrs)
	var lines bytes.Buffer
	var total uint64
	for _, a := range addrs {
		amt, err := cl.accountAmount(a)
		if err != nil {
			return finalState{}, err
		}
		total += amt
		fmt.Fprintf(&lines, "%s %d\n", a, amt)
	}
	bh := last.Hash()
	return finalState{
		Round:          uint64(last.Round()),
		BlockHash:      bh.String(),
		TxnCounter:     last.TxnCounter,
		TotalMoney:     sup.TotalMoney,
		OnlineMoney:    sup.OnlineMoney,
		Accounts:       len(addrs),
		AccountsAlgos:  total,
		AccountsSHA256: sha256Hex(lines.Bytes()),
	}, nil
}
