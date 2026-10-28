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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
)

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// verifyCorpus re-decodes a corpus with go-algorand's codec and checks it
// against its corpus.json: consecutive rounds 0..N, the prev-hash chain, the
// histogram, the txid fingerprint and the final block. It is the Go twin of
// the Rust corpus test.
func verifyCorpus(dir string) (*corpusJSON, error) {
	var cj corpusJSON
	b, err := os.ReadFile(filepath.Join(dir, "corpus.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &cj); err != nil {
		return nil, err
	}
	if cj.Schema != corpusSchema {
		return nil, fmt.Errorf("schema %q, want %q", cj.Schema, corpusSchema)
	}
	g, err := bookkeeping.LoadGenesisFromFile(filepath.Join(dir, cj.Files["genesis"]))
	if err != nil {
		return nil, err
	}
	gh := g.Hash()
	if base64.StdEncoding.EncodeToString(gh[:]) != cj.Network.GenesisHash {
		return nil, fmt.Errorf("genesis.json hash %s != corpus.json %s", gh, cj.Network.GenesisHash)
	}
	f, err := os.Open(filepath.Join(dir, cj.Files["blocks"]))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	hist := newHistogram()
	txh := newTxidHasher()
	var prev bookkeeping.Block
	next := uint64(0)
	err = readBlocks(f, func(round uint64, payload []byte) error {
		if round != next {
			return fmt.Errorf("record for round %d, expected %d", round, next)
		}
		blk, payset, err := decodeBlockCert(payload)
		if err != nil {
			return fmt.Errorf("round %d: %w", round, err)
		}
		if uint64(blk.Round()) != round {
			return fmt.Errorf("record %d holds block %d", round, blk.Round())
		}
		if blk.GenesisHash() != gh {
			return fmt.Errorf("round %d: genesis hash mismatch", round)
		}
		if round > 0 {
			if blk.Branch != prev.Hash() {
				return fmt.Errorf("round %d: prev hash mismatch", round)
			}
			txh.add(hist.addBlock(payset))
		}
		prev = blk
		next++
		return nil
	})
	if err != nil {
		return nil, err
	}
	var errs []string
	if next != cj.Rounds.Count || next == 0 || uint64(prev.Round()) != cj.Rounds.Last {
		errs = append(errs, fmt.Sprintf("rounds: stream has %d records, corpus.json says %+v", next, cj.Rounds))
	}
	if txh.count != cj.Txns {
		errs = append(errs, fmt.Sprintf("txns: %d decoded, corpus.json %d", txh.count, cj.Txns))
	}
	if txh.hex() != cj.TxidsSHA {
		errs = append(errs, "txids_sha256 differs")
	}
	want, _ := json.Marshal(cj.Histogram)
	got, _ := json.Marshal(hist)
	if !bytes.Equal(want, got) {
		errs = append(errs, fmt.Sprintf("histogram differs:\n  corpus.json %s\n  decoded     %s", want, got))
	}
	if prev.Hash().String() != cj.Final.BlockHash || prev.TxnCounter != cj.Final.TxnCounter {
		errs = append(errs, "final block hash / txn counter differs")
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("%d check(s) failed:\n%s", len(errs), joinLines(errs))
	}
	return &cj, nil
}

func joinLines(s []string) string {
	var b bytes.Buffer
	for _, l := range s {
		b.WriteString("  " + l + "\n")
	}
	return b.String()
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	dir := fs.String("corpus", "", "corpus directory")
	fs.Parse(args)
	if *dir == "" {
		die("verify needs -corpus")
	}
	cj, err := verifyCorpus(*dir)
	if err != nil {
		die("%s: %v", *dir, err)
	}
	// The consensus params the corpus was cut with must be this build's.
	var cd struct {
		Version string          `json:"version"`
		Params  json.RawMessage `json:"params"`
	}
	b, err := os.ReadFile(filepath.Join(*dir, cj.Files["consensus"]))
	if err != nil {
		die("%v", err)
	}
	if err := json.Unmarshal(b, &cd); err != nil {
		die("%v", err)
	}
	mine, _ := json.Marshal(config.Consensus[protocol.ConsensusVersion(cd.Version)])
	if cd.Version != cj.Network.ConsensusVersion || !jsonEqual(cd.Params, mine) {
		die("%s: consensus.json does not match this go-algorand build's %s params", *dir, cd.Version)
	}
	fmt.Printf("corpusgen: %s OK: rounds 0..%d, %d txns, final %s\n", *dir, cj.Rounds.Last, cj.Txns, cj.Final.BlockHash)
}

func jsonEqual(a, b []byte) bool {
	var x, y interface{}
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}
