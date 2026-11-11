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

// Catchpoint start (issue #2291, epic #2101, design in
// docs/BENCH_CATCHPOINT_REPLAY.md): the replay can export the catchpoint go's
// own ledger generated while replaying a corpus (-export-catchpoint), and a
// fresh ledger can be started from such a file (-from-catchpoint, with its
// -catchpoint-label), then replay the blocks after the catchpoint round.
//
// The start is go's catchpoint catchup (catchup/catchpointService.go) with the
// network replaced by the corpus: the ledger is staged from the catchpoint
// file's chunks (CatchpointCatchupAccessor.ProcessStagingBalances), the merkle
// trie is built and checked against the label (VerifyCatchpoint of the
// catchpoint block), the block of the catchpoint round and the blocks of the
// lookback before it are stored from the corpus, and CompleteCatchup switches
// the databases and reloads the ledger.

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/stateproof"
)

// exportCatchpoint writes the newest catchpoint file go generated to path and
// returns its label ("" when none was generated).
func exportCatchpoint(l *data.Ledger, path string) (string, error) {
	label := l.GetLastCatchpointLabel()
	if label == "" {
		return "", nil
	}
	round, _, err := ledgercore.ParseCatchpointLabel(label)
	if err != nil {
		return "", fmt.Errorf("catchpoint label %q: %w", label, err)
	}
	rc, err := l.GetCatchpointStream(round)
	if err != nil {
		return "", fmt.Errorf("catchpoint stream for round %d: %w", round, err)
	}
	defer rc.Close()
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(f, rc); err != nil {
		f.Close()
		return "", err
	}
	return label, f.Close()
}

// lookbackForStateproofs is catchup/catchpointService.go
// lookbackForStateproofsSupport.
func lookbackForStateproofs(top *bookkeeping.Block) uint64 {
	proto := config.Consensus[top.CurrentProtocol]
	if proto.StateProofInterval == 0 {
		return 0
	}
	lowest := stateproof.GetOldestExpectedStateProof(&top.BlockHeader)
	lowest = lowest.SubSaturate(basics.Round(proto.StateProofInterval))
	lowest = lowest.SubSaturate(basics.Round(proto.StateProofVotersLookback))
	return uint64(top.Round().SubSaturate(lowest))
}

// catchpointLookback is processStageBlocksDownload's lookback: how many blocks
// before the catchpoint round the ledger needs.
func catchpointLookback(top *bookkeeping.Block) uint64 {
	proto := config.Consensus[top.CurrentProtocol]
	lookback := max(proto.MaxTxnLife+proto.DeeperBlockHeaderHistory+proto.CatchpointLookback, proto.MaxBalLookback)
	lookback = max(lookback, lookbackForStateproofs(top))
	if lookback >= uint64(top.Round()) {
		lookback = uint64(top.Round() - 1)
	}
	return lookback
}

// stageCatchpointFile feeds the chunks of a catchpoint file (a tar, possibly
// gzipped) to the accessor, as the ledger fetcher does for the downloaded one.
func stageCatchpointFile(ctx context.Context, acc ledger.CatchpointCatchupAccessor, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, 1<<20)
	var in io.Reader = br
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return err
		}
		defer gz.Close()
		in = gz
	}
	tr := tar.NewReader(in)
	var progress ledger.CatchpointCatchupAccessorProgress
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Size < 1 {
			return fmt.Errorf("catchpoint file: entry %q has size %d", hdr.Name, hdr.Size)
		}
		chunk := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, chunk); err != nil {
			return fmt.Errorf("catchpoint file: entry %q: %w", hdr.Name, err)
		}
		if err := acc.ProcessStagingBalances(ctx, hdr.Name, chunk, &progress); err != nil {
			return fmt.Errorf("catchpoint file: entry %q: %w", hdr.Name, err)
		}
	}
}

// restoreFromCatchpoint starts the (fresh) ledger l from the catchpoint file
// with the given label. blocks serves the corpus's record of a round (the
// catchpoint round and the lookback before it must be in the corpus).
func restoreFromCatchpoint(ctx context.Context, l *data.Ledger, log logging.Logger, label, file string,
	blocks func(round uint64) (record, error)) (basics.Round, error) {
	round, _, err := ledgercore.ParseCatchpointLabel(label)
	if err != nil {
		return 0, fmt.Errorf("catchpoint label %q: %w", label, err)
	}
	acc := ledger.MakeCatchpointCatchupAccessor(l.Ledger, log)
	if err := acc.ResetStagingBalances(ctx, true); err != nil {
		return 0, fmt.Errorf("reset staging balances: %w", err)
	}
	if err := acc.SetLabel(ctx, label); err != nil {
		return 0, fmt.Errorf("set label: %w", err)
	}
	if err := stageCatchpointFile(ctx, acc, file); err != nil {
		return 0, err
	}
	if err := acc.BuildMerkleTrie(ctx, func(uint64, uint64) {}); err != nil {
		return 0, fmt.Errorf("build merkle trie: %w", err)
	}
	if err := acc.SetState(ctx, ledger.CatchpointCatchupStateLatestBlockDownload); err != nil {
		return 0, err
	}

	// processStageLatestBlockDownload.
	blockRound, err := acc.GetCatchupBlockRound(ctx)
	if err != nil {
		return 0, err
	}
	if blockRound != round {
		return 0, fmt.Errorf("the catchpoint file is for round %d, its label for round %d", blockRound, round)
	}
	rec, err := blocks(uint64(blockRound))
	if err != nil {
		return 0, err
	}
	top, topCert, err := processBlockBytes(rec.payload, blockRound)
	if err != nil {
		return 0, err
	}
	if !top.ContentsMatchHeader() {
		return 0, fmt.Errorf("round %d: block contents do not match header", blockRound)
	}
	if err := acc.VerifyCatchpoint(ctx, top); err != nil {
		return 0, fmt.Errorf("the catchpoint file does not match its label at round %d: %w", blockRound, err)
	}
	if err := acc.StoreBalancesRound(ctx, top); err != nil {
		return 0, err
	}
	if err := acc.StoreFirstBlock(ctx, top, topCert); err != nil {
		return 0, err
	}
	if err := acc.SetState(ctx, ledger.CatchpointCatchupStateBlocksDownload); err != nil {
		return 0, err
	}

	// processStageBlocksDownload: the blocks before the catchpoint round,
	// each checked against its successor.
	lookback := catchpointLookback(top)
	next := top
	for i := uint64(1); i <= lookback; i++ {
		r := blockRound - basics.Round(i)
		rec, err := blocks(uint64(r))
		if err != nil {
			return 0, err
		}
		blk, cert, err := processBlockBytes(rec.payload, r)
		if err != nil {
			return 0, err
		}
		if !blk.ContentsMatchHeader() {
			return 0, fmt.Errorf("round %d: block contents do not match header", r)
		}
		if blk.Hash() != next.BlockHeader.Branch {
			return 0, fmt.Errorf("round %d: block hash %s is not round %d's parent %s", r, blk.Hash(), next.Round(), next.BlockHeader.Branch)
		}
		if err := acc.StoreBlock(ctx, blk, cert); err != nil {
			return 0, fmt.Errorf("round %d: store block: %w", r, err)
		}
		next = blk
	}
	if err := acc.SetState(ctx, ledger.CatchpointCatchupStateSwitch); err != nil {
		return 0, err
	}
	if err := acc.CompleteCatchup(ctx); err != nil {
		return 0, fmt.Errorf("complete catchup: %w", err)
	}
	if err := acc.SetState(ctx, ledger.CatchpointCatchupStateInactive); err != nil {
		return 0, err
	}
	return blockRound, nil
}
