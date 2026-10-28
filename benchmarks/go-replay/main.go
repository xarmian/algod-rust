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

// goreplay replays a workload block corpus (benchmarks/corpus, issue #2104)
// offline through go-algorand's own ledger, the way go's catchup service
// writes fetched blocks (issue #2105, epic #2101):
//
//	goreplay -corpus DIR -data FRESHDIR -out RESULT.json [-config FILE] [-rounds N]
//
// It opens a fresh on-disk ledger exactly like node.MakeFull (config.json in
// the data directory, EnsureAndResolveGenesisDirs, data.LoadLedger), then for
// every corpus block does what catchup/service.go fetchAndWrite does with a
// fetched block: processBlockBytes (decode + round checks),
// ContentsMatchHeader, certificate authentication, the MaxBalLookback
// backpressure wait, and Validate + AddValidatedBlock or AddBlock depending
// on CatchupBlockValidateMode (default: AddBlock). At the end it waits for
// the blocks and the trackers to be written, then reports the timings, the
// resource use and the canonical final state (state.go) as JSON. The
// scripts/bench/tiers/replay.py tier compares that state with algod-rust's.
//
// Exit status: 0 ok, 1 replay/setup error, 3 the final state differs from
// the corpus's corpus.json final_state.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
	"github.com/algorand/go-algorand/util/execpool"
)

const (
	resultSchema = "bench-replay-run/v1"
	blocksMagic  = "ACRPBLK1"
)

// corpusMeta is the part of corpus.json the replay needs.
type corpusMeta struct {
	Schema  string `json:"schema"`
	Name    string `json:"name"`
	Network struct {
		GenesisID   string `json:"genesis_id"`
		GenesisHash string `json:"genesis_hash"`
		DevMode     bool   `json:"devmode"`
	} `json:"network"`
	Files struct {
		Blocks     string `json:"blocks"`
		Genesis    string `json:"genesis"`
		NodeConfig string `json:"node_config"`
	} `json:"files"`
	Rounds struct {
		Last uint64 `json:"last"`
	} `json:"rounds"`
	Final map[string]any `json:"final_state"`
}

type metrics struct {
	WallS        float64 `json:"wall_s"`
	Blocks       uint64  `json:"blocks"`
	Txns         uint64  `json:"txns"`
	InnerTxns    uint64  `json:"inner_txns"`
	BlocksPerS   float64 `json:"blocks_per_s"`
	TxnsPerS     float64 `json:"txns_per_s"`
	PeakRSSBytes uint64  `json:"peak_rss_bytes"`
	CPUUserS     float64 `json:"cpu_user_s"`
	CPUSysS      float64 `json:"cpu_sys_s"`
	// WriteBytes is /proc/self/io write_bytes over the timed section, null
	// where the kernel keeps no per-task I/O accounting (WSL2, for one).
	WriteBytes *uint64 `json:"write_bytes"`
	// DBBytes is the size of the data directory after the close.
	DBBytes uint64 `json:"db_bytes"`
	// FlushS is the part of WallS after the last AddBlock: waiting for the
	// block queue to reach the disk and closing the ledger.
	FlushS float64 `json:"flush_s"`
}

type result struct {
	Schema      string         `json:"schema"`
	Impl        string         `json:"impl"`
	Corpus      string         `json:"corpus"`
	Rounds      uint64         `json:"rounds"`
	Config      map[string]any `json:"config"`
	Metrics     metrics        `json:"metrics"`
	FinalState  finalState     `json:"final_state"`
	CorpusMatch *bool          `json:"corpus_match"`
	Mismatches  []string       `json:"corpus_mismatches,omitempty"`
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "goreplay: "+format+"\n", args...)
	os.Exit(1)
}

// record is one blocks.bin entry.
type record struct {
	round   uint64
	payload []byte
}

// blockReader streams blocks.bin records in order (the replay reads each
// block from the file when it needs it, like a fetch, instead of holding the
// whole corpus in memory).
type blockReader struct {
	f *os.File
	r *bufio.Reader
}

func openBlocks(path string) (*blockReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(f, 1<<20)
	magic := make([]byte, len(blocksMagic))
	if _, err := io.ReadFull(r, magic); err != nil || string(magic) != blocksMagic {
		f.Close()
		return nil, fmt.Errorf("%s: bad magic (expected %s)", path, blocksMagic)
	}
	return &blockReader{f: f, r: r}, nil
}

func (b *blockReader) next() (record, error) {
	var hdr [12]byte
	if _, err := io.ReadFull(b.r, hdr[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return record{}, io.EOF
		}
		return record{}, fmt.Errorf("blocks.bin: truncated record header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[8:])
	p := make([]byte, n)
	if _, err := io.ReadFull(b.r, p); err != nil {
		return record{}, fmt.Errorf("blocks.bin: record for round %d truncated", binary.BigEndian.Uint64(hdr[:8]))
	}
	return record{round: binary.BigEndian.Uint64(hdr[:8]), payload: p}, nil
}

func (b *blockReader) close() { b.f.Close() }

// processBlockBytes mirrors catchup/universalFetcher.go processBlockBytes.
func processBlockBytes(buf []byte, r basics.Round) (*bookkeeping.Block, *agreement.Certificate, error) {
	var ebc rpcs.EncodedBlockCert
	if err := protocol.Decode(buf, &ebc); err != nil {
		return nil, nil, fmt.Errorf("round %d: cannot decode block: %w", r, err)
	}
	if ebc.Block.Round() != r {
		return nil, nil, fmt.Errorf("round %d: got block for round %d", r, ebc.Block.Round())
	}
	if ebc.Certificate.Round != r {
		return nil, nil, fmt.Errorf("round %d: got cert for round %d", r, ebc.Certificate.Round)
	}
	return &ebc.Block, &ebc.Certificate, nil
}

// countInner counts inner txns at every nesting level.
func countInner(ad transactions.ApplyData) uint64 {
	var n uint64
	for i := range ad.EvalDelta.InnerTxns {
		n += 1 + countInner(ad.EvalDelta.InnerTxns[i].ApplyData)
	}
	return n
}

// prepass decodes every record once, untimed: it checks the stream, counts
// the work (top-level + inner txns) and collects the corpus.json account set.
func prepass(path string, last uint64, g bookkeeping.Genesis) (blocks, txns, inner uint64, known []basics.Address, err error) {
	br, err := openBlocks(path)
	if err != nil {
		return
	}
	defer br.close()
	ks := newKnownSet(g)
	for want := uint64(0); want <= last; want++ {
		rec, rerr := br.next()
		if rerr != nil {
			err = fmt.Errorf("blocks.bin ends before round %d: %v", want, rerr)
			return
		}
		if rec.round != want {
			err = fmt.Errorf("blocks.bin: record %d holds round %d", want, rec.round)
			return
		}
		if want == 0 {
			continue
		}
		blk, _, derr := processBlockBytes(rec.payload, basics.Round(want))
		if derr != nil {
			err = derr
			return
		}
		payset, derr := blk.DecodePaysetFlat()
		if derr != nil {
			err = fmt.Errorf("round %d: %v", want, derr)
			return
		}
		blocks++
		txns += uint64(len(payset))
		for i := range payset {
			inner += countInner(payset[i].ApplyData)
		}
		ks.addBlock(payset)
	}
	known = ks.list()
	return
}

func dirSize(root string) (uint64, error) {
	var n uint64
	err := filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			n += uint64(info.Size())
		}
		return nil
	})
	return n, err
}

func main() {
	corpusDir := flag.String("corpus", "", "corpus directory (benchmarks/corpus/<name>)")
	dataDir := flag.String("data", "", "fresh node data directory to create (must not exist or be empty)")
	out := flag.String("out", "", "result JSON file")
	cfgFile := flag.String("config", "", "config.json for the node (default: the corpus's node-config.json)")
	rounds := flag.Uint64("rounds", 0, "replay only rounds 1..N (0: the whole corpus); for bisecting")
	dumpDir := flag.String("dump-state", "", "also write the digested final-state lines into this directory")
	flag.Parse()
	if *corpusDir == "" || *dataDir == "" || *out == "" {
		die("usage: goreplay -corpus DIR -data FRESHDIR -out RESULT.json [-config FILE] [-rounds N]")
	}

	var meta corpusMeta
	raw, err := os.ReadFile(filepath.Join(*corpusDir, "corpus.json"))
	if err != nil {
		die("%v", err)
	}
	// UseNumber: final_state values are compared exactly (no float64).
	if err := decodeJSON(raw, &meta); err != nil {
		die("corpus.json: %v", err)
	}
	if meta.Schema != "algod-corpus/v1" {
		die("corpus.json: schema %q, want algod-corpus/v1", meta.Schema)
	}
	last := meta.Rounds.Last
	if *rounds != 0 {
		if *rounds > last {
			die("-rounds %d beyond the corpus's last round %d", *rounds, last)
		}
		last = *rounds
	}

	genesis, err := bookkeeping.LoadGenesisFromFile(filepath.Join(*corpusDir, meta.Files.Genesis))
	if err != nil {
		die("%v", err)
	}
	gh := genesis.Hash()
	if base64.StdEncoding.EncodeToString(gh[:]) != meta.Network.GenesisHash {
		die("genesis.json hash %s does not match corpus.json", gh)
	}

	// Data directory: config.json, as a node's data dir holds it.
	if ents, err := os.ReadDir(*dataDir); err == nil && len(ents) > 0 {
		die("%s is not empty: the replay needs a fresh ledger", *dataDir)
	}
	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		die("%v", err)
	}
	src := *cfgFile
	if src == "" {
		src = filepath.Join(*corpusDir, meta.Files.NodeConfig)
	}
	cfgBytes, err := os.ReadFile(src)
	if err != nil {
		die("%v", err)
	}
	if err := os.WriteFile(filepath.Join(*dataDir, config.ConfigFilename), cfgBytes, 0o644); err != nil {
		die("%v", err)
	}
	cfg, err := config.LoadConfigFromDisk(*dataDir)
	if err != nil {
		die("config: %v", err)
	}

	log := logging.NewLogger()
	log.SetLevel(logging.Warn)
	log.SetOutput(os.Stderr)

	blocksPath := filepath.Join(*corpusDir, meta.Files.Blocks)
	nBlocks, nTxns, nInner, known, err := prepass(blocksPath, last, genesis)
	if err != nil {
		die("%v", err)
	}

	// node.MakeFull: genesis dirs, genesis balances, data.LoadLedger.
	genesisDirs, err := cfg.EnsureAndResolveGenesisDirs(*dataDir, genesis.ID(), log)
	if err != nil {
		die("%v", err)
	}
	genalloc, err := genesis.Balances()
	if err != nil {
		die("%v", err)
	}
	cryptoPool := execpool.MakePool(nil, "worker", "cryptoPool")
	defer cryptoPool.Shutdown()
	validationPool := execpool.MakeBacklog(cryptoPool, 2*cryptoPool.GetParallelism(), execpool.LowPriority, nil, "worker", "lowPriorityCryptoVerificationPool")
	defer validationPool.Shutdown()
	ledgerPaths := ledger.DirsAndPrefix{DBFilePrefix: config.LedgerFilenamePrefix, ResolvedGenesisDirs: genesisDirs}
	l, err := data.LoadLedger(log, ledgerPaths, false, genesis.Proto, genalloc, genesis.ID(), gh, cfg)
	if err != nil {
		die("LoadLedger: %v", err)
	}

	br, err := openBlocks(blocksPath)
	if err != nil {
		die("%v", err)
	}
	defer br.close()
	rec0, err := br.next()
	if err != nil {
		die("%v", err)
	}
	blk0, _, err := processBlockBytes(rec0.payload, 0)
	if err != nil {
		die("%v", err)
	}
	ours, err := l.Block(0)
	if err != nil {
		die("%v", err)
	}
	if ours.Hash() != blk0.Hash() {
		die("the ledger's genesis block %s differs from the corpus's round 0 %s", ours.Hash(), blk0.Hash())
	}
	var avv *agreement.AsyncVoteVerifier
	if !meta.Network.DevMode && cfg.CatchupVerifyCertificate() {
		avv = agreement.MakeAsyncVoteVerifier(validationPool)
		defer avv.Quit()
	}

	before := readProcStats()
	start := time.Now()
	for r := uint64(1); r <= last; r++ {
		rec, err := br.next()
		if err != nil {
			die("%v", err)
		}
		if err := writeBlock(l, cfg, rec, basics.Round(r), meta.Network.DevMode, avv, validationPool); err != nil {
			die("%v", err)
		}
	}
	addDone := time.Now()
	// The block queue and the account trackers write in the background:
	// wait until every block is durable (WaitForCommit), then close the
	// ledger, which waits for any tracker commit in flight and stops the
	// writers. That is the work a node has done once the blocks are safe.
	// go keeps up to ~5 s of account deltas in memory between tracker
	// flushes (balancesFlushInterval) and rebuilds them from the blocks on
	// restart, which the reopen below does too.
	l.WaitForCommit(basics.Round(last))
	l.Close()
	end := time.Now()
	after := readProcStats()
	wall := end.Sub(start)

	m := metrics{
		WallS:     wall.Seconds(),
		Blocks:    nBlocks,
		Txns:      nTxns + nInner,
		InnerTxns: nInner,
		FlushS:    end.Sub(addDone).Seconds(),
	}
	m.BlocksPerS = float64(m.Blocks) / m.WallS
	m.TxnsPerS = float64(m.Txns) / m.WallS
	m.PeakRSSBytes = after.peakRSS
	m.CPUUserS = after.userS - before.userS
	m.CPUSysS = after.sysS - before.sysS
	if before.ioOK && after.ioOK {
		w := after.writeBytes - before.writeBytes
		m.WriteBytes = &w
	}
	if m.DBBytes, err = dirSize(*dataDir); err != nil {
		die("%v", err)
	}

	// The final state is read from the reopened ledger: what survived the
	// close, as a restarted node sees it (untimed).
	l, err = data.LoadLedger(log, ledgerPaths, false, genesis.Proto, genalloc, genesis.ID(), gh, cfg)
	if err != nil {
		die("reopen: %v", err)
	}
	fs, err := computeFinalState(l, filepath.Join(genesisDirs.TrackerGenesisDir, config.LedgerFilenamePrefix+".tracker.sqlite"), known, *dumpDir)
	if err != nil {
		die("final state: %v", err)
	}
	dbRound := l.LatestTrackerCommitted()
	l.Close()

	res := result{
		Schema:  resultSchema,
		Impl:    "go",
		Corpus:  meta.Name,
		Rounds:  last,
		Metrics: m,
		Config: map[string]any{
			"Archival":                 cfg.Archival,
			"CatchupBlockValidateMode": cfg.CatchupBlockValidateMode,
			"CatchupParallelBlocks":    cfg.CatchupParallelBlocks,
			"MaxAcctLookback":          cfg.MaxAcctLookback,
			"LedgerSynchronousMode":    cfg.LedgerSynchronousMode,
			"StorageEngine":            cfg.StorageEngine,
			"CatchpointInterval":       cfg.CatchpointInterval,
			"CatchpointTracking":       cfg.CatchpointTracking,
			"DevMode":                  meta.Network.DevMode,
			"tracker_db_round":         uint64(dbRound),
		},
		FinalState: fs,
	}
	if last == meta.Rounds.Last {
		mm := compareWithCorpus(fs, meta.Final)
		ok := len(mm) == 0
		res.CorpusMatch = &ok
		res.Mismatches = mm
	}
	if err := writeResult(*out, res); err != nil {
		die("%v", err)
	}
	fmt.Fprintf(os.Stderr, "goreplay: %d blocks, %d txns (%d inner) in %.2fs: %.1f blocks/s, %.0f txn/s; final round %d %s\n",
		m.Blocks, m.Txns, m.InnerTxns, m.WallS, m.BlocksPerS, m.TxnsPerS, fs.Round, fs.BlockHash)
	if res.CorpusMatch != nil && !*res.CorpusMatch {
		for _, s := range res.Mismatches {
			fmt.Fprintf(os.Stderr, "goreplay: final state differs from corpus.json: %s\n", s)
		}
		os.Exit(3)
	}
}

// writeBlock mirrors the per-block body of catchup/service.go fetchAndWrite
// for a block that was already fetched (processBlockBytes) and is next in
// line (prevFetchCompleteChan): the payset hash check, the certificate
// check, the MaxBalLookback backpressure wait, then Validate +
// AddValidatedBlock or AddBlock.
func writeBlock(l *data.Ledger, cfg config.Local, rec record, r basics.Round, devMode bool,
	avv *agreement.AsyncVoteVerifier, pool execpool.BacklogPool) error {
	if basics.Round(rec.round) != r {
		return fmt.Errorf("blocks.bin: expected round %d, record holds %d", r, rec.round)
	}
	block, cert, err := processBlockBytes(rec.payload, r)
	if err != nil {
		return err
	}
	if cfg.CatchupVerifyPaysetHash() && !block.ContentsMatchHeader() {
		return fmt.Errorf("round %d: block contents do not match header", r)
	}
	if cfg.CatchupVerifyCertificate() {
		if devMode {
			// A DevMode certificate holds only the round (no votes, no
			// proposal): there is nothing to authenticate. processBlockBytes
			// already checked the round; require that it is that degenerate
			// form, exactly like the Rust replay does.
			if len(cert.Votes) != 0 || len(cert.EquivocationVotes) != 0 {
				return fmt.Errorf("round %d: DevMode corpus carries a certificate with votes", r)
			}
		} else if err := cert.Authenticate(*block, l, avv); err != nil {
			return fmt.Errorf("round %d: cert did not authenticate block: %w", r, err)
		}
	}
	proto, err := l.ConsensusParams(r.SubSaturate(1))
	if err != nil {
		return fmt.Errorf("round %d: consensus params: %w", r, err)
	}
	<-l.Wait(r.SubSaturate(basics.Round(proto.MaxBalLookback)))
	if cfg.CatchupVerifyTransactionSignatures() || cfg.CatchupVerifyApplyData() {
		vb, err := l.Validate(context.Background(), *block, pool)
		if err != nil {
			return fmt.Errorf("round %d: failed to validate block: %w", r, err)
		}
		err = l.AddValidatedBlock(*vb, *cert)
		if err != nil {
			return fmt.Errorf("round %d: AddValidatedBlock: %w", r, err)
		}
		return nil
	}
	if err := l.AddBlock(*block, *cert); err != nil {
		return fmt.Errorf("round %d: AddBlock: %w", r, err)
	}
	return nil
}

func writeResult(path string, res result) error {
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
