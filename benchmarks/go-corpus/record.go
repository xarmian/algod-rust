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
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

// Block stream format (blocks.bin), documented in docs/BENCHMARK_COMPARISON.md:
//
//	magic   8 bytes  "ACRPBLK1"
//	record* round   u64 big-endian
//	        length  u32 big-endian
//	        payload `length` bytes: the exact /v2/blocks/{round}?format=msgpack
//	                response body, msgpack map {"block": Block, "cert": Certificate}
//
// Records are consecutive rounds 0..N (round 0 is the genesis block).
const blocksMagic = "ACRPBLK1"

type blockWriter struct {
	f *os.File
	w *bufio.Writer
}

func createBlockWriter(path string) (*blockWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	bw := &blockWriter{f: f, w: bufio.NewWriterSize(f, 1<<20)}
	_, err = bw.w.WriteString(blocksMagic)
	return bw, err
}

func (b *blockWriter) write(round uint64, payload []byte) error {
	var hdr [12]byte
	binary.BigEndian.PutUint64(hdr[0:8], round)
	binary.BigEndian.PutUint32(hdr[8:12], uint32(len(payload)))
	if _, err := b.w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := b.w.Write(payload)
	return err
}

func (b *blockWriter) close() error {
	if err := b.w.Flush(); err != nil {
		return err
	}
	return b.f.Close()
}

// readBlocks iterates a blocks.bin stream.
func readBlocks(r io.Reader, fn func(round uint64, payload []byte) error) error {
	br := bufio.NewReaderSize(r, 1<<20)
	magic := make([]byte, len(blocksMagic))
	if _, err := io.ReadFull(br, magic); err != nil {
		return err
	}
	if string(magic) != blocksMagic {
		return fmt.Errorf("bad blocks.bin magic %q", magic)
	}
	var hdr [12]byte
	for {
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		payload := make([]byte, binary.BigEndian.Uint32(hdr[8:12]))
		if _, err := io.ReadFull(br, payload); err != nil {
			return err
		}
		if err := fn(binary.BigEndian.Uint64(hdr[0:8]), payload); err != nil {
			return err
		}
	}
}

// histogram is the txn census recorded in corpus.json. The Rust corpus test
// (crates/tools/algo-bench/tests/corpus_small.rs) recomputes it from the
// production decoder with the same definitions, so keep both in step.
type histogram struct {
	Types    map[string]uint64 `json:"types"`
	Subtypes map[string]uint64 `json:"subtypes"`
	Inner    map[string]uint64 `json:"inner_types"`
	Features map[string]uint64 `json:"features"`
}

func newHistogram() *histogram {
	return &histogram{Types: map[string]uint64{}, Subtypes: map[string]uint64{},
		Inner: map[string]uint64{}, Features: map[string]uint64{}}
}

func subtype(t *transactions.Transaction) string {
	switch t.Type {
	case protocol.PaymentTx:
		if !t.CloseRemainderTo.IsZero() {
			return "close"
		}
		return "payment"
	case protocol.AssetTransferTx:
		switch {
		case !t.AssetCloseTo.IsZero():
			return "close"
		case !t.AssetSender.IsZero():
			return "clawback"
		case t.AssetAmount == 0 && t.AssetReceiver == t.Sender:
			return "optin"
		default:
			return "transfer"
		}
	case protocol.AssetConfigTx:
		switch {
		case t.ConfigAsset == 0:
			return "create"
		case t.AssetParams == (basics.AssetParams{}):
			return "destroy"
		default:
			return "reconfigure"
		}
	case protocol.AssetFreezeTx:
		if t.AssetFrozen {
			return "freeze"
		}
		return "unfreeze"
	case protocol.ApplicationCallTx:
		if t.ApplicationID == 0 {
			return "create"
		}
		switch t.OnCompletion {
		case transactions.NoOpOC:
			return "call"
		case transactions.OptInOC:
			return "optin"
		case transactions.CloseOutOC:
			return "closeout"
		case transactions.ClearStateOC:
			return "clear"
		case transactions.UpdateApplicationOC:
			return "update"
		case transactions.DeleteApplicationOC:
			return "delete"
		}
	case protocol.KeyRegistrationTx:
		switch {
		case t.Nonparticipation:
			return "nonparticipation"
		case !t.VotePK.IsEmpty():
			return "online"
		default:
			return "offline"
		}
	}
	return "other"
}

func (h *histogram) inner(ads []transactions.SignedTxnWithAD) {
	for i := range ads {
		h.Inner[string(ads[i].Txn.Type)]++
		h.Features["inner_txns"]++
		h.inner(ads[i].EvalDelta.InnerTxns)
	}
}

// addBlock counts one block's payset (already decoded with genesis fields
// restored) and returns the top-level txids in order.
func (h *histogram) addBlock(payset []transactions.SignedTxnWithAD) []transactions.Txid {
	ids := make([]transactions.Txid, 0, len(payset))
	if len(payset) == 0 {
		h.Features["empty_blocks"]++
	}
	var lastGroup [32]byte
	for i := range payset {
		st := &payset[i]
		t := &st.Txn
		ids = append(ids, t.ID())
		ty := string(t.Type)
		h.Types[ty]++
		h.Subtypes[ty+"."+subtype(t)]++
		if !t.Group.IsZero() {
			h.Features["grouped_txns"]++
			if i == 0 || t.Group != lastGroup {
				h.Features["groups"]++
			}
			lastGroup = t.Group
		} else {
			lastGroup = [32]byte{}
		}
		if !t.RekeyTo.IsZero() {
			h.Features["rekey_txns"]++
		}
		if !st.AuthAddr.IsZero() {
			h.Features["auth_addr_txns"]++
		}
		if t.Type == protocol.ApplicationCallTx {
			if len(st.EvalDelta.GlobalDelta) > 0 {
				h.Features["app_global_delta_txns"]++
			}
			if len(st.EvalDelta.LocalDeltas) > 0 {
				h.Features["app_local_delta_txns"]++
			}
			if len(t.Boxes) > 0 {
				h.Features["app_box_ref_txns"]++
			}
		}
		h.inner(st.EvalDelta.InnerTxns)
	}
	return ids
}

// decodeBlockCert decodes one blocks.bin payload with go-algorand's own codec.
func decodeBlockCert(payload []byte) (bookkeeping.Block, []transactions.SignedTxnWithAD, error) {
	var ebc rpcs.EncodedBlockCert
	if err := protocol.Decode(payload, &ebc); err != nil {
		return bookkeeping.Block{}, nil, err
	}
	payset, err := ebc.Block.DecodePaysetFlat()
	if err != nil {
		return bookkeeping.Block{}, nil, err
	}
	if ebc.Certificate.Round != ebc.Block.Round() {
		return bookkeeping.Block{}, nil, fmt.Errorf("cert round %d != block round %d", ebc.Certificate.Round, ebc.Block.Round())
	}
	return ebc.Block, payset, nil
}

// txidHasher is sha256 over the 32-byte txids of every top-level txn, in
// block order: corpus.json "txids_sha256", the determinism fingerprint.
type txidHasher struct {
	h     hashWriter
	count uint64
}

type hashWriter interface {
	io.Writer
	Sum([]byte) []byte
}

func newTxidHasher() *txidHasher { return &txidHasher{h: sha256.New()} }

func (t *txidHasher) add(ids []transactions.Txid) {
	for _, id := range ids {
		t.h.Write(id[:])
		t.count++
	}
}

func (t *txidHasher) hex() string { return hex.EncodeToString(t.h.Sum(nil)) }
