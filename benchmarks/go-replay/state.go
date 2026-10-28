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

// The canonical final state of a replay. algod-rust computes the very same
// document in crates/tools/algo-bench/src/replay_state.rs; the line formats
// below and there must stay identical (docs/BENCHMARK_COMPARISON.md, "The
// replay tier"). Every digest is the lowercase hex sha256 of the
// concatenated lines.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/data"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/ledgercore"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/db"
)

type algoCount struct {
	Money       uint64 `json:"money"`
	RewardUnits uint64 `json:"reward_units"`
}

type totalsJSON struct {
	Online           algoCount `json:"online"`
	Offline          algoCount `json:"offline"`
	NotParticipating algoCount `json:"not_participating"`
	RewardsLevel     uint64    `json:"rewards_level"`
}

type digest struct {
	Count      uint64 `json:"count"`
	MicroAlgos uint64 `json:"microalgos"`
	SHA256     string `json:"sha256"`
}

type finalState struct {
	Round       uint64     `json:"round"`
	BlockHash   string     `json:"block_hash"`
	TxnCounter  uint64     `json:"txn_counter"`
	TotalMoney  uint64     `json:"total_money"`
	OnlineMoney uint64     `json:"online_money"`
	Totals      totalsJSON `json:"totals"`
	// corpus.json's account set and digest: "<address> <amount>\n" over the
	// sorted addresses, amount with pending rewards (REST `amount`).
	Known digest `json:"known_accounts"`
	// Every non-empty account of the ledger, base record + resources.
	Accounts digest `json:"all_accounts"`
	// Every KV (box) entry, "<hex key> <hex value>\n" sorted by key.
	KV digest `json:"kv"`
}

// knownSet rebuilds the account set corpus.json's accounts_sha256 covers
// (benchmarks/go-corpus workload.known): every genesis allocation, every
// receiver of a top-level payment, and the accounts of the first two apps
// the corpus creates (its main and callee apps).
type knownSet struct {
	seen  map[basics.Address]bool
	apps  int
	addrs []basics.Address
}

func newKnownSet(g bookkeeping.Genesis) *knownSet {
	k := &knownSet{seen: map[basics.Address]bool{}}
	for _, a := range g.Allocation {
		addr, err := basics.UnmarshalChecksumAddress(a.Address)
		if err == nil {
			k.add(addr)
		}
	}
	return k
}

func (k *knownSet) add(a basics.Address) {
	if !k.seen[a] {
		k.seen[a] = true
		k.addrs = append(k.addrs, a)
	}
}

func (k *knownSet) addBlock(payset []transactions.SignedTxnWithAD) {
	for i := range payset {
		t := &payset[i].Txn
		switch t.Type {
		case protocol.PaymentTx:
			k.add(t.Receiver)
		case protocol.ApplicationCallTx:
			if t.ApplicationID == 0 && k.apps < 2 {
				k.apps++
				k.add(payset[i].ApplyData.ApplicationID.Address())
			}
		}
	}
}

func (k *knownSet) list() []basics.Address { return k.addrs }

// boxPrefix is the KV key prefix of app boxes (go apps.MakeBoxKey).
const boxPrefix = "bx:"

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// addrStr is the checksummed address, "-" for the zero address.
func addrStr(a basics.Address) string {
	if a.IsZero() {
		return "-"
	}
	return a.String()
}

func b01(b bool) int {
	if b {
		return 1
	}
	return 0
}

// tkv is a TealKeyValue as "<hex key>:u<uint>" / "<hex key>:b<hex bytes>"
// entries sorted by key bytes, joined with ",".
func tkv(kv basics.TealKeyValue) string {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := kv[k]
		if v.Type == basics.TealUintType {
			parts = append(parts, fmt.Sprintf("%x:u%d", k, v.Uint))
		} else {
			parts = append(parts, fmt.Sprintf("%x:b%x", k, v.Bytes))
		}
	}
	return strings.Join(parts, ",")
}

// accountLines is one account's record in the all_accounts digest: the base
// record (stored values, no pending rewards) and its resources sorted by
// kind, then id.
func accountLines(addr basics.Address, base ledgercore.AccountData, full basics.AccountData) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s st=%d amt=%d rb=%d rwd=%d auth=%s ie=%d sch=%d/%d xp=%d napp=%d nls=%d nasp=%d nas=%d bx=%d bb=%d lp=%d lh=%d vote=%x sel=%x sp=%x vfv=%d vlv=%d kd=%d\n",
		addr, byte(base.Status), base.MicroAlgos.Raw, base.RewardsBase, base.RewardedMicroAlgos.Raw,
		addrStr(base.AuthAddr), b01(base.IncentiveEligible),
		base.TotalAppSchema.NumUint, base.TotalAppSchema.NumByteSlice, base.TotalExtraAppPages,
		base.TotalAppParams, base.TotalAppLocalStates, base.TotalAssetParams, base.TotalAssets,
		base.TotalBoxes, base.TotalBoxBytes, uint64(base.LastProposed), uint64(base.LastHeartbeat),
		base.VoteID[:], base.SelectionID[:], base.StateProofID[:],
		uint64(base.VoteFirstValid), uint64(base.VoteLastValid), base.VoteKeyDilution)

	assets := make([]basics.AssetIndex, 0, len(full.Assets))
	for id := range full.Assets {
		assets = append(assets, id)
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i] < assets[j] })
	for _, id := range assets {
		h := full.Assets[id]
		fmt.Fprintf(&b, " as %d %d %d\n", uint64(id), h.Amount, b01(h.Frozen))
	}
	apars := make([]basics.AssetIndex, 0, len(full.AssetParams))
	for id := range full.AssetParams {
		apars = append(apars, id)
	}
	sort.Slice(apars, func(i, j int) bool { return apars[i] < apars[j] })
	for _, id := range apars {
		p := full.AssetParams[id]
		fmt.Fprintf(&b, " asp %d t=%d dc=%d df=%d un=%x an=%x url=%x mh=%x m=%s r=%s f=%s c=%s\n",
			uint64(id), p.Total, p.Decimals, b01(p.DefaultFrozen), p.UnitName, p.AssetName, p.URL,
			p.MetadataHash[:], addrStr(p.Manager), addrStr(p.Reserve), addrStr(p.Freeze), addrStr(p.Clawback))
	}
	locals := make([]basics.AppIndex, 0, len(full.AppLocalStates))
	for id := range full.AppLocalStates {
		locals = append(locals, id)
	}
	sort.Slice(locals, func(i, j int) bool { return locals[i] < locals[j] })
	for _, id := range locals {
		s := full.AppLocalStates[id]
		fmt.Fprintf(&b, " ls %d %d/%d %s\n", uint64(id), s.Schema.NumUint, s.Schema.NumByteSlice, tkv(s.KeyValue))
	}
	apps := make([]basics.AppIndex, 0, len(full.AppParams))
	for id := range full.AppParams {
		apps = append(apps, id)
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i] < apps[j] })
	for _, id := range apps {
		p := full.AppParams[id]
		fmt.Fprintf(&b, " app %d ap=%s cp=%s gs=%d/%d lsch=%d/%d xp=%d v=%d ss=%s fbr=%d fba=%d %s\n",
			uint64(id), sha(p.ApprovalProgram), sha(p.ClearStateProgram),
			p.GlobalStateSchema.NumUint, p.GlobalStateSchema.NumByteSlice,
			p.LocalStateSchema.NumUint, p.LocalStateSchema.NumByteSlice,
			p.ExtraProgramPages, p.Version, addrStr(p.SizeSponsor), b01(p.ForeignBoxReads), b01(p.FamilyBoxAccess),
			tkv(p.GlobalState))
	}
	return b.String()
}

// ledgerAddresses lists every address that may hold an account at the
// latest round: the tracker DB's accountbase (up to its dbRound) plus every
// account an in-memory delta after it touched.
func ledgerAddresses(l *data.Ledger, trackerDB string) ([]basics.Address, error) {
	set := map[basics.Address]bool{}
	dbRound := l.LatestTrackerCommitted()
	latest := l.Latest()
	for r := dbRound + 1; r <= latest; r++ {
		sd, err := l.GetStateDeltaForRound(r)
		if err != nil {
			// Committed meanwhile: then the DB read below covers it.
			continue
		}
		for _, a := range sd.Accts.ModifiedAccounts() {
			set[a] = true
		}
	}
	acc, err := db.MakeAccessor(trackerDB, true, false)
	if err != nil {
		return nil, err
	}
	defer acc.Close()
	err = acc.Atomic(func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT address FROM accountbase")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b []byte
			if err := rows.Scan(&b); err != nil {
				return err
			}
			var a basics.Address
			if len(b) != len(a) {
				return fmt.Errorf("accountbase address of %d bytes", len(b))
			}
			copy(a[:], b)
			set[a] = true
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	out := make([]basics.Address, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	return out, nil
}

func computeFinalState(l *data.Ledger, trackerDB string, known []basics.Address, dumpDir string) (finalState, error) {
	dump := func(name string, b []byte) error {
		if dumpDir == "" {
			return nil
		}
		if err := os.MkdirAll(dumpDir, 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dumpDir, name), b, 0o644)
	}
	var fs finalState
	latest := l.Latest()
	blk, err := l.Block(latest)
	if err != nil {
		return fs, err
	}
	rnd, totals, err := l.LatestTotals()
	if err != nil {
		return fs, err
	}
	if rnd != latest {
		return fs, fmt.Errorf("totals at round %d, latest block %d", rnd, latest)
	}
	bh := blk.Hash()
	fs.Round = uint64(latest)
	fs.BlockHash = bh.String()
	fs.TxnCounter = blk.TxnCounter
	fs.TotalMoney = totals.Participating().Raw
	fs.OnlineMoney = totals.Online.Money.Raw
	fs.Totals = totalsJSON{
		Online:           algoCount{totals.Online.Money.Raw, totals.Online.RewardUnits},
		Offline:          algoCount{totals.Offline.Money.Raw, totals.Offline.RewardUnits},
		NotParticipating: algoCount{totals.NotParticipating.Money.Raw, totals.NotParticipating.RewardUnits},
		RewardsLevel:     totals.RewardsLevel,
	}

	// corpus.json's digest (go-corpus finalState): REST amounts.
	ks := make([]string, 0, len(known))
	byStr := map[string]basics.Address{}
	for _, a := range known {
		ks = append(ks, a.String())
		byStr[a.String()] = a
	}
	sort.Strings(ks)
	var lines bytes.Buffer
	for _, s := range ks {
		ad, _, _, err := l.LookupLatest(byStr[s])
		if err != nil {
			return fs, err
		}
		fs.Known.MicroAlgos += ad.MicroAlgos.Raw
		fmt.Fprintf(&lines, "%s %d\n", s, ad.MicroAlgos.Raw)
	}
	fs.Known.Count = uint64(len(ks))
	fs.Known.SHA256 = sha(lines.Bytes())
	if err := dump("known_accounts.txt", lines.Bytes()); err != nil {
		return fs, err
	}

	addrs, err := ledgerAddresses(l, trackerDB)
	if err != nil {
		return fs, err
	}
	type acct struct {
		key   string
		lines string
		algos uint64
	}
	var accts []acct
	for _, a := range addrs {
		base, _, err := l.LookupWithoutRewards(latest, a)
		if err != nil {
			return fs, err
		}
		if base.IsZero() {
			continue
		}
		full, _, _, err := l.LookupLatest(a)
		if err != nil {
			return fs, err
		}
		accts = append(accts, acct{a.String(), accountLines(a, base, full), base.MicroAlgos.Raw})
	}
	sort.Slice(accts, func(i, j int) bool { return accts[i].key < accts[j].key })
	lines.Reset()
	for _, a := range accts {
		lines.WriteString(a.lines)
		fs.Accounts.MicroAlgos += a.algos
	}
	fs.Accounts.Count = uint64(len(accts))
	fs.Accounts.SHA256 = sha(lines.Bytes())
	if err := dump("all_accounts.txt", lines.Bytes()); err != nil {
		return fs, err
	}

	keys, err := l.LookupKeysByPrefix(latest, boxPrefix, 0)
	if err != nil {
		return fs, err
	}
	sort.Strings(keys)
	lines.Reset()
	for _, k := range keys {
		v, err := l.LookupKv(latest, k)
		if err != nil {
			return fs, err
		}
		if v == nil {
			continue
		}
		fs.KV.Count++
		fmt.Fprintf(&lines, "%x %x\n", k, v)
	}
	fs.KV.SHA256 = sha(lines.Bytes())
	if err := dump("kv.txt", lines.Bytes()); err != nil {
		return fs, err
	}
	return fs, nil
}

// decodeJSON decodes with UseNumber, so integers above 2^53 keep every digit
// (json.Number) instead of being rounded through float64.
func decodeJSON(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(v)
}

// compareWithCorpus checks the replayed state against corpus.json's
// final_state (what the generating go-algorand node reported over REST).
func compareWithCorpus(fs finalState, want map[string]any) []string {
	// want comes from decodeJSON: integers are json.Number, parsed exactly.
	num := func(k string) (uint64, bool) {
		n, ok := want[k].(json.Number)
		if !ok {
			return 0, false
		}
		v, err := strconv.ParseUint(n.String(), 10, 64)
		return v, err == nil
	}
	var mm []string
	check := func(name string, got uint64) {
		w, ok := num(name)
		if !ok {
			mm = append(mm, fmt.Sprintf("%s missing from corpus.json", name))
		} else if w != got {
			mm = append(mm, fmt.Sprintf("%s: replay %d, corpus.json %d", name, got, w))
		}
	}
	check("round", fs.Round)
	check("txn_counter", fs.TxnCounter)
	check("total_money", fs.TotalMoney)
	check("online_money", fs.OnlineMoney)
	check("accounts", fs.Known.Count)
	check("accounts_microalgos", fs.Known.MicroAlgos)
	if s, _ := want["block_hash"].(string); s != fs.BlockHash {
		mm = append(mm, fmt.Sprintf("block_hash: replay %s, corpus.json %s", fs.BlockHash, s))
	}
	if s, _ := want["accounts_sha256"].(string); s != fs.Known.SHA256 {
		mm = append(mm, fmt.Sprintf("accounts_sha256: replay %s, corpus.json %s", fs.Known.SHA256, s))
	}
	return mm
}
