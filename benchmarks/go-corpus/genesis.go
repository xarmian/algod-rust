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
	"fmt"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/protocol"
)

const (
	networkName = "benchcorpus"
	schemaID    = "v1"
	// genesisTimestamp pins the genesis block time (2026-01-01T00:00:00Z).
	// `goal network create` stamps the wall clock instead (CLAUDE.md, issue
	// #1590), which is why this generator writes its own genesis.
	genesisTimestamp = 1767225600
	numValidators    = 4
	accountAlgos     = 1_000_000_000_000   // 1M Algo per workload account
	validatorAlgos   = 100_000_000_000_000 // 100M Algo of online ballast stake
	rewardsPoolAlgos = 100_000_000_000_000
)

// network holds every key the generator knows about. Index 0 of accounts is
// the "admin": asset creator/manager/freeze/clawback and app creator.
type network struct {
	seed        string
	rewardsPool key
	feeSink     key
	validators  []key
	accounts    []key
}

func newNetwork(seed string, numAccounts int) *network {
	n := &network{
		seed:        seed,
		rewardsPool: deriveKey(seed, "rewards-pool", 0),
		feeSink:     deriveKey(seed, "fee-sink", 0),
	}
	for i := 0; i < numValidators; i++ {
		n.validators = append(n.validators, deriveKey(seed, "validator", uint64(i)))
	}
	for i := 0; i < numAccounts; i++ {
		n.accounts = append(n.accounts, deriveKey(seed, "account", uint64(i)))
	}
	return n
}

// genesis builds the DevMode genesis. Every field is a function of the seed
// and the account count, so its hash (and with it every txid's `gh`) is
// reproducible.
func (n *network) genesis() bookkeeping.Genesis {
	proto := config.Consensus[protocol.ConsensusCurrentVersion]
	g := bookkeeping.Genesis{
		SchemaID:    schemaID,
		Network:     protocol.NetworkID(networkName),
		Proto:       protocol.ConsensusCurrentVersion,
		RewardsPool: n.rewardsPool.addr.String(),
		FeeSink:     n.feeSink.addr.String(),
		Timestamp:   genesisTimestamp,
		Comment:     "algod-rust deterministic benchmark corpus (issue #2104)",
		DevMode:     true,
	}
	add := func(name string, addr basics.Address, st bookkeeping.GenesisAccountData) {
		g.Allocation = append(g.Allocation, bookkeeping.GenesisAllocation{
			Address: addr.String(), Comment: name, State: st,
		})
	}
	add("RewardsPool", n.rewardsPool.addr, bookkeeping.GenesisAccountData{
		Status: basics.NotParticipating, MicroAlgos: basics.MicroAlgos{Raw: rewardsPoolAlgos},
	})
	add("FeeSink", n.feeSink.addr, bookkeeping.GenesisAccountData{
		Status: basics.NotParticipating, MicroAlgos: basics.MicroAlgos{Raw: proto.MinBalance},
	})
	for i, v := range n.validators {
		pk := derivePartKeys(n.seed, "validator", uint64(i))
		add(fmt.Sprintf("validator-%d", i), v.addr, bookkeeping.GenesisAccountData{
			Status:          basics.Online,
			MicroAlgos:      basics.MicroAlgos{Raw: validatorAlgos},
			VoteID:          pk.vote,
			SelectionID:     pk.selection,
			StateProofID:    pk.stateProf,
			VoteFirstValid:  0,
			VoteLastValid:   10_000_000,
			VoteKeyDilution: 10_000,
		})
	}
	for i, a := range n.accounts {
		add(fmt.Sprintf("account-%d", i), a.addr, bookkeeping.GenesisAccountData{
			Status: basics.Offline, MicroAlgos: basics.MicroAlgos{Raw: accountAlgos},
		})
	}
	return g
}

// nodeConfig is the fixed config.json of the single DevMode node: archival
// (every block stays servable), no peers, the developer + experimental APIs
// on (/v2/devmode/blocks/offset, /v2/transactions/async).
func nodeConfig() config.Local {
	cfg := config.GetDefaultLocal()
	cfg.Archival = true
	cfg.EnableDeveloperAPI = true
	cfg.EnableExperimentalAPI = true
	cfg.DNSBootstrapID = ""
	cfg.GossipFanout = 0
	cfg.IncomingConnectionsLimit = 0
	cfg.NetAddress = ""
	cfg.EndpointAddress = "127.0.0.1:0"
	return cfg
}

// writeDataDir writes genesis.json and config.json into dir.
func writeDataDir(n *network, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	g := n.genesis()
	js := append(protocol.EncodeJSON(g), '\n')
	if err := os.WriteFile(filepath.Join(dir, config.GenesisJSONFile), js, 0o644); err != nil {
		return err
	}
	return nodeConfig().SaveToFile(filepath.Join(dir, config.ConfigFilename))
}
