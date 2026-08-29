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

// kmd-wallet-with-keys-fixture-capture extends the wallet fixture
// from tools/kmd-wallet-fixture-capture by populating it with derived
// + imported keys, so the algo-kmd Rust port can verify list_keys /
// lookup_key / export_key against bytes produced by go-algorand's own
// kmd driver.
//
// The on-disk DB bytes are not byte-deterministic (Go's crypto/rand
// drives MEP/salt/nonce in CreateWallet + each encryptBlobWithKey
// call) but the *derived addresses* and *exported secret keys* are
// deterministic once we fix the MDK and the imported seeds. We
// regenerate by Init'ing the wallet and ExportKey'ing each address;
// those bytes go straight into the manifest.
//
// Regenerate with:
//
//	cd tools/kmd-wallet-with-keys-fixture-capture && go run . \
//	    ../../crates/node/algo-kmd/tests/fixtures/go_wallet_with_keys
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/kmd/config"
	"github.com/algorand/go-algorand/daemon/kmd/wallet/driver"
	"github.com/algorand/go-algorand/logging"
)

const (
	walletName  = "interop-with-keys"
	walletID    = "interop-keys-1"
	password    = "correct horse battery staple"
	numDerived  = 3
	numImported = 2
)

type keyEntry struct {
	AddressHex   string  `json:"address_hex"`
	SecretKeyHex string  `json:"secret_key_hex"`
	KeyIdx       *uint64 `json:"key_idx,omitempty"`
	Source       string  `json:"source"` // "derived" or "imported"
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: kmd-wallet-with-keys-fixture-capture <output-dir>")
	}
	outDir, err := filepath.Abs(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		log.Fatal(err)
	}

	cfg := config.KMDConfig{
		DataDir: outDir,
		DriverConfig: config.DriverConfig{
			SQLiteWalletDriverConfig: config.SQLiteWalletDriverConfig{
				UnsafeScrypt: true,
				ScryptParams: config.ScryptParams{
					ScryptN: 1024, ScryptR: 1, ScryptP: 1,
				},
			},
		},
	}

	var mdk crypto.MasterDerivationKey
	for i := range mdk {
		mdk[i] = byte(i + 1) // 0x01..0x20
	}

	logger := logging.NewLogger()
	logger.SetOutput(io.Discard)

	var swd driver.SQLiteWalletDriver
	if err := swd.InitWithConfig(cfg, logger); err != nil {
		log.Fatalf("InitWithConfig: %v", err)
	}

	walletsDir := filepath.Join(outDir, "sqlite_wallets")
	dbFile := filepath.Join(walletsDir, fmt.Sprintf("%s.%s.db", walletName, walletID))
	_ = os.Remove(dbFile)

	if err := swd.CreateWallet([]byte(walletName), []byte(walletID), []byte(password), mdk); err != nil {
		log.Fatalf("CreateWallet: %v", err)
	}

	w, err := swd.FetchWallet([]byte(walletID))
	if err != nil {
		log.Fatalf("FetchWallet: %v", err)
	}
	if err := w.Init([]byte(password)); err != nil {
		log.Fatalf("Init: %v", err)
	}

	derivedAddrs := make([]crypto.Digest, 0, numDerived)
	for i := 0; i < numDerived; i++ {
		addr, err := w.GenerateKey(false)
		if err != nil {
			log.Fatalf("GenerateKey #%d: %v", i, err)
		}
		derivedAddrs = append(derivedAddrs, addr)
	}

	importedAddrs := make([]crypto.Digest, 0, numImported)
	for i := 0; i < numImported; i++ {
		var seed crypto.Seed
		for j := range seed {
			seed[j] = byte(0x80 + i*16 + j)
		}
		secrets := crypto.GenerateSignatureSecrets(seed)
		sk := crypto.PrivateKey(secrets.SK)
		addr, err := w.ImportKey(sk)
		if err != nil {
			log.Fatalf("ImportKey #%d: %v", i, err)
		}
		importedAddrs = append(importedAddrs, addr)
	}

	indexFromOne := func(i int) *uint64 { v := uint64(i + 1); return &v }

	entries := make([]keyEntry, 0, numDerived+numImported)
	for i, addr := range derivedAddrs {
		sk, err := w.ExportKey(addr, []byte(password))
		if err != nil {
			log.Fatalf("ExportKey derived #%d: %v", i, err)
		}
		entries = append(entries, keyEntry{
			AddressHex:   hex.EncodeToString(addr[:]),
			SecretKeyHex: hex.EncodeToString(sk[:]),
			KeyIdx:       indexFromOne(i),
			Source:       "derived",
		})
	}
	for i, addr := range importedAddrs {
		sk, err := w.ExportKey(addr, []byte(password))
		if err != nil {
			log.Fatalf("ExportKey imported #%d: %v", i, err)
		}
		entries = append(entries, keyEntry{
			AddressHex:   hex.EncodeToString(addr[:]),
			SecretKeyHex: hex.EncodeToString(sk[:]),
			KeyIdx:       nil,
			Source:       "imported",
		})
	}

	manifest := struct {
		WalletDir   string     `json:"wallet_dir"`
		DbRelpath   string     `json:"db_relpath"`
		WalletName  string     `json:"wallet_name"`
		WalletID    string     `json:"wallet_id"`
		Password    string     `json:"password"`
		MdkHex      string     `json:"mdk_hex"`
		ScryptN     int        `json:"scrypt_n"`
		ScryptR     int        `json:"scrypt_r"`
		ScryptP     int        `json:"scrypt_p"`
		Keys        []keyEntry `json:"keys"`
		Description string     `json:"description"`
	}{
		WalletDir:  "sqlite_wallets",
		DbRelpath:  filepath.Join("sqlite_wallets", filepath.Base(dbFile)),
		WalletName: walletName,
		WalletID:   walletID,
		Password:   password,
		MdkHex:     hex.EncodeToString(mdk[:]),
		ScryptN:    1024, ScryptR: 1, ScryptP: 1,
		Keys: entries,
		Description: fmt.Sprintf("wallet with %d derived + %d imported keys, produced by go-algorand v4.6.0-stable kmd driver; consumed by algo-kmd's TASK-205 interop test",
			numDerived, numImported),
	}

	manifestPath := filepath.Join(outDir, "manifest.json")
	mf, err := os.Create(manifestPath)
	if err != nil {
		log.Fatal(err)
	}
	defer mf.Close()
	enc := json.NewEncoder(mf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(manifest); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("wrote %s and %s (%d derived + %d imported keys)\n",
		dbFile, manifestPath, numDerived, numImported)
}
