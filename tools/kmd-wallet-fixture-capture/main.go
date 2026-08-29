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

// kmd-wallet-fixture-capture creates a wallet SQLite database using
// go-algorand's actual kmd driver (CreateWallet), so the algo-kmd
// Rust port can prove interop by opening it.
//
// The on-disk bytes are NOT deterministic — Go's CreateWallet pulls a
// fresh MEP, salts, and nonces from crypto/rand. We pin determinism by:
//   1. supplying a fixed master-derivation key (MDK), and
//   2. using a known password.
//
// The Rust test opens the wallet, runs `Wallet::init(password)`, calls
// `export_master_derivation_key(password)`, and asserts the returned
// 32 bytes match the MDK we supplied here. That round-trip exercises
// scrypt(password) → MEP, secretbox(MEP) → MDK, and the metadata-row
// layout end-to-end against go-algorand's reference implementation.
//
// Regenerate with:
//
//	cd tools/kmd-wallet-fixture-capture && go run . \
//	    ../../crates/node/algo-kmd/tests/fixtures/go_wallet
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
	walletName = "interop-wallet"
	walletID   = "interop-id-1"
	password   = "correct horse battery staple"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: kmd-wallet-fixture-capture <output-dir>")
	}
	outDir, err := filepath.Abs(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		log.Fatal(err)
	}

	// kmd writes wallet .db files into a `sqlite_wallets/` subdirectory
	// of its data dir. We point the driver at outDir as its data dir,
	// so the wallet ends up at outDir/sqlite_wallets/<name>.<id>.db.
	cfg := config.KMDConfig{
		DataDir: outDir,
		DriverConfig: config.DriverConfig{
			SQLiteWalletDriverConfig: config.SQLiteWalletDriverConfig{
				// Weak scrypt so the fixture regenerates fast.
				// allow_unsafe_scrypt=true bypasses the production minimum.
				UnsafeScrypt: true,
				ScryptParams: config.ScryptParams{
					ScryptN: 1024,
					ScryptR: 1,
					ScryptP: 1,
				},
			},
		},
	}

	// Fixed MDK so the Rust assert has something to compare against.
	var mdk crypto.MasterDerivationKey
	for i := range mdk {
		mdk[i] = byte(i + 1) // 0x01, 0x02, ..., 0x20
	}

	// Silence the driver's logger.
	logger := logging.NewLogger()
	logger.SetOutput(io.Discard)

	var swd driver.SQLiteWalletDriver
	if err := swd.InitWithConfig(cfg, logger); err != nil {
		log.Fatalf("InitWithConfig: %v", err)
	}

	// Clean up any prior fixture under the same name so reruns are
	// idempotent. kmd's CreateWallet won't clobber an existing file.
	walletsDir := filepath.Join(outDir, "sqlite_wallets")
	dbFile := filepath.Join(walletsDir, fmt.Sprintf("%s.%s.db", walletName, walletID))
	_ = os.Remove(dbFile)

	if err := swd.CreateWallet([]byte(walletName), []byte(walletID), []byte(password), mdk); err != nil {
		log.Fatalf("CreateWallet: %v", err)
	}

	// Sanity: round-trip the export through Go too, so we know what we
	// wrote and what Rust should read back.
	w, err := swd.FetchWallet([]byte(walletID))
	if err != nil {
		log.Fatalf("FetchWallet: %v", err)
	}
	if err := w.Init([]byte(password)); err != nil {
		log.Fatalf("Init: %v", err)
	}
	exported, err := w.ExportMasterDerivationKey([]byte(password))
	if err != nil {
		log.Fatalf("ExportMasterDerivationKey: %v", err)
	}
	if exported != mdk {
		log.Fatalf("Go-side round-trip failed: exported MDK %x != supplied %x", exported[:], mdk[:])
	}

	// Emit a manifest the Rust test reads to know what to expect.
	manifest := struct {
		WalletDir   string `json:"wallet_dir"`
		DbRelpath   string `json:"db_relpath"`
		WalletName  string `json:"wallet_name"`
		WalletID    string `json:"wallet_id"`
		Password    string `json:"password"`
		MdkHex      string `json:"mdk_hex"`
		ScryptN     int    `json:"scrypt_n"`
		ScryptR     int    `json:"scrypt_r"`
		ScryptP     int    `json:"scrypt_p"`
		Description string `json:"description"`
	}{
		WalletDir:   "sqlite_wallets",
		DbRelpath:   filepath.Join("sqlite_wallets", filepath.Base(dbFile)),
		WalletName:  walletName,
		WalletID:    walletID,
		Password:    password,
		MdkHex:      hex.EncodeToString(mdk[:]),
		ScryptN:     1024,
		ScryptR:     1,
		ScryptP:     1,
		Description: "wallet produced by go-algorand v4.6.0-stable daemon/kmd/wallet/driver.SQLiteWalletDriver.CreateWallet; used by algo-kmd's interop test to verify Rust can open and export the MDK",
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

	fmt.Printf("wrote %s and %s\n", dbFile, manifestPath)
}
