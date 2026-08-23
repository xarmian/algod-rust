// kmd-wallet-multisig-fixture-capture creates a wallet populated with
// derived/imported keys AND multisig addresses, so the algo-kmd Rust
// port can verify ImportMultisigAddr / LookupMultisigPreimage /
// ListMultisigAddrs / DeleteMultisigAddr against bytes Go writes.
//
// Like the sibling key-fixture tool, the on-disk DB bytes aren't
// byte-deterministic (Go's crypto/rand drives MEP/salt/nonces) but the
// stored *addresses* and *pks blobs* are deterministic once the input
// public keys are fixed. We extract the bytes via LookupMultisigPreimage
// after creation and pin them in the manifest.
//
// Regenerate with:
//
//	cd tools/kmd-wallet-multisig-fixture-capture && go run . \
//	    ../../crates/node/algo-kmd/tests/fixtures/go_wallet_multisig
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
	walletName = "interop-msig"
	walletID   = "interop-msig-1"
	password   = "correct horse battery staple"
)

type msigEntry struct {
	AddressHex string   `json:"address_hex"`
	Version    uint8    `json:"version"`
	Threshold  uint8    `json:"threshold"`
	PksHex     []string `json:"pks_hex"`
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: kmd-wallet-multisig-fixture-capture <output-dir>")
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
				ScryptParams: config.ScryptParams{ScryptN: 1024, ScryptR: 1, ScryptP: 1},
			},
		},
	}

	var mdk crypto.MasterDerivationKey
	for i := range mdk {
		mdk[i] = byte(i + 1)
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

	// Three multisig preimages with deterministic public keys + varied
	// thresholds so the test exercises a handful of shapes:
	//   - 2-of-3
	//   - 1-of-2
	//   - 4-of-5
	makeMsigPks := func(count int, offset byte) []crypto.PublicKey {
		out := make([]crypto.PublicKey, count)
		for i := 0; i < count; i++ {
			for j := 0; j < 32; j++ {
				out[i][j] = offset + byte(i*32+j)
			}
		}
		return out
	}

	type msigInput struct {
		version, threshold uint8
		pks                []crypto.PublicKey
	}
	inputs := []msigInput{
		{1, 2, makeMsigPks(3, 0x10)},
		{1, 1, makeMsigPks(2, 0x40)},
		{1, 4, makeMsigPks(5, 0x70)},
	}

	entries := make([]msigEntry, 0, len(inputs))
	for i, in := range inputs {
		addr, err := w.ImportMultisigAddr(in.version, in.threshold, in.pks)
		if err != nil {
			log.Fatalf("ImportMultisigAddr #%d: %v", i, err)
		}

		// Round-trip via lookup to sanity-check the (version, threshold,
		// pks) recovered from disk before we record them.
		gotV, gotT, gotPks, err := w.LookupMultisigPreimage(addr)
		if err != nil {
			log.Fatalf("LookupMultisigPreimage #%d: %v", i, err)
		}
		if gotV != in.version || gotT != in.threshold {
			log.Fatalf("lookup mismatch on #%d: got (%d,%d) want (%d,%d)",
				i, gotV, gotT, in.version, in.threshold)
		}
		if len(gotPks) != len(in.pks) {
			log.Fatalf("pk count mismatch on #%d", i)
		}

		pksHex := make([]string, len(gotPks))
		for j, pk := range gotPks {
			pksHex[j] = hex.EncodeToString(pk[:])
		}
		entries = append(entries, msigEntry{
			AddressHex: hex.EncodeToString(addr[:]),
			Version:    in.version,
			Threshold:  in.threshold,
			PksHex:     pksHex,
		})
	}

	manifest := struct {
		WalletDir   string      `json:"wallet_dir"`
		DbRelpath   string      `json:"db_relpath"`
		WalletName  string      `json:"wallet_name"`
		WalletID    string      `json:"wallet_id"`
		Password    string      `json:"password"`
		MdkHex      string      `json:"mdk_hex"`
		ScryptN     int         `json:"scrypt_n"`
		ScryptR     int         `json:"scrypt_r"`
		ScryptP     int         `json:"scrypt_p"`
		Multisig    []msigEntry `json:"multisig"`
		Description string      `json:"description"`
	}{
		WalletDir:  "sqlite_wallets",
		DbRelpath:  filepath.Join("sqlite_wallets", filepath.Base(dbFile)),
		WalletName: walletName,
		WalletID:   walletID,
		Password:   password,
		MdkHex:     hex.EncodeToString(mdk[:]),
		ScryptN:    1024, ScryptR: 1, ScryptP: 1,
		Multisig: entries,
		Description: fmt.Sprintf("wallet with %d multisig preimages produced by go-algorand v4.6.0-stable kmd; consumed by algo-kmd's TASK-206 interop test",
			len(inputs)),
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

	fmt.Printf("wrote %s and %s (%d multisig entries)\n", dbFile, manifestPath, len(inputs))
}
