// kmd-wallet-interop is the Go side of algo-kmd's TASK-207 MIXED_CLUSTER
// interop test. It exposes two subcommands:
//
//	write   <out_dir>
//	    Create a wallet at <out_dir>/sqlite_wallets/<name>.<id>.db with a
//	    deterministic workload: a fixed MDK, N derived keys, M imported
//	    keys, K multisig entries. Emit a manifest.json describing every
//	    address + secret + multisig preimage so the Rust side can assert
//	    parity without re-running scrypt.
//
//	verify  <wallet_dir> <manifest_path>
//	    Open the wallet at <wallet_dir> (relative to its sqlite_wallets
//	    subdir) and assert every key/multisig/MDK in the manifest is
//	    present and matches byte-for-byte. Exit non-zero on any mismatch.
//
// The single tool covers both interop directions:
//   - Direction A (Go-writes, Rust-reads): Rust shells out to `write`, then
//     opens the wallet via algo-kmd and asserts each manifest entry.
//   - Direction B (Rust-writes, Go-reads): Rust uses algo-kmd to create a
//     wallet + write a manifest, then shells out to `verify`.
//
// Workload constants must stay in sync with the Rust side
// (tests/interop_test.rs::WORKLOAD_*).
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
	walletName    = "interop"
	walletID      = "interop-id"
	password      = "interop-pw"
	numDerived    = 2
	numImported   = 2
	scryptN       = 1024
	scryptR       = 1
	scryptP       = 1
)

type keyEntry struct {
	AddressHex   string  `json:"address_hex"`
	SecretKeyHex string  `json:"secret_key_hex"`
	KeyIdx       *uint64 `json:"key_idx,omitempty"`
	Source       string  `json:"source"`
}

type msigEntry struct {
	AddressHex string   `json:"address_hex"`
	Version    uint8    `json:"version"`
	Threshold  uint8    `json:"threshold"`
	PksHex     []string `json:"pks_hex"`
}

type manifest struct {
	DbRelpath  string      `json:"db_relpath"`
	WalletID   string      `json:"wallet_id"`
	WalletName string      `json:"wallet_name"`
	Password   string      `json:"password"`
	MdkHex     string      `json:"mdk_hex"`
	ScryptN    int         `json:"scrypt_n"`
	ScryptR    int         `json:"scrypt_r"`
	ScryptP    int         `json:"scrypt_p"`
	Keys       []keyEntry  `json:"keys"`
	Multisig   []msigEntry `json:"multisig"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "write":
		if len(os.Args) != 3 {
			usage()
		}
		runWrite(os.Args[2])
	case "verify":
		if len(os.Args) != 4 {
			usage()
		}
		runVerify(os.Args[2], os.Args[3])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr,
		"usage:\n  %s write <out_dir>\n  %s verify <wallet_dir> <manifest_path>\n",
		os.Args[0], os.Args[0])
	os.Exit(2)
}

func fixedMDK() crypto.MasterDerivationKey {
	var mdk crypto.MasterDerivationKey
	for i := range mdk {
		mdk[i] = byte(0xA0 + i) // distinct from other fixtures
	}
	return mdk
}

func importedSeeds() []crypto.Seed {
	out := make([]crypto.Seed, numImported)
	for i := range out {
		for j := range out[i] {
			out[i][j] = byte(0xC0 + i*32 + j)
		}
	}
	return out
}

type msigDef struct{ version, threshold uint8; pkOffset byte; pkCount int }

func msigInputs() []msigDef {
	return []msigDef{
		{1, 2, 0x10, 3},
		{1, 1, 0x40, 2},
	}
}

func makePks(count int, offset byte) []crypto.PublicKey {
	out := make([]crypto.PublicKey, count)
	for i := range out {
		for j := range out[i] {
			out[i][j] = offset + byte(i*32+j)
		}
	}
	return out
}

// ---- write -----------------------------------------------------------------

func runWrite(outDir string) {
	abs, err := filepath.Abs(outDir)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		log.Fatal(err)
	}

	cfg := config.KMDConfig{
		DataDir: abs,
		DriverConfig: config.DriverConfig{
			SQLiteWalletDriverConfig: config.SQLiteWalletDriverConfig{
				UnsafeScrypt: true,
				ScryptParams: config.ScryptParams{ScryptN: scryptN, ScryptR: scryptR, ScryptP: scryptP},
			},
		},
	}
	logger := logging.NewLogger()
	logger.SetOutput(io.Discard)

	var swd driver.SQLiteWalletDriver
	if err := swd.InitWithConfig(cfg, logger); err != nil {
		log.Fatalf("InitWithConfig: %v", err)
	}

	mdk := fixedMDK()

	walletsDir := filepath.Join(abs, "sqlite_wallets")
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

	mfst := manifest{
		DbRelpath:  filepath.Join("sqlite_wallets", filepath.Base(dbFile)),
		WalletID:   walletID,
		WalletName: walletName,
		Password:   password,
		MdkHex:     hex.EncodeToString(mdk[:]),
		ScryptN:    scryptN, ScryptR: scryptR, ScryptP: scryptP,
	}

	for i := 0; i < numDerived; i++ {
		addr, err := w.GenerateKey(false)
		if err != nil {
			log.Fatalf("GenerateKey: %v", err)
		}
		sk, err := w.ExportKey(addr, []byte(password))
		if err != nil {
			log.Fatalf("ExportKey: %v", err)
		}
		idx := uint64(i + 1)
		mfst.Keys = append(mfst.Keys, keyEntry{
			AddressHex:   hex.EncodeToString(addr[:]),
			SecretKeyHex: hex.EncodeToString(sk[:]),
			KeyIdx:       &idx,
			Source:       "derived",
		})
	}

	for i, seed := range importedSeeds() {
		secrets := crypto.GenerateSignatureSecrets(seed)
		sk := crypto.PrivateKey(secrets.SK)
		addr, err := w.ImportKey(sk)
		if err != nil {
			log.Fatalf("ImportKey %d: %v", i, err)
		}
		exported, err := w.ExportKey(addr, []byte(password))
		if err != nil {
			log.Fatalf("ExportKey imported: %v", err)
		}
		mfst.Keys = append(mfst.Keys, keyEntry{
			AddressHex:   hex.EncodeToString(addr[:]),
			SecretKeyHex: hex.EncodeToString(exported[:]),
			Source:       "imported",
		})
	}

	for _, m := range msigInputs() {
		pks := makePks(m.pkCount, m.pkOffset)
		addr, err := w.ImportMultisigAddr(m.version, m.threshold, pks)
		if err != nil {
			log.Fatalf("ImportMultisigAddr: %v", err)
		}
		pksHex := make([]string, len(pks))
		for i, pk := range pks {
			pksHex[i] = hex.EncodeToString(pk[:])
		}
		mfst.Multisig = append(mfst.Multisig, msigEntry{
			AddressHex: hex.EncodeToString(addr[:]),
			Version:    m.version,
			Threshold:  m.threshold,
			PksHex:     pksHex,
		})
	}

	manifestPath := filepath.Join(abs, "manifest.json")
	mf, err := os.Create(manifestPath)
	if err != nil {
		log.Fatal(err)
	}
	defer mf.Close()
	enc := json.NewEncoder(mf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&mfst); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s and %s (%d keys, %d multisig)\n",
		dbFile, manifestPath, len(mfst.Keys), len(mfst.Multisig))
}

// ---- verify ----------------------------------------------------------------

func runVerify(walletDir, manifestPath string) {
	absDir, err := filepath.Abs(walletDir)
	if err != nil {
		log.Fatal(err)
	}

	mfBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		log.Fatalf("read manifest: %v", err)
	}
	var mfst manifest
	if err := json.Unmarshal(mfBytes, &mfst); err != nil {
		log.Fatalf("parse manifest: %v", err)
	}

	cfg := config.KMDConfig{
		DataDir: absDir,
		DriverConfig: config.DriverConfig{
			SQLiteWalletDriverConfig: config.SQLiteWalletDriverConfig{
				UnsafeScrypt: true,
				ScryptParams: config.ScryptParams{ScryptN: mfst.ScryptN, ScryptR: mfst.ScryptR, ScryptP: mfst.ScryptP},
			},
		},
	}
	logger := logging.NewLogger()
	logger.SetOutput(io.Discard)

	var swd driver.SQLiteWalletDriver
	if err := swd.InitWithConfig(cfg, logger); err != nil {
		log.Fatalf("InitWithConfig: %v", err)
	}

	w, err := swd.FetchWallet([]byte(mfst.WalletID))
	if err != nil {
		log.Fatalf("FetchWallet: %v", err)
	}
	if err := w.Init([]byte(mfst.Password)); err != nil {
		log.Fatalf("Init: %v", err)
	}

	// MDK round-trip.
	exportedMDK, err := w.ExportMasterDerivationKey([]byte(mfst.Password))
	if err != nil {
		log.Fatalf("ExportMasterDerivationKey: %v", err)
	}
	expectedMDK, err := hex.DecodeString(mfst.MdkHex)
	if err != nil {
		log.Fatalf("bad mdk_hex: %v", err)
	}
	if !bytesEqualSlice(exportedMDK[:], expectedMDK) {
		log.Fatalf("MDK mismatch:\n  got  %x\n  want %x", exportedMDK[:], expectedMDK)
	}

	// Keys.
	listedAddrs, err := w.ListKeys()
	if err != nil {
		log.Fatalf("ListKeys: %v", err)
	}
	addrSet := make(map[string]bool, len(listedAddrs))
	for _, a := range listedAddrs {
		addrSet[hex.EncodeToString(a[:])] = true
	}
	if len(addrSet) != len(mfst.Keys) {
		log.Fatalf("ListKeys count mismatch: got %d, want %d", len(addrSet), len(mfst.Keys))
	}
	for _, k := range mfst.Keys {
		if !addrSet[k.AddressHex] {
			log.Fatalf("address %s missing from Go ListKeys output", k.AddressHex)
		}
		addrBytes, err := hex.DecodeString(k.AddressHex)
		if err != nil {
			log.Fatalf("bad address_hex: %v", err)
		}
		var addr crypto.Digest
		copy(addr[:], addrBytes)
		sk, err := w.ExportKey(addr, []byte(mfst.Password))
		if err != nil {
			log.Fatalf("ExportKey(%s): %v", k.AddressHex, err)
		}
		expected, _ := hex.DecodeString(k.SecretKeyHex)
		if !bytesEqualSlice(sk[:], expected) {
			log.Fatalf("SK mismatch for %s:\n  got  %x\n  want %x", k.AddressHex, sk[:], expected)
		}
	}

	// Multisig.
	listedMsig, err := w.ListMultisigAddrs()
	if err != nil {
		log.Fatalf("ListMultisigAddrs: %v", err)
	}
	if len(listedMsig) != len(mfst.Multisig) {
		log.Fatalf("ListMultisigAddrs count mismatch: got %d, want %d",
			len(listedMsig), len(mfst.Multisig))
	}
	msigSet := make(map[string]bool, len(listedMsig))
	for _, a := range listedMsig {
		msigSet[hex.EncodeToString(a[:])] = true
	}
	for _, m := range mfst.Multisig {
		if !msigSet[m.AddressHex] {
			log.Fatalf("multisig %s missing from Go ListMultisigAddrs", m.AddressHex)
		}
		addrBytes, _ := hex.DecodeString(m.AddressHex)
		var addr crypto.Digest
		copy(addr[:], addrBytes)
		gotV, gotT, gotPks, err := w.LookupMultisigPreimage(addr)
		if err != nil {
			log.Fatalf("LookupMultisigPreimage(%s): %v", m.AddressHex, err)
		}
		if gotV != m.Version || gotT != m.Threshold {
			log.Fatalf("multisig (v,t) mismatch for %s: got (%d,%d) want (%d,%d)",
				m.AddressHex, gotV, gotT, m.Version, m.Threshold)
		}
		if len(gotPks) != len(m.PksHex) {
			log.Fatalf("multisig pk count mismatch for %s", m.AddressHex)
		}
		for i, want := range m.PksHex {
			wantBytes, _ := hex.DecodeString(want)
			if !bytesEqualSlice(gotPks[i][:], wantBytes) {
				log.Fatalf("multisig pk[%d] mismatch for %s", i, m.AddressHex)
			}
		}
	}

	fmt.Printf("verify OK: %d keys, %d multisig, MDK matches\n",
		len(mfst.Keys), len(mfst.Multisig))
}

func bytesEqualSlice(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
