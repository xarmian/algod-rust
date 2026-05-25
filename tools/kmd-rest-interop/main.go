// kmd-rest-interop drives kmd-rust through the full v1 REST workflow
// using go-algorand's official `KMDClient`, then verifies every signed
// payload under go-algorand's crypto layer.
//
// Invocation:
//
//	kmd-rest-interop --data-dir <path> [--timeout 30s]
//
// The caller (the MIXED_CLUSTER Rust integration test) is responsible
// for spawning `kmd-rust serve --data-dir <path>` first.  This tool
// reads `<path>/kmd.net` and `<path>/kmd.token`, then drives:
//
//  1. List wallets (empty)
//  2. Create wallet
//  3. Init handle
//  4. Generate two keys (the "single-sig" + the "multisig threshold" signer)
//  5. Import one multisig preimage (1-of-1 over the first generated key)
//  6. Sign a payment transaction with the single key → verify the sig
//  7. Sign the same payment transaction with the 1-of-1 multisig → MultisigVerify
//  8. Sign a TEAL program → verify "Program"||data sig
//  9. Release the handle
//
// Exits 0 on success; any failure prints a diagnostic and exits non-zero.
package main

import (
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/daemon/kmd/client"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

func main() {
	dataDir := flag.String("data-dir", "", "path to the kmd-rust data dir (must contain kmd.net + kmd.token)")
	timeout := flag.Duration("timeout", 30*time.Second, "max wall time to wait for kmd-rust to be reachable")
	flag.Parse()
	if *dataDir == "" {
		fmt.Fprintln(os.Stderr, "kmd-rest-interop: --data-dir is required")
		os.Exit(2)
	}

	if err := run(*dataDir, *timeout); err != nil {
		fmt.Fprintf(os.Stderr, "kmd-rest-interop: %v\n", err)
		os.Exit(1)
	}
	log.Printf("kmd-rest-interop: OK")
}

func run(dataDir string, timeout time.Duration) error {
	addr, token, err := readNetAndToken(dataDir, timeout)
	if err != nil {
		return err
	}

	kcl, err := client.MakeKMDClient(addr, token)
	if err != nil {
		return fmt.Errorf("MakeKMDClient(%s): %w", addr, err)
	}

	// 1. /versions sanity check.
	versions, err := kcl.Version()
	if err != nil {
		return fmt.Errorf("Version: %w", err)
	}
	if len(versions.Versions) == 0 || versions.Versions[0] != "v1" {
		return fmt.Errorf("unexpected versions response: %+v", versions)
	}

	// 2. Initial wallet list (empty).
	list, err := kcl.ListWallets()
	if err != nil {
		return fmt.Errorf("ListWallets: %w", err)
	}
	if len(list.Wallets) != 0 {
		return fmt.Errorf("expected empty wallet list, got %d", len(list.Wallets))
	}

	// 3. Create wallet.
	walletName := []byte("interop-rest")
	walletPw := []byte("interop-pw")
	var fixedMDK crypto.MasterDerivationKey
	for i := range fixedMDK {
		fixedMDK[i] = byte(0xD0 + i) // distinct from Phase A's 0xA0 fixture
	}
	createResp, err := kcl.CreateWallet(walletName, "sqlite", walletPw, fixedMDK)
	if err != nil {
		return fmt.Errorf("CreateWallet: %w", err)
	}
	walletID := []byte(createResp.Wallet.ID)
	if len(walletID) == 0 {
		return fmt.Errorf("CreateWallet returned empty id")
	}

	// 4. Init handle.
	initResp, err := kcl.InitWallet(walletID, walletPw)
	if err != nil {
		return fmt.Errorf("InitWallet: %w", err)
	}
	handle := []byte(initResp.WalletHandleToken)

	// 5. Generate two keys.
	keyA, err := kcl.GenerateKey(handle)
	if err != nil {
		return fmt.Errorf("GenerateKey A: %w", err)
	}
	keyB, err := kcl.GenerateKey(handle)
	if err != nil {
		return fmt.Errorf("GenerateKey B: %w", err)
	}

	// 6. Sign a payment txn with key A.
	pkA, err := basics.UnmarshalChecksumAddress(keyA.Address)
	if err != nil {
		return fmt.Errorf("decode address A: %w", err)
	}
	pkB, err := basics.UnmarshalChecksumAddress(keyB.Address)
	if err != nil {
		return fmt.Errorf("decode address B: %w", err)
	}
	txn := payTxn(pkA, pkB)

	pkAed := crypto.PublicKey(pkA)
	signResp, err := kcl.SignTransaction(handle, walletPw, pkAed, txn)
	if err != nil {
		return fmt.Errorf("SignTransaction: %w", err)
	}
	var stxn transactions.SignedTxn
	if err := protocol.Decode(signResp.SignedTransaction, &stxn); err != nil {
		return fmt.Errorf("decode signed txn: %w", err)
	}
	// Verify the Ed25519 signature directly against the canonical
	// signing message Go produces (HashRep prepends the "TX" hash
	// tag).  This catches any byte-level wire divergence in the txn
	// encoding step.
	if !ed25519.Verify(pkA[:], crypto.HashRep(txn), stxn.Sig[:]) {
		return fmt.Errorf("single-sig verification failed")
	}

	// 7. Import a 1-of-1 multisig over keyA, then sign the same txn
	//    through the multisig route and MultisigVerify the result.
	msigResp, err := kcl.ImportMultisigAddr(handle, 1, 1, []crypto.PublicKey{pkAed})
	if err != nil {
		return fmt.Errorf("ImportMultisigAddr: %w", err)
	}
	msigAddrStr := msigResp.Address
	msigAddr, err := basics.UnmarshalChecksumAddress(msigAddrStr)
	if err != nil {
		return fmt.Errorf("decode multisig address: %w", err)
	}
	// Sign a payment from the multisig sender.
	msigTxn := payTxn(msigAddr, pkB)
	msigSignResp, err := kcl.MultisigSignTransaction(
		handle, walletPw, protocol.Encode(&msigTxn), pkAed, crypto.MultisigSig{}, crypto.Digest{},
	)
	if err != nil {
		return fmt.Errorf("MultisigSignTransaction: %w", err)
	}
	var assembled crypto.MultisigSig
	if err := protocol.Decode(msigSignResp.Multisig, &assembled); err != nil {
		return fmt.Errorf("decode assembled multisig: %w", err)
	}
	if err := crypto.MultisigVerify(msigTxn, crypto.Digest(msigAddr), assembled); err != nil {
		return fmt.Errorf("MultisigVerify: %w", err)
	}

	// 8. Sign a TEAL program with keyA → verify "Program"||data sig.
	program := []byte{0x02, 0x20, 0x01, 0x01, 0x22, 0x43}
	progResp, err := kcl.SignProgram(handle, walletPw, keyA.Address, program)
	if err != nil {
		return fmt.Errorf("SignProgram: %w", err)
	}
	// Go's signing message is "Program" || data — same on both sides.
	msg := append([]byte("Program"), program...)
	if !ed25519.Verify(pkA[:], msg, progResp.Signature) {
		return fmt.Errorf("program-sign verification failed")
	}

	// 9. Release.
	if _, err := kcl.ReleaseWalletHandle(handle); err != nil {
		return fmt.Errorf("ReleaseWalletHandle: %w", err)
	}

	// 10. Verify the released handle is dead (401 on /wallet/info).
	if _, err := kcl.RenewWalletHandle(handle); err == nil {
		return fmt.Errorf("RenewWalletHandle on released token should have failed")
	}
	return nil
}

func payTxn(sender, receiver basics.Address) transactions.Transaction {
	return transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      sender,
			Fee:         basics.MicroAlgos{Raw: 1000},
			FirstValid:  basics.Round(1),
			LastValid:   basics.Round(1000),
			GenesisID:   "interop-v1",
			GenesisHash: crypto.Digest{0xD1, 0xD2, 0xD3},
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: 42},
		},
	}
}

// readNetAndToken polls for kmd.net + kmd.token to appear (the
// kmd-rust server writes them after binding) and returns the bound
// address + API token.  Used so the caller can race the spawn / drive
// sequence without an explicit handshake.
func readNetAndToken(dataDir string, timeout time.Duration) (string, string, error) {
	netPath := filepath.Join(dataDir, "kmd.net")
	tokenPath := filepath.Join(dataDir, "kmd.token")
	deadline := time.Now().Add(timeout)
	for {
		netBytes, netErr := os.ReadFile(netPath)
		tokBytes, tokErr := os.ReadFile(tokenPath)
		if netErr == nil && tokErr == nil {
			addr := strings.TrimSpace(string(netBytes))
			token := strings.TrimSpace(string(tokBytes))
			if addr != "" && token != "" {
				return addr, token, nil
			}
		}
		if time.Now().After(deadline) {
			return "", "", fmt.Errorf(
				"timed out waiting for kmd.net + kmd.token at %s (net err=%v, token err=%v)",
				dataDir, netErr, tokErr,
			)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
