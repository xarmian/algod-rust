// canonical-extract: Extract canonical msgpack bytes from algod via the Go SDK.
//
// Connects to a local algod node, fetches blocks as raw msgpack, extracts
// transactions, and outputs canonical encoding for Rust conformance testing.
//
// Usage:
//
//	go run . -algod-url http://localhost:4001 \
//	  -algod-token aaaa...aa -rounds 1-5 \
//	  -output-dir ../../crates/core/algo-codec/tests/fixtures/canonical

package main

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"
)

// blockResponseRaw is a minimal block response that uses raw msgpack for
// the block body so we can handle unknown fields like prev512.
type blockResponseRaw struct {
	Block blockRaw `codec:"block"`
}

// blockRaw extracts only the payset from the block, ignoring unknown header fields.
type blockRaw struct {
	BlockHeader types.BlockHeader                  `codec:",inline"`
	Payset      []types.SignedTxnInBlock           `codec:"txns,allocbound=100000"`
}

func main() {
	algodURL := flag.String("algod-url", "http://localhost:4001", "algod REST API URL")
	algodToken := flag.String("algod-token", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "algod API token")
	rounds := flag.String("rounds", "1-5", "round range (e.g., 1-5)")
	outputDir := flag.String("output-dir", ".", "output directory for canonical bytes")
	flag.Parse()

	parts := strings.Split(*rounds, "-")
	if len(parts) != 2 {
		log.Fatalf("invalid rounds format: %s (expected start-end)", *rounds)
	}
	startRound, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		log.Fatalf("invalid start round: %v", err)
	}
	endRound, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		log.Fatalf("invalid end round: %v", err)
	}

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", *outputDir, err)
	}

	client, err := algod.MakeClient(*algodURL, *algodToken)
	if err != nil {
		log.Fatalf("failed to create algod client: %v", err)
	}

	ctx := context.Background()

	for round := startRound; round <= endRound; round++ {
		fmt.Printf("=== Round %d ===\n", round)

		blockBytes, err := client.BlockRaw(round).Do(ctx)
		if err != nil {
			log.Fatalf("failed to get block %d: %v", round, err)
		}

		// Decode just the payset from the block response.
		// We use a raw intermediate representation to extract transactions
		// without requiring the SDK to know every block header field.
		var payset []types.SignedTxnInBlock
		if err := extractPayset(blockBytes, &payset); err != nil {
			log.Fatalf("failed to extract payset from block %d: %v", round, err)
		}

		for i, stib := range payset {
			stxn := stib.SignedTxnWithAD.SignedTxn

			// Canonical encode of the inner Transaction (used for txn ID)
			txnBytes := msgpack.Encode(&stxn.Txn)
			txnHex := hex.EncodeToString(txnBytes)
			txnFile := filepath.Join(*outputDir, fmt.Sprintf("block_%d_txn_%d.canonical.hex", round, i))
			if err := os.WriteFile(txnFile, []byte(txnHex+"\n"), 0o644); err != nil {
				log.Fatalf("write %s: %v", txnFile, err)
			}
			fmt.Printf("  txn[%d]: %d bytes (type=%s) -> %s\n", i, len(txnBytes), stxn.Txn.Type, txnFile)

			// Compute transaction ID: SHA512/256("TX" || canonical_bytes)
			txnID := hashWithPrefix([]byte("TX"), txnBytes)
			txnIDFile := filepath.Join(*outputDir, fmt.Sprintf("block_%d_txn_%d.txid.hex", round, i))
			if err := os.WriteFile(txnIDFile, []byte(hex.EncodeToString(txnID[:])+"\n"), 0o644); err != nil {
				log.Fatalf("write %s: %v", txnIDFile, err)
			}
			fmt.Printf("  txid[%d]: %s -> %s\n", i, hex.EncodeToString(txnID[:]), txnIDFile)

			// Canonical encode of the SignedTxn
			stxnBytes := msgpack.Encode(&stxn)
			stxnHex := hex.EncodeToString(stxnBytes)
			stxnFile := filepath.Join(*outputDir, fmt.Sprintf("block_%d_stxn_%d.canonical.hex", round, i))
			if err := os.WriteFile(stxnFile, []byte(stxnHex+"\n"), 0o644); err != nil {
				log.Fatalf("write %s: %v", stxnFile, err)
			}
			fmt.Printf("  stxn[%d]: %d bytes -> %s\n", i, len(stxnBytes), stxnFile)
		}

		// Block digest: use the "prev" field of the NEXT block as the
		// authoritative digest of this block's header. This avoids
		// re-encoding the header (which can corrupt string/binary types
		// when round-tripping through generic maps).
		nextBlockBytes, err := client.BlockRaw(round + 1).Do(ctx)
		if err != nil {
			fmt.Printf("  digest: SKIPPED (cannot fetch block %d for prev field)\n", round+1)
			continue
		}
		prevHash, err := extractPrevHash(nextBlockBytes)
		if err != nil {
			log.Fatalf("failed to extract prev hash from block %d: %v", round+1, err)
		}
		digestFile := filepath.Join(*outputDir, fmt.Sprintf("block_%d.digest.hex", round))
		if err := os.WriteFile(digestFile, []byte(hex.EncodeToString(prevHash)+"\n"), 0o644); err != nil {
			log.Fatalf("write %s: %v", digestFile, err)
		}
		fmt.Printf("  digest: %s -> %s\n", hex.EncodeToString(prevHash), digestFile)
	}

	fmt.Println("\nDone. Reference canonical bytes written.")
}

// hashWithPrefix computes SHA512/256(prefix || data).
func hashWithPrefix(prefix, data []byte) [32]byte {
	h := sha512.New512_256()
	h.Write(prefix)
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// extractPrevHash extracts the "prev" field from a block response.
// This is the SHA512/256 digest of the previous block's header.
// Uses generic map decoding to avoid SDK type limitations.
func extractPrevHash(blockBytes []byte) ([]byte, error) {
	var raw map[string]interface{}
	if err := msgpack.Decode(blockBytes, &raw); err != nil {
		return nil, fmt.Errorf("raw decode: %w", err)
	}

	blockRaw, ok := raw["block"]
	if !ok {
		return nil, fmt.Errorf("no 'block' field in response")
	}

	blockMap, ok := blockRaw.(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("block is not a map, got %T", blockRaw)
	}

	prev, ok := blockMap["prev"]
	if !ok {
		return nil, fmt.Errorf("no 'prev' field in block")
	}

	prevBytes, ok := prev.([]byte)
	if !ok {
		return nil, fmt.Errorf("prev is not bytes, got %T", prev)
	}

	return prevBytes, nil
}

// extractPayset decodes just the payset from the raw block response msgpack,
// working around unknown block header fields.
func extractPayset(blockBytes []byte, payset *[]types.SignedTxnInBlock) error {
	// Decode the block response into a generic map first
	var raw map[string]interface{}
	if err := msgpack.Decode(blockBytes, &raw); err != nil {
		return fmt.Errorf("raw decode: %w", err)
	}

	// Get the "block" field
	blockRaw, ok := raw["block"]
	if !ok {
		return fmt.Errorf("no 'block' field in response")
	}

	blockMap, ok := blockRaw.(map[interface{}]interface{})
	if !ok {
		return fmt.Errorf("block is not a map, got %T", blockRaw)
	}

	// Get the "txns" field from the block
	txnsRaw, ok := blockMap["txns"]
	if !ok {
		// No transactions in this block
		*payset = nil
		return nil
	}

	// Re-encode just the txns array and decode into typed slice
	txnsBytes := msgpack.Encode(txnsRaw)
	return msgpack.Decode(txnsBytes, payset)
}
