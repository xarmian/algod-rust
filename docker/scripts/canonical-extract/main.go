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

			// Canonical encode of the SignedTxn
			stxnBytes := msgpack.Encode(&stxn)
			stxnHex := hex.EncodeToString(stxnBytes)
			stxnFile := filepath.Join(*outputDir, fmt.Sprintf("block_%d_stxn_%d.canonical.hex", round, i))
			if err := os.WriteFile(stxnFile, []byte(stxnHex+"\n"), 0o644); err != nil {
				log.Fatalf("write %s: %v", stxnFile, err)
			}
			fmt.Printf("  stxn[%d]: %d bytes -> %s\n", i, len(stxnBytes), stxnFile)
		}
	}

	fmt.Println("\nDone. Reference canonical bytes written.")
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
