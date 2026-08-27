// canonical-extract: Extract canonical msgpack bytes from algod for
// Rust conformance testing.
//
// Two operating modes:
//
//  1. -mode blocks (default): connect to a local algod node, fetch
//     blocks as raw msgpack, and write per-block canonical fixtures
//     (transaction, signed transaction, txid, header digest).
//
//  2. -mode trackerdb-blobs: open a Go-produced tracker SQLite file
//     directly and dump every BLOB column (account / online-account /
//     resource / online-round-params / txtail / state-proof) as a
//     hex fixture, plus a `_meta.json` per type. PLAN-36 G8
//     (TASK-119) — the byte corpus for the G8 canonical-encoder
//     tasks (TASK-120..125).
//
// Examples:
//
//	# Blocks mode (existing behavior — default mode):
//	go run . -algod-url http://localhost:4001 \
//	    -algod-token aaaa...aa -rounds 1-5 \
//	    -output-dir ../../../crates/core/algo-codec/tests/fixtures/canonical
//
//	# trackerdb-blobs mode (new):
//	go run . -mode trackerdb-blobs \
//	    -tracker-db /tmp/devnet.tracker.sqlite \
//	    -output-dir ../../../crates/core/algo-codec/tests/fixtures/trackerdb \
//	    -source-version v4.7.2-stable \
//	    -source-prefix /algod/data/Node
package main

import (
	"context"
	"crypto/sha512"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/algod"
	"github.com/algorand/go-algorand-sdk/v2/encoding/msgpack"
	"github.com/algorand/go-algorand-sdk/v2/types"

	_ "modernc.org/sqlite"
)

// blockResponseRaw is a minimal block response that uses raw msgpack for
// the block body so we can handle unknown fields like prev512.
type blockResponseRaw struct {
	Block blockRaw `codec:"block"`
}

// blockRaw extracts only the payset from the block, ignoring unknown header fields.
type blockRaw struct {
	BlockHeader types.BlockHeader        `codec:",inline"`
	Payset      []types.SignedTxnInBlock `codec:"txns,allocbound=100000"`
}

func main() {
	mode := flag.String("mode", "blocks", "extraction mode: 'blocks' or 'trackerdb-blobs'")

	// Shared flag.
	outputDir := flag.String("output-dir", ".", "output directory for canonical bytes")

	// blocks-mode flags.
	algodURL := flag.String("algod-url", "http://localhost:4001", "[blocks mode] algod REST API URL")
	algodToken := flag.String("algod-token", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "[blocks mode] algod API token")
	rounds := flag.String("rounds", "1-5", "[blocks mode] round range (e.g., 1-5)")

	// trackerdb-blobs-mode flags.
	trackerDB := flag.String("tracker-db", "", "[trackerdb-blobs mode] path to the Go-produced <prefix>.tracker.sqlite file")
	sourceVersion := flag.String("source-version", "", "[trackerdb-blobs mode] go-algorand version that produced the DB (recorded in _meta.json)")
	sourcePrefix := flag.String("source-prefix", "", "[trackerdb-blobs mode] original data-dir prefix that produced the DB (recorded in _meta.json)")

	flag.Parse()

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", *outputDir, err)
	}

	switch *mode {
	case "blocks":
		runBlocksMode(*algodURL, *algodToken, *rounds, *outputDir)
	case "trackerdb-blobs":
		if *trackerDB == "" {
			log.Fatalf("-mode trackerdb-blobs requires -tracker-db <path>")
		}
		if err := runTrackerdbBlobsMode(*trackerDB, *outputDir, *sourceVersion, *sourcePrefix); err != nil {
			log.Fatalf("trackerdb-blobs: %v", err)
		}
	default:
		log.Fatalf("unknown -mode %q (expected 'blocks' or 'trackerdb-blobs')", *mode)
	}
}

// ---------------------------------------------------------------------------
// blocks mode (pre-existing behavior, refactored into a single entry point)
// ---------------------------------------------------------------------------

func runBlocksMode(algodURL, algodToken, rounds, outputDir string) {
	parts := strings.Split(rounds, "-")
	if len(parts) != 2 {
		log.Fatalf("invalid rounds format: %s (expected start-end)", rounds)
	}
	startRound, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		log.Fatalf("invalid start round: %v", err)
	}
	endRound, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		log.Fatalf("invalid end round: %v", err)
	}

	client, err := algod.MakeClient(algodURL, algodToken)
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
			txnFile := filepath.Join(outputDir, fmt.Sprintf("block_%d_txn_%d.canonical.hex", round, i))
			if err := os.WriteFile(txnFile, []byte(txnHex+"\n"), 0o644); err != nil {
				log.Fatalf("write %s: %v", txnFile, err)
			}
			fmt.Printf("  txn[%d]: %d bytes (type=%s) -> %s\n", i, len(txnBytes), stxn.Txn.Type, txnFile)

			// Compute transaction ID: SHA512/256("TX" || canonical_bytes)
			txnID := hashWithPrefix([]byte("TX"), txnBytes)
			txnIDFile := filepath.Join(outputDir, fmt.Sprintf("block_%d_txn_%d.txid.hex", round, i))
			if err := os.WriteFile(txnIDFile, []byte(hex.EncodeToString(txnID[:])+"\n"), 0o644); err != nil {
				log.Fatalf("write %s: %v", txnIDFile, err)
			}
			fmt.Printf("  txid[%d]: %s -> %s\n", i, hex.EncodeToString(txnID[:]), txnIDFile)

			// Canonical encode of the SignedTxn
			stxnBytes := msgpack.Encode(&stxn)
			stxnHex := hex.EncodeToString(stxnBytes)
			stxnFile := filepath.Join(outputDir, fmt.Sprintf("block_%d_stxn_%d.canonical.hex", round, i))
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
		digestFile := filepath.Join(outputDir, fmt.Sprintf("block_%d.digest.hex", round))
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

// ---------------------------------------------------------------------------
// trackerdb-blobs mode (PLAN-36 TASK-119)
// ---------------------------------------------------------------------------

// blobMeta is the schema for every `<type>/_meta.json` sibling file.
//
// Fields are intentionally flat so this stays diffable as the corpus
// regenerates round-to-round; only counts + provenance change.
type blobMeta struct {
	Type            string `json:"type"`
	SourceVersion   string `json:"source_go_algorand_version,omitempty"`
	SourcePrefix    string `json:"source_data_dir_prefix,omitempty"`
	SourceDB        string `json:"source_tracker_db"`
	CapturedAtUTC   string `json:"captured_at_utc"`
	RowCount        int    `json:"row_count"`
	HighestRound    *int64 `json:"highest_round,omitempty"`
	Notes           string `json:"notes,omitempty"`
}

func runTrackerdbBlobsMode(trackerDB, outputDir, sourceVersion, sourcePrefix string) error {
	abs, err := filepath.Abs(trackerDB)
	if err != nil {
		return fmt.Errorf("resolve tracker-db path: %w", err)
	}
	if _, err := os.Stat(abs); err != nil {
		return fmt.Errorf("tracker-db not accessible: %w", err)
	}

	// Open read-only. `mode=ro` blocks writes; we intentionally do NOT
	// pass `immutable=1` because the algod writer keeps the DB in WAL
	// mode, so recent rows may live in `<file>-wal` until checkpoint.
	// `immutable=1` would tell SQLite to ignore the WAL entirely and
	// produce stale fixtures (Codex review, PR #295). The Make target
	// docker-cps both `-wal` and `-shm` sidecars alongside the main
	// file so this read sees a consistent view of any unflushed
	// frames.
	dsn := fmt.Sprintf("file:%s?mode=ro", abs)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return fmt.Errorf("ping sqlite: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)

	fmt.Printf("=== trackerdb-blobs: %s ===\n", abs)

	if err := dumpAccountbase(db, outputDir, sourceVersion, sourcePrefix, abs, now); err != nil {
		return fmt.Errorf("accountbase: %w", err)
	}
	if err := dumpOnlineAccounts(db, outputDir, sourceVersion, sourcePrefix, abs, now); err != nil {
		return fmt.Errorf("onlineaccounts: %w", err)
	}
	if err := dumpResources(db, outputDir, sourceVersion, sourcePrefix, abs, now); err != nil {
		return fmt.Errorf("resources: %w", err)
	}
	if err := dumpOnlineRoundParams(db, outputDir, sourceVersion, sourcePrefix, abs, now); err != nil {
		return fmt.Errorf("onlineroundparamstail: %w", err)
	}
	if err := dumpTxTail(db, outputDir, sourceVersion, sourcePrefix, abs, now); err != nil {
		return fmt.Errorf("txtail: %w", err)
	}
	if err := dumpStateProofVerification(db, outputDir, sourceVersion, sourcePrefix, abs, now); err != nil {
		return fmt.Errorf("stateproofverification: %w", err)
	}

	fmt.Println("\nDone. Trackerdb BLOB fixtures written.")
	return nil
}

// writeBlob writes `data` (hex-encoded, trailing newline matching the
// existing canonical/*.hex convention) to <dir>/<basename>.canonical.hex.
func writeBlob(dir, basename string, data []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, basename+".canonical.hex")
	return os.WriteFile(path, []byte(hex.EncodeToString(data)+"\n"), 0o644)
}

// resetTypeDir clears any stale `*.canonical.hex` files (and the
// `_meta.json` sibling) from a per-type output directory before a new
// capture writes fresh fixtures into it. Without this, a regenerated
// corpus would mix new + stale files when a later capture has fewer
// rows than an earlier one (Codex review, PR #295) — for example,
// `stateproof/` going from populated → empty, or an account leaving
// the online set. The function tolerates a non-existent dir (first
// run) and only removes the file types this tool writes, so a manual
// `README` placed in the dir would survive.
func resetTypeDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".canonical.hex") && name != "_meta.json" {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// writeMeta writes a `_meta.json` sibling describing the just-written
// fixture set. Pretty-printed for readable diffs.
func writeMeta(dir string, m blobMeta) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return os.WriteFile(filepath.Join(dir, "_meta.json"), body, 0o644)
}

// dumpAccountbase walks `accountbase(address, data)` and writes
// `baseaccountdata/<addrhex>.canonical.hex` per row.
func dumpAccountbase(db *sql.DB, outputDir, ver, prefix, src, now string) error {
	dir := filepath.Join(outputDir, "baseaccountdata")
	if err := resetTypeDir(dir); err != nil {
		return err
	}
	rows, err := db.Query(`SELECT address, data FROM accountbase`)
	if err != nil {
		return err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var addr, data []byte
		if err := rows.Scan(&addr, &data); err != nil {
			return err
		}
		if len(data) == 0 {
			continue
		}
		if err := writeBlob(dir, hex.EncodeToString(addr), data); err != nil {
			return err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	fmt.Printf("  baseaccountdata: %d rows\n", count)
	return writeMeta(dir, blobMeta{
		Type:          "baseaccountdata",
		SourceVersion: ver, SourcePrefix: prefix, SourceDB: src,
		CapturedAtUTC: now, RowCount: count,
		Notes: "One file per accountbase row; basename is the lowercase-hex 32-byte address.",
	})
}

// dumpOnlineAccounts walks `onlineaccounts(address, updround, data)`.
func dumpOnlineAccounts(db *sql.DB, outputDir, ver, prefix, src, now string) error {
	dir := filepath.Join(outputDir, "baseonlineaccountdata")
	if err := resetTypeDir(dir); err != nil {
		return err
	}
	rows, err := db.Query(`SELECT address, updround, data FROM onlineaccounts`)
	if err != nil {
		return err
	}
	defer rows.Close()

	count := 0
	var highest int64
	for rows.Next() {
		var addr, data []byte
		var updround int64
		if err := rows.Scan(&addr, &updround, &data); err != nil {
			return err
		}
		if len(data) == 0 {
			continue
		}
		name := fmt.Sprintf("%s_%d", hex.EncodeToString(addr), updround)
		if err := writeBlob(dir, name, data); err != nil {
			return err
		}
		if updround > highest {
			highest = updround
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	fmt.Printf("  baseonlineaccountdata: %d rows (highest updround %d)\n", count, highest)
	m := blobMeta{
		Type:          "baseonlineaccountdata",
		SourceVersion: ver, SourcePrefix: prefix, SourceDB: src,
		CapturedAtUTC: now, RowCount: count,
		Notes: "Basename: <addrhex>_<updround>. Multiple rows per address are normal — onlineaccounts tracks history.",
	}
	if count > 0 {
		m.HighestRound = &highest
	}
	return writeMeta(dir, m)
}

// dumpResources walks `resources(addrid, aidx, ctype, data)` joined with
// `accountbase` so the output uses addresses (not rowids) as keys.
//
// ctype may be missing on very old DBs that haven't run the
// `ALTER TABLE resources ADD COLUMN ctype INTEGER NOT NULL DEFAULT -1`
// migration (see `../go-algorand/ledger/store/trackerdb/sqlitedriver/schema.go`
// line ~970). We refuse to dump in that case so a downstream encoder
// task doesn't silently key fixtures by a stale `-1` sentinel.
func dumpResources(db *sql.DB, outputDir, ver, prefix, src, now string) error {
	dir := filepath.Join(outputDir, "resourcesdata")
	if err := resetTypeDir(dir); err != nil {
		return err
	}

	if !hasColumn(db, "resources", "ctype") {
		return errors.New("resources table missing `ctype` column; run a recent go-algorand binary that applies the resources-ctype migration before capturing")
	}

	rows, err := db.Query(`
		SELECT a.address, r.aidx, r.ctype, r.data
		FROM resources r
		JOIN accountbase a ON a.rowid = r.addrid`)
	if err != nil {
		return err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var addr, data []byte
		var aidx, ctype int64
		if err := rows.Scan(&addr, &aidx, &ctype, &data); err != nil {
			return err
		}
		if len(data) == 0 {
			continue
		}
		name := fmt.Sprintf("%s_%d_%d", hex.EncodeToString(addr), aidx, ctype)
		if err := writeBlob(dir, name, data); err != nil {
			return err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	fmt.Printf("  resourcesdata: %d rows\n", count)
	return writeMeta(dir, blobMeta{
		Type:          "resourcesdata",
		SourceVersion: ver, SourcePrefix: prefix, SourceDB: src,
		CapturedAtUTC: now, RowCount: count,
		Notes: "Basename: <addrhex>_<aidx>_<ctype>. ctype 0=Asset, 1=App per go-algorand basics/teal.",
	})
}

// dumpOnlineRoundParams walks `onlineroundparamstail(rnd, data)`.
func dumpOnlineRoundParams(db *sql.DB, outputDir, ver, prefix, src, now string) error {
	dir := filepath.Join(outputDir, "onlineroundparams")
	return dumpRoundKeyed(db, dir, ver, prefix, src, now,
		"onlineroundparams",
		`SELECT rnd, data FROM onlineroundparamstail`,
		"Basename: <round>. One row per round in the rolling param window.")
}

// dumpTxTail walks `txtail(rnd, data)`.
func dumpTxTail(db *sql.DB, outputDir, ver, prefix, src, now string) error {
	dir := filepath.Join(outputDir, "txtailround")
	return dumpRoundKeyed(db, dir, ver, prefix, src, now,
		"txtailround",
		`SELECT rnd, data FROM txtail`,
		"Basename: <round>. msgp-encoded TxTailRound per round.")
}

// dumpStateProofVerification walks `stateproofverification(lastattestedround, verificationcontext)`.
//
// State-proof rows only exist on networks that have actually produced
// state proofs — a fresh localnet won't have any. We tolerate an
// empty table and record the fact in `_meta.json` so a downstream
// encoder test can skip gracefully.
func dumpStateProofVerification(db *sql.DB, outputDir, ver, prefix, src, now string) error {
	dir := filepath.Join(outputDir, "stateproof")
	return dumpRoundKeyed(db, dir, ver, prefix, src, now,
		"stateproof",
		`SELECT lastattestedround, verificationcontext FROM stateproofverification`,
		"Basename: <lastattestedround>. May be empty on networks that haven't produced state proofs.")
}

// dumpRoundKeyed is the shared `SELECT rnd, blob FROM ...` walker used
// by the four `<round>.canonical.hex` types.
func dumpRoundKeyed(db *sql.DB, dir, ver, prefix, src, now, typ, query, notes string) error {
	if err := resetTypeDir(dir); err != nil {
		return err
	}
	rows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	count := 0
	var rounds []int64
	for rows.Next() {
		var rnd int64
		var data []byte
		if err := rows.Scan(&rnd, &data); err != nil {
			return err
		}
		if len(data) == 0 {
			continue
		}
		if err := writeBlob(dir, strconv.FormatInt(rnd, 10), data); err != nil {
			return err
		}
		rounds = append(rounds, rnd)
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}

	m := blobMeta{
		Type:          typ,
		SourceVersion: ver, SourcePrefix: prefix, SourceDB: src,
		CapturedAtUTC: now, RowCount: count, Notes: notes,
	}
	if count > 0 {
		sort.Slice(rounds, func(i, j int) bool { return rounds[i] < rounds[j] })
		highest := rounds[len(rounds)-1]
		m.HighestRound = &highest
	}
	fmt.Printf("  %s: %d rows\n", typ, count)
	return writeMeta(dir, m)
}

// hasColumn returns whether `table` carries a `column` named exactly
// `col`. Used to gate migration-dependent dumps so the tool returns a
// clear error instead of a SQL "no such column" on stale DBs.
func hasColumn(db *sql.DB, table, col string) bool {
	row := db.QueryRow(`SELECT 1 FROM pragma_table_info(?) WHERE name = ?`, table, col)
	var x int
	if err := row.Scan(&x); err != nil {
		return false
	}
	return x == 1
}
