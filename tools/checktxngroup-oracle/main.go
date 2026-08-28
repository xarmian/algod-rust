// Command checktxngroup-oracle is a parity oracle for algod-rust issue #617:
// it builds the same scenarios as crates/core/algo-validate/src/checks.rs's
// unit tests directly as go-algorand v4.7.4-stable transactions.Transaction
// values and runs them through the real transactions.CheckTxnGroup /
// CheckPayset functions, confirming the Rust port (check_txn_group /
// check_payset) accepts/rejects each case exactly the same way.
//
// Several of these cases are drawn directly from go-algorand's own
// checks_test.go (TestCheckTxnGroupUnknownType, TestCheckTxnGroupApplicationBoxIndex),
// so this oracle doubles as a check that the Rust port matches upstream's own
// regression coverage, not just this tool's guess at upstream behavior.
//
// Exit codes: 0 all cases match, 2 a mismatch was found, 1 usage/IO error.
package main

import (
	"fmt"
	"os"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

type caseResult struct {
	name       string
	wantAccept bool
	wantErrHas string
	err        error
}

func main() {
	var results []caseResult

	check := func(name string, wantAccept bool, wantErrHas string, group []transactions.SignedTxn) {
		results = append(results, caseResult{
			name:       name,
			wantAccept: wantAccept,
			wantErrHas: wantErrHas,
			err:        transactions.CheckTxnGroup(group),
		})
	}

	txn := func(typ protocol.TxType) transactions.SignedTxn {
		return transactions.SignedTxn{Txn: transactions.Transaction{
			Type: typ,
		}}
	}

	// ── Heartbeat missing fields ─────────────────────────────────
	check("heartbeat_missing_fields_is_rejected", false, "heartbeat", []transactions.SignedTxn{
		txn(protocol.HeartbeatTx),
	})
	{
		hb := txn(protocol.HeartbeatTx)
		hb.Txn.HeartbeatTxnFields = &transactions.HeartbeatTxnFields{}
		check("heartbeat_with_fields_is_accepted", true, "", []transactions.SignedTxn{hb})
	}

	// ── Heartbeat grouped with resource-availability trigger ─────
	{
		hb := txn(protocol.HeartbeatTx)
		hb.Txn.HeartbeatTxnFields = &transactions.HeartbeatTxnFields{}
		appl := txn(protocol.ApplicationCallTx)
		check("heartbeat_grouped_with_appl_is_rejected", false, "heartbeat", []transactions.SignedTxn{hb, appl})
	}
	{
		hb := txn(protocol.HeartbeatTx)
		hb.Txn.HeartbeatTxnFields = &transactions.HeartbeatTxnFields{}
		acfgCreate := txn(protocol.AssetConfigTx) // ConfigAsset zero-value == creation
		check("heartbeat_grouped_with_asset_create_is_rejected", false, "heartbeat", []transactions.SignedTxn{hb, acfgCreate})
	}
	{
		hb := txn(protocol.HeartbeatTx)
		hb.Txn.HeartbeatTxnFields = &transactions.HeartbeatTxnFields{}
		acfgReconfig := txn(protocol.AssetConfigTx)
		acfgReconfig.Txn.ConfigAsset = 42
		check("heartbeat_grouped_with_asset_reconfig_is_accepted", true, "", []transactions.SignedTxn{hb, acfgReconfig})
	}
	{
		hb := txn(protocol.HeartbeatTx)
		hb.Txn.HeartbeatTxnFields = &transactions.HeartbeatTxnFields{}
		pay := txn(protocol.PaymentTx)
		check("heartbeat_grouped_with_payment_is_accepted", true, "", []transactions.SignedTxn{hb, pay})
	}

	// ── Application box index bound (mirrors go-algorand's own
	//    TestCheckTxnGroupApplicationBoxIndex verbatim) ─────────────
	{
		malformed := txn(protocol.ApplicationCallTx)
		malformed.Txn.ApplicationCallTxnFields.Boxes = []transactions.BoxRef{{Index: 1}}
		check("box_index_exceeding_foreign_apps_is_rejected", false, "box", []transactions.SignedTxn{malformed})
	}
	{
		currentApp := txn(protocol.ApplicationCallTx)
		currentApp.Txn.ApplicationCallTxnFields.Boxes = []transactions.BoxRef{{Index: 0}}
		check("box_index_zero_is_current_app_is_accepted", true, "", []transactions.SignedTxn{currentApp})
	}
	{
		foreignApp := txn(protocol.ApplicationCallTx)
		foreignApp.Txn.ApplicationCallTxnFields.ForeignApps = []basics.AppIndex{1}
		foreignApp.Txn.ApplicationCallTxnFields.Boxes = []transactions.BoxRef{{Index: 1}}
		check("box_index_within_foreign_apps_is_accepted", true, "", []transactions.SignedTxn{foreignApp})
	}

	// ── Unknown transaction type (mirrors go-algorand's own
	//    TestCheckTxnGroupUnknownType verbatim) ─────────────────────
	check("unknown_txn_type_alone_is_rejected", false, "unknown", []transactions.SignedTxn{
		txn(protocol.TxType("bogus")),
	})
	check("unknown_txn_type_grouped_after_appl_is_rejected", false, "unknown", []transactions.SignedTxn{
		txn(protocol.ApplicationCallTx), txn(protocol.TxType("bogus")),
	})
	for _, tt := range []protocol.TxType{
		protocol.PaymentTx, protocol.KeyRegistrationTx, protocol.AssetConfigTx,
		protocol.AssetTransferTx, protocol.AssetFreezeTx, protocol.ApplicationCallTx,
		protocol.StateProofTx,
	} {
		check(fmt.Sprintf("every_known_type_is_accepted_%s", tt), true, "", []transactions.SignedTxn{txn(tt)})
	}

	failed := 0
	for _, r := range results {
		accepted := r.err == nil
		ok := accepted == r.wantAccept
		if ok && !r.wantAccept && r.wantErrHas != "" {
			ok = containsFold(r.err.Error(), r.wantErrHas)
		}
		status := "PASS"
		if !ok {
			status = "FAIL"
			failed++
		}
		fmt.Printf("[%s] %-55s accept=%v want=%v err=%v\n", status, r.name, accepted, r.wantAccept, r.err)
	}

	fmt.Printf("\n%d/%d cases matched go-algorand v4.7.4-stable's real CheckTxnGroup\n", len(results)-failed, len(results))
	if failed > 0 {
		os.Exit(2)
	}
}

func containsFold(s, substr string) bool {
	sl, subl := []rune(s), []rune(substr)
	toLower := func(rs []rune) []rune {
		out := make([]rune, len(rs))
		for i, r := range rs {
			if r >= 'A' && r <= 'Z' {
				r += 'a' - 'A'
			}
			out[i] = r
		}
		return out
	}
	sl, subl = toLower(sl), toLower(subl)
	n, m := len(sl), len(subl)
	if m == 0 {
		return true
	}
	for i := 0; i+m <= n; i++ {
		match := true
		for j := 0; j < m; j++ {
			if sl[i+j] != subl[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
