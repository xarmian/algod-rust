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

// Parity oracle for algod-rust issue #2470: go-algorand v5.0.5-stable's
// HTTP status and response body for POST /v2/transactions/simulate requests
// that fail its request validation (Handlers.SimulateTransaction in
// daemon/algod/api/server/v2/handlers.go, then Simulator.Simulate in
// ledger/simulation/simulator.go).
//
// It is staged into daemon/algod/api/server/v2/test of a go-algorand
// checkout (package test, so it can use that package's mock node backed by
// a real ledger and simulator) and writes one JSON object per case to
// $ORACLE_OUT: the request body (hex, optionally padded with spaces to
// pad_to bytes), the `format` query value ("" = absent), and go's status
// and exact response body. Every transaction is signed with a fixed key,
// so the output is deterministic.
package test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/simulation"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

type simulateRequestTextCase struct {
	Name     string `json:"name"`
	Format   string `json:"format"`
	BodyHex  string `json:"body_hex"`
	PadTo    int    `json:"pad_to,omitempty"`
	Status   int    `json:"status"`
	Response string `json:"response"`
}

func oracleSignedPay(amount uint64) transactions.SignedTxn {
	var seed crypto.Seed
	seed[0] = 0x47
	secrets := crypto.GenerateSignatureSecrets(seed)
	var receiver basics.Address
	receiver[0] = 0x24
	var gh crypto.Digest
	gh[0] = 0xAB
	txn := transactions.Transaction{
		Type: protocol.PaymentTx,
		Header: transactions.Header{
			Sender:      basics.Address(secrets.SignatureVerifier),
			Fee:         basics.MicroAlgos{Raw: 1000},
			FirstValid:  1,
			LastValid:   1000,
			GenesisHash: gh,
		},
		PaymentTxnFields: transactions.PaymentTxnFields{
			Receiver: receiver,
			Amount:   basics.MicroAlgos{Raw: amount},
		},
	}
	return txn.Sign(secrets)
}

func oracleGroup(amounts ...uint64) v2.PreEncodedSimulateRequestTransactionGroup {
	var g v2.PreEncodedSimulateRequestTransactionGroup
	for _, a := range amounts {
		g.Txns = append(g.Txns, oracleSignedPay(a))
	}
	return g
}

func TestAlgodRustSimulateRequestTextOracle(t *testing.T) {
	out := os.Getenv("ORACLE_OUT")
	if out == "" {
		t.Skip("ORACLE_OUT not set")
	}

	mockLedger, _, _, _, releasefunc := testingenv(t, 1, 1, true)
	defer releasefunc()
	mockNode := makeMockNode(mockLedger, t.Name(), nil, cannedStatusReportGolden, false)
	handler := v2.Handlers{Node: mockNode, Log: logging.Base(), Shutdown: make(chan struct{})}

	seventeen := make([]uint64, 17)
	for i := range seventeen {
		seventeen[i] = uint64(i + 1)
	}
	jsonReq := func(r v2.PreEncodedSimulateRequest) []byte { return protocol.EncodeJSON(&r) }
	msgpReq := func(r v2.PreEncodedSimulateRequest) []byte { return protocol.EncodeReflect(&r) }

	cases := []simulateRequestTextCase{
		{Name: "json_empty_txn_groups", BodyHex: hex.EncodeToString([]byte(`{"txn-groups":[]}`))},
		{Name: "json_no_txn_groups_key", BodyHex: hex.EncodeToString([]byte(`{}`))},
		{Name: "json_empty_txn_groups_bad_format", Format: "xml", BodyHex: hex.EncodeToString([]byte(`{"txn-groups":[]}`))},
		{Name: "json_group_with_no_txns", BodyHex: hex.EncodeToString([]byte(`{"txn-groups":[{"txns":[]}]}`))},
		{Name: "json_group_without_txns_key", BodyHex: hex.EncodeToString([]byte(`{"txn-groups":[{}]}`))},
		{Name: "json_group_with_no_txns_bad_format", Format: "xml", BodyHex: hex.EncodeToString([]byte(`{"txn-groups":[{"txns":[]}]}`))},
		{Name: "json_second_group_with_no_txns", BodyHex: hex.EncodeToString(jsonReq(v2.PreEncodedSimulateRequest{
			TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{oracleGroup(1), {}},
		}))},
		{Name: "json_group_over_max_size", BodyHex: hex.EncodeToString(jsonReq(v2.PreEncodedSimulateRequest{
			TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{oracleGroup(seventeen...)},
		}))},
		{Name: "json_two_groups", BodyHex: hex.EncodeToString(jsonReq(v2.PreEncodedSimulateRequest{
			TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{oracleGroup(1), oracleGroup(2)},
		}))},
		{Name: "json_two_groups_bad_format", Format: "xml", BodyHex: hex.EncodeToString(jsonReq(v2.PreEncodedSimulateRequest{
			TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{oracleGroup(1), oracleGroup(2)},
		}))},
		{Name: "json_fix_signers_without_allow_empty_signatures", BodyHex: hex.EncodeToString(jsonReq(v2.PreEncodedSimulateRequest{
			TxnGroups:  []v2.PreEncodedSimulateRequestTransactionGroup{oracleGroup(1)},
			FixSigners: true,
		}))},
		{Name: "json_fix_signers_without_allow_empty_signatures_no_groups", BodyHex: hex.EncodeToString([]byte(`{"txn-groups":[],"fix-signers":true}`))},
		{Name: "json_exec_trace_without_developer_api", BodyHex: hex.EncodeToString(jsonReq(v2.PreEncodedSimulateRequest{
			TxnGroups:       []v2.PreEncodedSimulateRequestTransactionGroup{oracleGroup(1)},
			ExecTraceConfig: simulation.ExecTraceConfig{Enable: true},
		}))},
		{Name: "msgpack_empty_request", BodyHex: hex.EncodeToString(msgpReq(v2.PreEncodedSimulateRequest{}))},
		{Name: "msgpack_group_with_no_txns", BodyHex: hex.EncodeToString(msgpReq(v2.PreEncodedSimulateRequest{
			TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{{}},
		}))},
		{Name: "msgpack_group_over_max_size", BodyHex: hex.EncodeToString(msgpReq(v2.PreEncodedSimulateRequest{
			TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{oracleGroup(seventeen...)},
		}))},
		{Name: "msgpack_two_groups", BodyHex: hex.EncodeToString(msgpReq(v2.PreEncodedSimulateRequest{
			TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{oracleGroup(1), oracleGroup(2)},
		}))},
		{Name: "body_over_max_simulate_bytes", BodyHex: hex.EncodeToString([]byte(`{"txn-groups":[]}`)), PadTo: v2.MaxSimulateBytes + 1},
		{Name: "body_over_max_simulate_bytes_bad_format", Format: "xml", BodyHex: hex.EncodeToString([]byte(`{"txn-groups":[]}`)), PadTo: v2.MaxSimulateBytes + 1},
	}

	var lines bytes.Buffer
	for _, tc := range cases {
		body, err := hex.DecodeString(tc.BodyHex)
		require.NoError(t, err)
		if tc.PadTo > len(body) {
			body = append(body, bytes.Repeat([]byte{' '}, tc.PadTo-len(body))...)
		}
		req := httptest.NewRequest("POST", "/v2/transactions/simulate", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(req, rec)
		var params model.SimulateTransactionParams
		if tc.Format != "" {
			f := model.SimulateTransactionParamsFormat(tc.Format)
			params.Format = &f
		}
		require.NoError(t, handler.SimulateTransaction(c, params), tc.Name)
		tc.Status = rec.Code
		tc.Response = rec.Body.String()
		line, err := json.Marshal(tc)
		require.NoError(t, err)
		lines.Write(line)
		lines.WriteByte('\n')
	}
	require.NoError(t, os.WriteFile(out, lines.Bytes(), 0o644))
}
