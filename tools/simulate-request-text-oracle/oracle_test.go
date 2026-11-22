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

// Parity oracle for algod-rust issue #2470: go-algorand v5.1.1-stable's
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
//
// Issue #2477 adds hundreds of malformed bodies (go answers its go-codec
// JSON decoder's own error text, with byte positions) and
// TestAlgodRustSimulateRequestSchema, which writes the go-codec schema of
// the request type that algo-rest-api decodes these bodies with
// ($SCHEMA_OUT, crates/node/algo-rest-api/src/simulate_request_schema.rs).
package test

import (
	"bytes"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/algorand/go-codec/codec"
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

	dropIfSimulated bool
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

	cases = append(cases, malformedSimulateBodies(msgpReq)...)

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
		if tc.dropIfSimulated && tc.Status == 200 {
			// decoded and simulated: not a request-validation text
			continue
		}
		line, err := json.Marshal(tc)
		require.NoError(t, err)
		lines.Write(line)
		lines.WriteByte('\n')
	}
	require.NoError(t, os.WriteFile(out, lines.Bytes(), 0o644))
}

// malformedSimulateBodies are bodies go's decode of PreEncodedSimulateRequest
// rejects, or accepts only through go-codec's leniency (issue #2477): go
// answers its JSON decoder's own error text, positions included, for every
// body its msgpack decode rejects. Bodies that decode are built with two
// groups so that they stop at the simulator's group-count check.
func malformedSimulateBodies(msgpReq func(v2.PreEncodedSimulateRequest) []byte) []simulateRequestTextCase {
	var cases []simulateRequestTextCase
	add := func(name string, body []byte) {
		cases = append(cases, simulateRequestTextCase{Name: name, BodyHex: hex.EncodeToString(body), dropIfSimulated: true})
	}
	// one real transaction, then a second group holding an empty SignedTxn
	var compact bytes.Buffer
	if err := json.Compact(&compact, protocol.EncodeJSON(oracleSignedPay(1))); err != nil {
		panic(err)
	}
	twoGroups := func(stxnJSON string) []byte {
		return []byte(`{"txn-groups":[{"txns":[` + stxnJSON + `]},{"txns":[{}]}]}`)
	}
	base := twoGroups(compact.String())
	zeroAddr := basics.Address{}.String()

	for i, s := range []string{
		``, ` `, `not json`, `null`, `nul`, `nulx`, `true`, `5`, `"x"`, `[]`, `[1]`, `[[]]`, `[null]`,
		`[[],1,true,false,0,{},1,2,3]`, `{`, `{ `, `{"`, `{"txn-groups"`, `{"txn-groups":`,
		`{"txn-groups":5}`, `{"txn-groups":"x"}`, `{"txn-groups":true}`, `{"txn-groups":{}}`,
		`{"txn-groups":{"a":1}}`, `{"txn-groups":[5]}`, `{"txn-groups":[[]]}`, `{"txn-groups":[[1]]}`,
		`{"txn-groups":[{"txns":5}]}`, `{"txn-groups":[{"txns":"x"}]}`, `{"txn-groups":[{"txns":[5]}]}`,
		`{"txn-groups":[{"txns":[{"txn":5}]}]}`, `{"txn-groups":[{"txns":[[1,2,3,4,5,6,7]]}]}`,
		`{"txn-groups":[{"foo":1}]}`, `{"txn-groups":[],"foo":1}`, `{"foo":1,"txn-groups":5}`,
		`{"txn-groups":[],}`, `{,}`, `{"a" 1}`, `{"":1}`, `{1:2}`, `{"txn-groups":[]}xyz`,
		`{"txn-groups":[]} {"round":5}`, `{"txn-groups":[] "round":5}`, `{"txn-groups":[1,`,
		`{"round":-1}`, `{"round":1.5}`, `{"round":"7"}`, `{"round":1e3}`, `{"round":true}`, `{"round":"x"}`,
		`{"round":18446744073709551616}`, `{"round":1e20}`, `{"round":""}`, `{"round":[]}`,
		`{"allow-empty-signatures":1}`, `{"allow-empty-signatures":"true"}`, `{"allow-empty-signatures":tru}`,
		`{"allow-empty-signatures":fals}`, `{"allow-more-logging":null}`, `{"allow-unnamed-resources":nul}`,
		`{"extra-opcode-budget":-5}`, `{"extra-opcode-budget":99999999999999999999}`,
		`{"extra-opcode-budget":-9223372036854775809}`, `{"extra-opcode-budget":"x"}`, `{"extra-opcode-budget":1.25}`,
		`{"exec-trace-config":[]}`, `{"exec-trace-config":5}`, `{"exec-trace-config":{"enable":2}}`,
		`{"exec-trace-config":{"foo":true}}`, `{"exec-trace-config":[true,true,true,true,true]}`,
		`{"fix-signers":null}`, `{"fix-signers":"x"}`, `{"txn-groups":[],"round":"7"}`,
	} {
		add(fmt.Sprintf("json_top_%02d", i), []byte(s))
	}

	for i, s := range []string{
		`{"sig":"!!"}`, `{"sig":"AAAA"}`, `{"sig":""}`, `{"sig":5}`, `{"sig":[1,2,3]}`, `{"sig":[256]}`,
		`{"sig":[-1]}`, `{"sig":[` + strings.Repeat("1,", 64) + `1]}`, `{"sig":{}}`, `{"sig":{"a":1}}`,
		`{"sig":true}`, `{"sig":"QQ="}`, `{"sig":"QQ==x"}`, `{"sig":"` + strings.Repeat("A", 100) + `"}`,
		`{"sgnr":"x"}`, `{"sgnr":""}`, `{"sgnr":5}`, `{"sgnr":null}`, `{"sgnr":[1]}`,
		`{"sgnr":"` + strings.Repeat("A", 58) + `"}`,
		`{"sgnr":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"}`,
		`{"sgnr":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay5hfkq"}`,
		`{"sgnr":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQA"}`,
		`{"sgnr":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKR"}`,
		`{"sgnr":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFK"}`,
		`{"sgnr":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ=="}`,
		`{"sgnr":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nY5HFKQ"}`,
		`{"msig":{"thr":256}}`, `{"msig":{"v":-1}}`, `{"msig":{"subsig":"x"}}`, `{"msig":{"subsig":[{"pk":"!!"}]}}`,
		`{"msig":{"subsig":[5]}}`, `{"msig":{"subsig":[{"s":[1,2]}]}}`, `{"msig":5}`, `{"msig":{"foo":1}}`,
		`{"lsig":{"l":"!"}}`, `{"lsig":{"arg":"x"}}`, `{"lsig":{"arg":["!"]}}`, `{"lsig":{"arg":[[1,2]]}}`,
		`{"lsig":{"arg":[[1,256]]}}`, `{"lsig":{"lmsig":{"thr":"x"}}}`, `{"lsig":{"sig":"!!"}}`, `{"lsig":[]}`,
		`{"pqsig":5}`, `{"pqsig":{"foo":1}}`, `{"txn":5}`, `{"txn":"x"}`, `{"txn":[]}`, `{"txn":[1]}`,
		`{"txn":null}`, `{"txn":{"foo":1}}`, `[]`, `[1,2,3,4,5,6,7]`, `{"foo":1}`, `{"sig":"AAAA","foo":1}`,
		`{"sig":"\u12"}`, `{"txn":{"type":"\u12"}}`, `{"txn":{"type":"\ud800"}}`, `{"txn":{"type":"\ud800A"}}`,
		`{"txn":{"type":"\x"}}`, `{"txn":{"type":"\uZZZZ"}}`, `{"txn":{"type":"pa\"y"}}`, `{"txn":{"type":"pay`,
		`{"txn":{"type":"é"}}`, `{"txn":{"type":"😀"}}`, `{"txn":{"type":"a\/b\'c"}}`,
		`{"sgnr":"` + zeroAddr + `"}`, `{"sgnr":"` + zeroAddr[:57] + `R"}`, `{"sgnr":"B` + zeroAddr[1:] + `"}`,
		`{"txn":{"snd":"` + zeroAddr + `","rcv":"` + zeroAddr + `","type":"pay","amt":"5","fv":1e1}}`,
		`{"sgnr":"` + zeroAddr[:56] + `\n` + zeroAddr[56:] + `"}`, `{"sgnr":"` + strings.ToLower(zeroAddr) + `"}`,
		`{"sgnr":"` + zeroAddr + `=="}`, `{"sgnr":"` + zeroAddr[:50] + `"}`,
	} {
		add(fmt.Sprintf("json_stxn_%02d", i), twoGroups(s))
	}

	for i, s := range []string{
		`{"type":5}`, `{"type":true}`, `{"type":null}`, `{"type":[]}`, `{"fee":-1}`, `{"fee":"12"}`, `{"fee":1.5}`,
		`{"fee":1e3}`, `{"fee":"abc"}`, `{"fee":18446744073709551616}`, `{"fee":true}`, `{"fee":[]}`, `{"fee":"1_000"}`,
		`{"fee":0x10}`, `{"fee":"0x10"}`, `{"fee":"Inf"}`, `{"fee":1e400}`, `{"fee":-0}`, `{"fee":""}`, `{"fee":01}`,
		`{"fv":[]}`, `{"amt":{}}`, `{"note":"!!"}`, `{"note":"QQ="}`, `{"note":[1,256]}`, `{"note":5}`,
		`{"note":true}`, `{"note":{}}`, `{"note":{"a":1}}`, `{"note":"QQ\n=="}`, `{"snd":"x"}`, `{"rcv":5}`,
		`{"close":true}`, `{"gh":"x"}`, `{"gh":"AAAA"}`, `{"grp":[1,2]}`, `{"lx":"!!"}`, `{"gen":5}`,
		`{"apid":-1}`, `{"apan":"x"}`, `{"apan":256}`, `{"apaa":"x"}`, `{"apaa":["!"]}`, `{"apat":"x"}`,
		`{"apat":["x"]}`, `{"apat":[5]}`, `{"apfa":"x"}`, `{"apfa":["x"]}`, `{"apfa":[-1]}`, `{"apas":{}}`,
		`{"apas":{"1":2}}`, `{"apbx":[{"i":"x"}]}`, `{"apbx":[{"n":"!"}]}`, `{"apbx":[{"z":1}]}`, `{"apbx":"x"}`,
		`{"apgs":{"nui":"x"}}`, `{"apls":{"nbs":-1}}`, `{"apep":4294967296}`, `{"apep":4294967295}`,
		`{"apap":"!!"}`, `{"apsu":[1,2]}`, `{"al":[{"d":"x"}]}`, `{"al":[{"h":{"d":256}}]}`, `{"al":"x"}`,
		`{"votekey":"!!"}`, `{"votefst":-1}`, `{"nonpart":1}`, `{"sprfkey":"x"}`, `{"selkey":[1]}`,
		`{"apar":{"t":"x"}}`, `{"apar":{"dc":4294967296}}`, `{"apar":{"am":"!!"}}`, `{"apar":{"m":"x"}}`,
		`{"apar":{"an":5}}`, `{"caid":"x"}`, `{"xaid":"x"}`, `{"aamt":-1}`, `{"asnd":"x"}`, `{"afrz":"x"}`,
		`{"sp":{"r":{"x":{}}}}`, `{"sp":{"r":{"1":5}}}`, `{"sp":{"r":5}}`, `{"sp":{"r":[1]}}`, `{"sp":{"r":{"1":{"p":{"w":"x"}}}}}`,
		`{"sp":{"P":{"td":256}}}`, `{"sp":{"P":{"hsh":{"t":65536}}}}`, `{"sp":{"pr":"x"}}`, `{"sp":5}`,
		`{"sptype":-1}`, `{"spmsg":{"b":"!!"}}`, `{"spmsg":{"v":-1}}`, `{"hb":{"a":"x"}}`, `{"hb":{"prf":{"s":"!!"}}}`,
		`{"hb":{"kd":-1}}`, `{"hb":5}`, `{"rekey":"x"}`, `{"lv":"1"}`,
	} {
		add(fmt.Sprintf("json_txn_%03d", i), twoGroups(`{"txn":`+s+`}`))
	}

	// every fourth prefix of a real body, and the body with one byte replaced
	for n := 0; n < len(base); n += 4 {
		add(fmt.Sprintf("json_truncated_%04d", n), base[:n])
	}
	for n := 1; n < len(base); n += 17 {
		for _, c := range []byte{'x', '"', '}', '\\'} {
			b := append([]byte(nil), base...)
			b[n] = c
			add(fmt.Sprintf("json_replaced_%04d_%02x", n, c), b)
		}
	}

	msgpTwo := msgpReq(v2.PreEncodedSimulateRequest{
		TxnGroups: []v2.PreEncodedSimulateRequestTransactionGroup{oracleGroup(1), oracleGroup(2)},
	})
	groupsKey := append([]byte{0x81, 0xaa}, []byte("txn-groups")...)
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	for i, b := range [][]byte{
		{0x80}, {0xc0}, {0x90}, {0x91, 0x90}, {0x81, 0xa1, 'x', 0x01}, {' ', 0x81, 0xa1, 'x', 0x01},
		{'\n', 0x81}, {0x81}, {0x81, 0xaa}, {0xff}, {0xc1}, {0x00}, {0x7b}, {0x5b}, {0x6e},
		groupsKey,
		cat(groupsKey, []byte{0x91, 0x81, 0xa4, 't', 'x', 'n', 's', 0x91, 0x81, 0xa3, 'f', 'o', 'o', 0x01}),
		cat(groupsKey, []byte{0x05}),
		msgpTwo[:len(msgpTwo)/2], msgpTwo[:len(msgpTwo)-1], cat(msgpTwo, []byte("x")),
	} {
		add(fmt.Sprintf("msgpack_malformed_%02d", i), b)
	}
	return append(cases, decodeEdgeBodies()...)
}

// decodeEdgeBodies are the go-codec decode edges of issue #2494: a struct
// sent as a msgpack array (or a slice as a map) at every level, a nested
// reserved 0xc1 byte, struct keys sent as bin, and string fields holding
// bytes that are not UTF-8, in msgpack and in JSON. Bodies that decode
// carry two groups (they stop at the simulator's group-count check); the
// `one_` bodies carry one group and show what go makes of the decoded value.
func decodeEdgeBodies() []simulateRequestTextCase {
	var cases []simulateRequestTextCase
	add := func(name string, body []byte) {
		cases = append(cases, simulateRequestTextCase{Name: name, BodyHex: hex.EncodeToString(body), dropIfSimulated: true})
	}
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	str := func(s string) []byte {
		if len(s) < 32 {
			return cat([]byte{0xa0 | byte(len(s))}, []byte(s))
		}
		return cat([]byte{0xd9, byte(len(s))}, []byte(s))
	}
	bin := func(b []byte) []byte { return cat([]byte{0xc4, byte(len(b))}, b) }
	mapN := func(n int) []byte { return []byte{0x80 | byte(n)} }
	arrN := func(n int) []byte { return []byte{0x90 | byte(n)} }
	arr := func(items ...[]byte) []byte { return cat(arrN(len(items)), cat(items...)) }
	nilB := []byte{0xc0}
	trueB := []byte{0xc3}
	falseB := []byte{0xc2}
	u := func(v uint64) []byte { return protocol.EncodeReflect(v) }

	st := oracleSignedPay(1)
	stx := protocol.EncodeReflect(st)
	stx2 := protocol.EncodeReflect(oracleSignedPay(2))
	txnMap := protocol.EncodeReflect(st.Txn)
	sig := bin(st.Sig[:])
	snd := bin(st.Txn.Sender[:])
	grp := func(txns ...[]byte) []byte { return cat(mapN(1), str("txns"), arr(txns...)) }
	req := func(groups ...[]byte) []byte { return cat(mapN(1), str("txn-groups"), arr(groups...)) }
	two := func(g1 []byte) []byte { return req(g1, grp(stx2)) }
	// one signed transaction from (key, value) pairs, keys in the given order
	stxnOf := func(kv ...[]byte) []byte { return cat(mapN(len(kv)/2), cat(kv...)) }
	txnWith := func(kv ...[]byte) []byte {
		return stxnOf(str("sig"), sig, str("txn"), cat(mapN(len(kv)/2), cat(kv...)))
	}
	pay := func(kv ...[]byte) []byte {
		base := [][]byte{str("type"), str("pay"), str("snd"), snd, str("fee"), u(1000), str("fv"), u(1), str("lv"), u(1000)}
		return txnWith(append(base, kv...)...)
	}
	appl := func(kv ...[]byte) []byte {
		base := [][]byte{str("type"), str("appl"), str("snd"), snd, str("fee"), u(1000), str("fv"), u(1), str("lv"), u(1000)}
		return txnWith(append(base, kv...)...)
	}
	acfg := func(kv ...[]byte) []byte {
		base := [][]byte{str("type"), str("acfg"), str("snd"), snd, str("fee"), u(1000), str("fv"), u(1), str("lv"), u(1000)}
		return txnWith(append(base, kv...)...)
	}
	topWith := func(kv ...[]byte) []byte {
		return cat(mapN(1+len(kv)/2), str("txn-groups"), arr(grp(stx), grp(stx2)), cat(kv...))
	}

	// a struct from an array, a slice from a map
	for i, b := range [][]byte{
		two(arr(arr(stx))),
		two(arr(nilB)),
		two(arr()),
		two(arr(arr(stx), u(1))),
		two(arr(arr(stx), nilB)),
		two(arr(cat(mapN(1), stx, stx2))),
		two(nilB),
		req(nilB, grp(stx2)),
		two(grp(arr(sig, nilB, nilB, nilB, txnMap))),
		two(grp(arr(sig, nilB, nilB, nilB, txnMap, bin(make([]byte, 32))))),
		two(grp(arr(sig, nilB, nilB, nilB, txnMap, nilB, nilB))),
		two(grp(arr(sig))),
		two(grp(arr())),
		two(grp(arr(u(5)))),
		two(grp(txnWith(str("type"), str("pay")), arr(sig, nilB, nilB, nilB, txnMap))),
		two(grp(stxnOf(str("sig"), sig, str("txn"), arr(str("pay"), snd, u(1000), u(1), u(1000))))),
		two(grp(stxnOf(str("sig"), sig, str("txn"), arr(str("pay"), u(5))))),
		two(grp(stxnOf(str("sig"), sig, str("txn"), arr(str("pay"), snd, arr(u(1000)))))),
		two(grp(stxnOf(str("txn"), txnMap, str("msig"), arr(u(1), u(1), arr(arr(bin(make([]byte, 32)))))))),
		two(grp(stxnOf(str("txn"), txnMap, str("msig"), arr(u(1), u(1), arr(arr(bin(make([]byte, 32)), bin(make([]byte, 64)), u(1))))))),
		two(grp(stxnOf(str("txn"), txnMap, str("lsig"), arr(bin([]byte{0x06, 0x81, 0x01}))))),
		two(grp(stxnOf(str("txn"), txnMap, str("lsig"), arr(bin([]byte{0x06, 0x81, 0x01}), nilB, nilB, nilB, nilB, arr(bin([]byte("a"))))))),
		two(grp(stxnOf(str("txn"), txnMap, str("pqsig"), arr(bin([]byte("ab")), u(1))))),
		two(grp(appl(str("apbx"), arr(arr(u(0), bin([]byte("x"))))))),
		two(grp(appl(str("apbx"), arr(arr(u(0), bin([]byte("x")), u(1)))))),
		two(grp(appl(str("al"), arr(arr(nilB, u(1)), arr(nilB, nilB, nilB, arr(u(1), u(2))))))),
		two(grp(appl(str("apls"), arr(u(1), u(2)), str("apgs"), arr(u(3))))),
		two(grp(appl(str("apaa"), cat(mapN(1), bin([]byte("a")), bin([]byte("b")))))),
		two(grp(appl(str("apas"), cat(mapN(1), u(1), u(2))))),
		two(grp(acfg(str("apar"), arr(u(1000), u(0), falseB, str("U"), str("Asset"))))),
		two(grp(acfg(str("apar"), arr(u(1000), u(0), falseB, str("U"), str("Asset"), nilB, nilB, nilB, nilB, nilB, nilB, nilB)))),
		two(grp(txnWith(str("type"), str("hb"), str("hb"), arr(snd, arr(bin(make([]byte, 64))), nilB, nilB, u(5), trueB)))),
		two(grp(txnWith(str("type"), str("stpf"), str("sp"), arr(bin([]byte("c")), u(1), arr(nilB, arr(u(1)), u(0))), str("spmsg"), arr(bin([]byte("b")))))),
		two(grp(txnWith(str("type"), str("stpf"), str("sp"), cat(mapN(1), str("r"), cat(mapN(1), u(1), arr(arr(nilB, u(2)), arr(nilB, u(3)))))))),
		cat(mapN(2), str("txn-groups"), arr(grp(stx), grp(stx2)), str("exec-trace-config"), arr(trueB)),
		cat(mapN(2), str("txn-groups"), arr(grp(stx), grp(stx2)), str("exec-trace-config"), arr(trueB, trueB, trueB, trueB, trueB)),
		cat(mapN(2), str("txn-groups"), arr(grp(stx)), str("exec-trace-config"), arr(trueB)),
		cat(mapN(2), str("txn-groups"), arr(grp(stx)), str("exec-trace-config"), arr(falseB, trueB)),
		arr(arr(arr(arr(stx)), arr(arr(stx2)))),
		arr(arr(arr(arr(arr(sig, nilB, nilB, nilB, txnMap))), grp(stx2)), u(5)),
		cat(mapN(1), str("txn-groups"), cat(mapN(1), grp(stx), grp(stx2))),
		cat(mapN(1), str("txn-groups"), cat(mapN(1), arr(arr(stx)), arr(arr(stx2)))),
		cat(mapN(1), str("txn-groups"), arr(cat(mapN(1), str("txns"), cat(mapN(1), stx, stx2)))),
		cat(mapN(1), str("txn-groups"), cat(mapN(1), grp(stx), nilB)),
		cat(mapN(1), str("txn-groups"), cat(mapN(1), nilB, grp(stx2))),
		cat(mapN(1), bin([]byte("txn-groups")), arr(grp(stx), grp(stx2))),
		cat(mapN(1), str("txn-groups"), arr(cat(mapN(1), bin([]byte("txns")), arr(stx)), grp(stx2))),
		two(grp(cat(mapN(2), bin([]byte("sig")), sig, bin([]byte("txn")), txnMap))),
		two(grp(txnWith(bin([]byte("type")), str("pay"), bin([]byte("fee")), u(5)))),
		cat(mapN(1), u(1), arr(grp(stx), grp(stx2))),
		cat(mapN(1), nilB, arr(grp(stx), grp(stx2))),
		cat(mapN(1), arr(), arr(grp(stx), grp(stx2))),
		cat(mapN(1), str(""), arr(grp(stx), grp(stx2))),
		topWith(str("round"), arr()),
		topWith(str("round"), cat(mapN(0))),
		topWith(str("fix-signers"), arr()),
		topWith(str("extra-opcode-budget"), arr(u(1))),
	} {
		add(fmt.Sprintf("msgpack_shape_%02d", i), b)
	}

	// the reserved 0xc1 byte nested in a body
	c1 := []byte{0xc1}
	for i, b := range [][]byte{
		cat(mapN(1), str("txn-groups"), c1),
		req(c1, grp(stx2)),
		two(cat(mapN(1), str("txns"), c1)),
		two(grp(c1)),
		two(grp(stx, c1)),
		two(grp(txnWith(str("type"), c1))),
		two(grp(txnWith(str("fee"), c1))),
		two(grp(stxnOf(str("sig"), c1, str("txn"), txnMap))),
		two(grp(stxnOf(str("txn"), c1))),
		two(grp(stxnOf(str("sgnr"), c1, str("txn"), txnMap))),
		two(grp(appl(str("apaa"), arr(c1)))),
		two(grp(appl(str("apas"), arr(c1)))),
		two(grp(appl(str("apbx"), arr(cat(mapN(1), str("n"), c1))))),
		two(grp(stxnOf(str("msig"), cat(mapN(1), str("thr"), c1), str("txn"), txnMap))),
		two(grp(stxnOf(str("sig"), arr(c1), str("txn"), txnMap))),
		two(grp(txnWith(str("note"), arr(u(1), c1)))),
		two(grp(cat(mapN(1), c1, u(1)))),
		cat(mapN(1), c1, arr(grp(stx), grp(stx2))),
		topWith(str("round"), c1),
		topWith(str("allow-empty-signatures"), c1),
		topWith(str("extra-opcode-budget"), c1),
		topWith(str("exec-trace-config"), c1),
		topWith(str("exec-trace-config"), cat(mapN(1), str("enable"), c1)),
		topWith(str("exec-trace-config"), arr(c1)),
		topWith(str("zzz"), c1),
		arr(c1),
		arr(arr(grp(stx), grp(stx2)), c1),
		cat(two(grp(stx)), c1),
		cat(two(grp(stx)), c1, c1, []byte{0xff}),
	} {
		add(fmt.Sprintf("msgpack_c1_%02d", i), b)
	}

	// string fields holding bytes that are not UTF-8
	bad := string([]byte{0xff, 0xfe, 'a', 0xc3})
	badStr := func(s string) []byte { return cat([]byte{0xa0 | byte(len(s))}, []byte(s)) }
	for i, b := range [][]byte{
		two(grp(txnWith(str("type"), badStr(bad)))),
		two(grp(pay(str("gen"), badStr(bad)))),
		two(grp(acfg(str("apar"), cat(mapN(3), str("an"), badStr(bad), str("un"), badStr("\xe2\x82"), str("au"), badStr("\x80"))))),
		two(grp(pay(str("note"), badStr(bad)))),
		two(grp(pay(str("gh"), badStr(bad)))),
		two(grp(pay(str("rcv"), badStr(bad)))),
		two(grp(cat(mapN(2), str("sig"), sig, badStr("tx\xff"), txnMap))),
		cat(mapN(1), badStr("txn-groups\xff"), arr(grp(stx), grp(stx2))),
		two(grp(txnWith(str("type"), cat([]byte{0xc4, 2}, []byte{0xff, 0xfe})))),
		req(grp(pay(str("gen"), badStr(bad)))),
		req(grp(txnWith(str("type"), badStr(bad), str("snd"), snd, str("fee"), u(1000), str("fv"), u(1), str("lv"), u(1000)))),
		cat(mapN(2), str("txn-groups"), arr(grp(acfg(str("apar"), cat(mapN(2), str("t"), u(5), str("an"), badStr(bad))))), str("allow-empty-signatures"), trueB),
	} {
		add(fmt.Sprintf("msgpack_utf8_%02d", i), b)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, protocol.EncodeJSON(oracleSignedPay(1))); err != nil {
		panic(err)
	}
	twoJSON := func(stxnJSON string) []byte {
		return []byte(`{"txn-groups":[{"txns":[` + stxnJSON + `]},{"txns":[` + compact.String() + `]}]}`)
	}
	oneJSON := func(stxnJSON string) []byte {
		return []byte(`{"txn-groups":[{"txns":[` + stxnJSON + `]}],"allow-empty-signatures":true}`)
	}
	sndJSON := basics.Address(st.Txn.Sender).String()
	for i, b := range [][]byte{
		twoJSON(`{"txn":{"type":"` + bad + `"}}`),
		twoJSON(`{"txn":{"type":"pay","gen":"` + bad + `"}}`),
		twoJSON(`{"txn":{"type":"acfg","apar":{"an":"` + bad + `","un":"\xe2\x82","au":"\x80"}}}`),
		twoJSON(`{"txn":{"type":"pay","note":"` + bad + `"}}`),
		twoJSON(`{"txn":{"type":"pay","rcv":"` + bad + `"}}`),
		twoJSON(`{"sig":"` + bad + `"}`),
		twoJSON(`{"tx` + bad + `":{}}`),
		twoJSON(`{"txn":{"ty\xffpe":"pay"}}`),
		[]byte(`{"txn-groups":[],"r` + bad + `":1}`),
		twoJSON(`{"txn":{"type":"pay","fee":"1` + bad + `"}}`),
		twoJSON(`{"txn":{"type":"pay","gen":"ÿ` + bad + `\n"}}`),
		twoJSON(`{"txn":{"type":["` + bad + `"]}}`),
		oneJSON(`{"txn":{"type":"` + bad + `","snd":"` + sndJSON + `","fee":1000,"fv":1,"lv":1000}}`),
		oneJSON(`{"txn":{"type":"pay","snd":"` + sndJSON + `","fee":1000,"fv":1,"lv":1000,"gen":"` + bad + `"}}`),
		oneJSON(`{"txn":{"type":"acfg","snd":"` + sndJSON + `","fee":1000,"fv":1,"lv":1000,"apar":{"t":5,"an":"` + bad + `"}}}`),
		append([]byte(`{"txn-groups":[]}`), 0xff),
		[]byte("\xff{\"txn-groups\":[]}"),
		[]byte("{\"txn-groups\":[]\xff}"),
	} {
		add(fmt.Sprintf("json_utf8_%02d", i), b)
	}
	return cases
}

// TestAlgodRustSimulateRequestSchema writes the Rust go-codec schema of
// PreEncodedSimulateRequest (algo-rest-api's simulate_request_schema.rs) to
// $SCHEMA_OUT: every field go-codec's reflection sees, in its order, with the
// decode function it picks (issue #2477).
func TestAlgodRustSimulateRequestSchema(t *testing.T) {
	out := os.Getenv("SCHEMA_OUT")
	if out == "" {
		t.Skip("SCHEMA_OUT not set")
	}
	g := schemaGen{named: map[reflect.Type]string{}}
	root := g.ty(reflect.TypeOf(v2.PreEncodedSimulateRequest{}))
	var b strings.Builder
	b.WriteString(schemaHeader)
	for _, d := range g.decls {
		b.WriteString(d)
	}
	fmt.Fprintf(&b, "/// The body go decodes: `%s`.\npub const SIMULATE_REQUEST: Ty = %s;\n", reflect.TypeOf(v2.PreEncodedSimulateRequest{}), root)
	require.NoError(t, os.WriteFile(out, []byte(b.String()), 0o644))
}

const schemaHeader = `// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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

//! GENERATED by tools/simulate-request-text-oracle
//! (TestAlgodRustSimulateRequestSchema) from go-algorand v5.1.1-stable; do
//! not edit: CI regenerates and diffs it.
//!
//! go-codec's view of the body of POST /v2/transactions/simulate: each
//! struct's fields in go-codec's order (embedded structs inlined, unexported
//! fields left out), with the decode function go-codec picks for each type
//! (issue #2477).

use algo_codec::go_codec_json::{Field, Ty};

`

type schemaGen struct {
	named map[reflect.Type]string
	decls []string
}

var (
	textMarshalerType   = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
	textUnmarshalerType = reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
	selferType          = reflect.TypeOf((*codec.Selfer)(nil)).Elem()
)

func implements(t, iface reflect.Type) bool {
	return t.Implements(iface) || reflect.PointerTo(t).Implements(iface)
}

func (g *schemaGen) ty(t reflect.Type) string {
	if implements(t, selferType) {
		if t != reflect.TypeOf(basics.MicroAlgos{}) {
			panic("unexpected codec.Selfer " + t.String())
		}
		// CodecDecodeSelf: dec.MustDecode(&base.Raw)
		return "Ty::U64"
	}
	if _, ok := reflect.PointerTo(t).MethodByName("UnmarshalJSON"); ok {
		panic("unexpected json unmarshaler " + t.String())
	}
	if implements(t, textMarshalerType) && implements(t, textUnmarshalerType) {
		if t != reflect.TypeOf(basics.Address{}) {
			panic("unexpected text unmarshaler " + t.String())
		}
		return "Ty::Address"
	}
	switch t.Kind() {
	case reflect.Bool:
		return "Ty::Bool"
	case reflect.String:
		return "Ty::Str"
	case reflect.Int, reflect.Int64:
		return "Ty::I64"
	case reflect.Uint, reflect.Uint64:
		return "Ty::U64"
	case reflect.Uint32:
		return "Ty::U32"
	case reflect.Uint16:
		return "Ty::U16"
	case reflect.Uint8:
		return "Ty::U8"
	case reflect.Ptr:
		return "Ty::Ptr(&" + g.ty(t.Elem()) + ")"
	case reflect.Array:
		if t.Elem().Kind() != reflect.Uint8 {
			panic("unexpected array " + t.String())
		}
		return fmt.Sprintf("Ty::ByteArray(%d)", t.Len())
	case reflect.Slice:
		e := t.Elem()
		if e.Kind() == reflect.Uint8 {
			return "Ty::Bytes"
		}
		if e.PkgPath() == "" && e.Name() != "" {
			// go-codec's fast path for a slice of a predeclared type
			switch e.Kind() {
			case reflect.Uint64:
				return "Ty::FastSlice(&Ty::U64)"
			case reflect.String:
				return "Ty::Strings"
			}
			panic("unexpected fast-path slice " + t.String())
		}
		return fmt.Sprintf("Ty::Slice(&%s, %q)", g.ty(e), t.String())
	case reflect.Map:
		if t.Key().Kind() != reflect.Uint64 || t.Key().PkgPath() != "" {
			panic("unexpected map " + t.String())
		}
		return fmt.Sprintf("Ty::Map(&Ty::U64, &%s)", g.ty(t.Elem()))
	case reflect.Struct:
		if name, ok := g.named[t]; ok {
			return name
		}
		name := strings.ToUpper(strings.NewReplacer(".", "_", "/", "_").Replace(t.String()))
		g.named[t] = name
		var fields []string
		g.fields(t, &fields, map[string]bool{})
		g.decls = append(g.decls, fmt.Sprintf("/// `%s`.\npub const %s: Ty = Ty::Struct(&[\n%s]);\n\n", t.String(), name, strings.Join(fields, "")))
		return name
	}
	panic("unexpected kind " + t.String())
}

// fields lists t's fields as go-codec's rget does: unexported and `-` fields
// skipped, an embedded struct without a tag name inlined at its place.
func (g *schemaGen) fields(t reflect.Type, out *[]string, seen map[string]bool) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("codec")
		if tag == "" {
			tag = f.Tag.Get("json")
		}
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if f.Anonymous && name == "" {
			ft := f.Type
			for ft.Kind() == reflect.Ptr {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				if f.Type.Kind() == reflect.Ptr {
					panic("unexpected embedded pointer in " + t.String())
				}
				g.fields(ft, out, seen)
				continue
			}
		}
		if f.PkgPath != "" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		if seen[name] {
			panic("duplicate field name " + name + " in " + t.String())
		}
		seen[name] = true
		*out = append(*out, fmt.Sprintf("    Field(%q, %s),\n", name, g.ty(f.Type)))
	}
}
