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

// Parity oracle for algod-rust issue #2492: go-algorand v5.0.5-stable's HTTP
// status and response body for raw transaction submits (POST /v2/transactions,
// Handlers.RawTransaction, and POST /v2/transactions/async,
// Handlers.RawTransactionAsync, in daemon/algod/api/server/v2/handlers.go).
// Both decode the body with decodeTxGroup: go-codec's msgpack reflection
// decoder (protocol.NewDecoder) reading SignedTxns one after the other until
// io.EOF, so a malformed body answers go-codec's own error text, byte
// position included.
//
// It is staged into daemon/algod/api/server/v2/test of a go-algorand checkout
// (package test, for its mock node, whose broadcasts succeed) and writes one
// JSON object per case to $ORACLE_OUT: the endpoint, the body (hex), go's
// status and exact response body and, for a body go accepts, the canonical
// msgp encoding of every transaction it decoded. Every transaction is signed
// with a fixed key, so the output is deterministic.
package test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	v2 "github.com/algorand/go-algorand/daemon/algod/api/server/v2"
	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

type rawSubmitCase struct {
	Name     string   `json:"name"`
	Endpoint string   `json:"endpoint"`
	BodyHex  string   `json:"body_hex"`
	Status   int      `json:"status"`
	Response string   `json:"response"`
	Decoded  []string `json:"decoded,omitempty"`
}

func rawSubmitSignedPay(amount uint64) transactions.SignedTxn {
	var seed crypto.Seed
	seed[0] = 0x52
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

// rawSubmitDecode is decodeTxGroup's loop (handlers.go), to record what go
// decoded from a body its handler accepted.
func rawSubmitDecode(body []byte) []string {
	dec := protocol.NewDecoder(bytes.NewReader(body))
	var out []string
	for {
		var st transactions.SignedTxn
		err := dec.Decode(&st)
		if err == io.EOF {
			return out
		}
		if err != nil {
			panic(err)
		}
		out = append(out, hex.EncodeToString(protocol.Encode(&st)))
	}
}

func TestAlgodRustRawSubmitTextOracle(t *testing.T) {
	out := os.Getenv("ORACLE_OUT")
	if out == "" {
		t.Skip("ORACLE_OUT not set")
	}

	cfg := config.GetDefaultLocal()
	cfg.EnableExperimentalAPI = true
	cfg.EnableDeveloperAPI = true
	mockNode := makeMockNodeWithConfig(nil, t.Name(), nil, cannedStatusReportGolden, false, cfg)
	handler := v2.Handlers{Node: mockNode, Log: logging.Base(), Shutdown: make(chan struct{})}

	var lines bytes.Buffer
	seen := map[string]bool{}
	for _, tc := range rawSubmitBodies() {
		key := tc.Endpoint + "/" + tc.BodyHex
		if seen[key] {
			continue
		}
		seen[key] = true
		body, err := hex.DecodeString(tc.BodyHex)
		require.NoError(t, err)
		path := "/v2/transactions"
		if tc.Endpoint == "async" {
			path += "/async"
		}
		req := httptest.NewRequest("POST", path, bytes.NewReader(body))
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(req, rec)
		if tc.Endpoint == "async" {
			require.NoError(t, handler.RawTransactionAsync(c, model.RawTransactionAsyncParams{}), tc.Name)
		} else {
			require.NoError(t, handler.RawTransaction(c, model.RawTransactionParams{}), tc.Name)
		}
		tc.Status = rec.Code
		tc.Response = rec.Body.String()
		if tc.Status == 200 {
			tc.Decoded = rawSubmitDecode(body)
		}
		line, err := json.Marshal(tc)
		require.NoError(t, err)
		lines.Write(line)
		lines.WriteByte('\n')
	}
	require.NoError(t, os.WriteFile(out, lines.Bytes(), 0o644))
}

// rawSubmitBodies are the raw-submit bodies of issue #2492: whole, concatenated,
// truncated and corrupted transactions, every field with values of every
// msgpack type, struct keys of every type, structs sent as arrays, slices
// sent as maps, repeated keys and non-canonical encodings. The `sync` cases
// go to POST /v2/transactions; most are repeated on the async endpoint.
func rawSubmitBodies() []rawSubmitCase {
	var cases []rawSubmitCase
	n := 0
	add := func(name string, body []byte) {
		cases = append(cases, rawSubmitCase{Name: name, Endpoint: "sync", BodyHex: hex.EncodeToString(body)})
		// the decode is shared; every third case is enough for the async endpoint
		if n%3 == 0 {
			cases = append(cases, rawSubmitCase{Name: name, Endpoint: "async", BodyHex: hex.EncodeToString(body)})
		}
		n++
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
	kv := func(pairs ...[]byte) []byte { return cat(mapN(len(pairs)/2), cat(pairs...)) }
	u := func(v uint64) []byte { return protocol.EncodeReflect(v) }
	nilB := []byte{0xc0}
	zeros := func(k int) []byte { return make([]byte, k) }

	st := rawSubmitSignedPay(1)
	stx := protocol.Encode(&st)
	st2 := rawSubmitSignedPay(2)
	stx2 := protocol.Encode(&st2)
	sig := bin(st.Sig[:])
	snd := bin(st.Txn.Sender[:])
	rcv := bin(st.Txn.Receiver[:])
	gh := bin(st.Txn.GenesisHash[:])
	// a payment's txn fields, keys in canonical order
	payFields := [][]byte{
		str("amt"), u(1), str("fee"), u(1000), str("fv"), u(1), str("gh"), gh,
		str("lv"), u(1000), str("rcv"), rcv, str("snd"), snd, str("type"), str("pay"),
	}
	txnOf := func(extra ...[]byte) []byte { return kv(append(append([][]byte{}, payFields...), extra...)...) }
	// a small unsigned payment with `top` added to the SignedTxn and
	// `txnExtra` to its txn (kept small: the fixture holds thousands)
	stxnWith := func(top [][]byte, txnExtra ...[]byte) []byte {
		txn := kv(append([][]byte{str("fee"), u(1000), str("type"), str("pay")}, txnExtra...)...)
		return kv(append([][]byte{str("txn"), txn}, top...)...)
	}

	// ---- basics
	for i, b := range [][]byte{
		{}, {0xc0}, {0x80}, {0x90}, {0x91, 0xc0}, {0x05}, {0x00}, {0xff}, {0xc1}, {0xc2}, {0xc3},
		{0xa0}, {0xa1, 'x'}, {0xc4, 0x00}, {0xca, 0, 0, 0, 0}, {0xd4, 0x01, 0x02}, {0xcc, 0x05},
		[]byte(`{}`), []byte(`{"txn":{}}`), []byte(" "), []byte("\n"), {0x81}, {0x8f}, {0x9f}, {0xde},
		{0xde, 0x00}, {0xde, 0x00, 0x00}, {0xdf, 0, 0, 0, 0}, {0xdc, 0x00, 0x00}, {0xdd, 0, 0, 0, 1, 0xc0},
		{0xc0, 0xc0}, {0x80, 0x80}, {0xc0, 0x05}, {0x80, 0xc1}, {0x90, 0x90, 0x90},
		{0x81, 0xa0, 0x01}, {0x81, 0xa1, 'x', 0x01}, {0x81, 0x01, 0x01}, {0x81, 0xc0, 0x01},
		{0x81, 0xc3, 0x01}, {0x81, 0xcc, 0x01, 0x01}, {0x81, 0xd0, 0xff, 0x01}, {0x81, 0x90, 0x01},
		{0x81, 0x93, 0x73, 0x69, 0x67, 0xc0}, {0x81, 0x80, 0x01}, {0x81, 0xca, 0, 0, 0, 0, 0x01},
		{0x81, 0xd4, 0x01, 0x02, 0x01}, {0x81, 0xc1, 0x01}, {0x81, 0xc4, 0x03, 's', 'i', 'g', 0xc0},
		{0x81, 0xa3, 's', 'i', 'g', 0xc0}, {0x81, 0xa3, 't', 'x', 'n', 0xc0}, {0x81, 0xa3, 't', 'x', 'n', 0x80},
		{0x81, 0xa3, 't', 'x', 'n', 0x90}, {0x81, 0xa3, 't', 'x', 'n', 0x05}, {0x81, 0xa3, 't', 'x', 'n', 0xa1, 'x'},
		{0x81, 0xa3, 's', 'i', 'g', 0x05}, {0x81, 0xa3, 's', 'i', 'g', 0xa1, 'x'},
		{0x81, 0xa3, 'S', 'i', 'g', 0xc0}, {0x81, 0xa3, 's', 'i', 0xff, 0xc0}, {0x81, 0xa4, 's', 'i', 'g', 0, 0xc0},
		{0x81, 0xd9, 0x03, 's', 'i', 'g', 0xc0}, {0x81, 0xda, 0x00, 0x03, 's', 'i', 'g', 0xc0},
		{0x81, 0xdb, 0, 0, 0, 3, 's', 'i', 'g', 0xc0}, {0x81, 0xc5, 0x00, 0x03, 's', 'i', 'g', 0xc0},
		{0x81, 0x93, 0x73, 0x69, 0xc0, 0xc0}, {0x81, 0x93, 0x73, 0x69, 0x01, 0x00}, {0x81, 0x92, 0xcd, 0x01, 0x00, 0x01},
		{0x81, 0x91, 0xff, 0x01}, {0x81, 0x91, 0xa1, 'x', 0x01},
	} {
		add(fmt.Sprintf("basic_%03d", i), b)
	}

	// ---- whole transactions, concatenated, with trailers
	group := func(k int) []byte {
		var parts [][]byte
		for i := 0; i < k; i++ {
			s := rawSubmitSignedPay(uint64(i + 1))
			parts = append(parts, protocol.Encode(&s))
		}
		return cat(parts...)
	}
	add("whole_one", stx)
	add("whole_two", cat(stx, stx2))
	add("whole_sixteen", group(16))
	add("whole_seventeen", group(17))
	add("whole_eighteen", group(18))
	add("whole_seventeen_truncated", group(17)[:len(group(17))-1])
	add("whole_sixteen_then_nil", cat(group(16), nilB))
	add("whole_sixteen_then_bad", cat(group(16), []byte{0xc1}))
	add("whole_reflect_encoded", protocol.EncodeReflect(&st))
	add("whole_json", protocol.EncodeJSON(&st))
	for i, tr := range [][]byte{
		{0xc0}, {0xc1}, {0x05}, {'x'}, {0x81}, {0x80}, {0x90}, {0xc4, 0x10}, {0xff}, {0x81, 0xa1, 'z', 0x01},
		{0x81, 0xa3, 'f', 'e', 'e', 0x01}, stx[:len(stx)-1], stx[:1], stx[:10], {0xc0, 0xc0}, {0x80, 0xc1},
		{' '}, {'\n'}, {0xc6, 0xff, 0xff, 0xff, 0xff}, {0xdf, 0xff, 0xff, 0xff, 0xff}, {0xdd, 0xff, 0xff, 0xff, 0xff},
		{0xa5, 'a'}, {0xcf, 1, 2}, {0x91}, {0x91, 0xc1},
	} {
		add(fmt.Sprintf("trailer_%02d", i), cat(stx, tr))
	}

	// ---- every prefix of one transaction, every fifth of two
	for k := 0; k < len(stx); k++ {
		add(fmt.Sprintf("prefix_%03d", k), stx[:k])
	}
	two := cat(stx, stx2)
	for k := len(stx); k < len(two); k += 5 {
		add(fmt.Sprintf("prefix2_%03d", k), two[:k])
	}

	// ---- one byte replaced, at every offset of a compact transaction
	compact := kv(str("txn"), kv(str("fee"), u(1000), str("note"), bin([]byte("ab")), str("snd"), bin(zeros(3)), str("type"), str("pay")))
	for at := 0; at < len(compact); at++ {
		for _, c := range []byte{0x00, 0x01, 0xc0, 0xc1, 0xc3, 0xff, 0x80, 0x81, 0x90, 0x91, 0xa0, 0xa1, 0xc4, 0xcc, 0xd0, 0xdc, 0xde, 0xcf, 0xca, 0xd4} {
			b := append([]byte(nil), compact...)
			if b[at] == c {
				continue
			}
			b[at] = c
			add(fmt.Sprintf("replace_%03d_%02x", at, c), b)
		}
	}

	// ---- every field with values of every msgpack type
	values := [][]byte{
		nilB, {0xc2}, {0xc3}, {0x00}, {0x01}, {0x02}, {0x7f}, {0xff}, {0xd0, 0x80}, {0xd0, 0x05}, {0xd1, 0xff, 0xff},
		{0xd2, 0x00, 0x00, 0x00, 0x07}, {0xd3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0xd3, 0x00, 0, 0, 0, 0, 0, 0, 0x09}, {0xcc, 0xff}, {0xcd, 0x01, 0x00}, {0xcd, 0xff, 0xff},
		{0xce, 0x00, 0x01, 0x00, 0x00}, {0xce, 0xff, 0xff, 0xff, 0xff}, {0xcf, 0, 0, 0, 1, 0, 0, 0, 0},
		{0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, {0xca, 0x3f, 0x80, 0, 0}, {0xcb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0},
		str(""), str("x"), str("pay"), str("\xff\xfe"), bin(nil), bin([]byte{1}), bin(zeros(2)), bin(zeros(31)), bin(zeros(32)),
		bin(zeros(33)), bin(zeros(64)), bin(zeros(65)), {0xc5, 0x00, 0x01, 0x07}, arr(), arr(u(1), u(2)), arr(u(256)),
		arr([]byte{0xff}), arr(nilB, u(3)), arr(str("x")), arr(arr()), arr(kv()), kv(), kv(str("a"), u(1)), kv(u(1), u(2)),
		kv(str("t"), u(1)), {0xd4, 0x01, 0x02}, {0xd5, 0x01, 0x02, 0x03}, {0xc7, 0x01, 0x05, 0x09}, {0xc1},
		{0xde, 0x00, 0x00}, {0xdc, 0x00, 0x01, 0x07}, {0xdc, 0x00, 0x21, 0x07}, {0xc4}, {0xc4, 0x05, 0x01},
	}
	txnFields := []string{
		"type", "snd", "fee", "fv", "note", "gen", "gh", "grp", "lx", "rekey", "votekey", "sprfkey", "votekd",
		"nonpart", "apar", "afrz", "apan", "apaa", "apat", "apas", "apfa", "al", "apbx", "apls", "apep", "sp",
		"spmsg", "hb", "amt", "close", "xaid",
	}
	for _, f := range txnFields {
		for i, v := range values {
			add(fmt.Sprintf("txn_%s_%02d", f, i), stxnWith(nil, str(f), v))
		}
	}
	stxnFields := []string{"sig", "msig", "lsig", "pqsig", "txn", "sgnr"}
	for _, f := range stxnFields {
		for i, v := range values {
			if f == "txn" {
				add(fmt.Sprintf("stxn_%s_%02d", f, i), kv(str("txn"), v))
			} else {
				add(fmt.Sprintf("stxn_%s_%02d", f, i), stxnWith([][]byte{str(f), v}))
			}
		}
	}
	// nested fields
	nested := []struct {
		name  string
		build func(v []byte) []byte
	}{
		{"msig_v", func(v []byte) []byte { return stxnWith([][]byte{str("msig"), kv(str("v"), v)}) }},
		{"msig_thr", func(v []byte) []byte { return stxnWith([][]byte{str("msig"), kv(str("thr"), v)}) }},
		{"msig_subsig", func(v []byte) []byte { return stxnWith([][]byte{str("msig"), kv(str("subsig"), v)}) }},
		{"msig_subsig_elem", func(v []byte) []byte { return stxnWith([][]byte{str("msig"), kv(str("subsig"), arr(v))}) }},
		{"msig_subsig_pk", func(v []byte) []byte {
			return stxnWith([][]byte{str("msig"), kv(str("subsig"), arr(kv(str("pk"), v)))})
		}},
		{"lsig_l", func(v []byte) []byte { return stxnWith([][]byte{str("lsig"), kv(str("l"), v)}) }},
		{"lsig_arg", func(v []byte) []byte { return stxnWith([][]byte{str("lsig"), kv(str("arg"), v)}) }},
		{"lsig_arg_elem", func(v []byte) []byte { return stxnWith([][]byte{str("lsig"), kv(str("arg"), arr(v))}) }},
		{"pqsig_sch", func(v []byte) []byte { return stxnWith([][]byte{str("pqsig"), kv(str("sch"), v)}) }},
		{"pqsig_slt", func(v []byte) []byte { return stxnWith([][]byte{str("pqsig"), kv(str("slt"), v)}) }},
		{"apar_dc", func(v []byte) []byte { return stxnWith(nil, str("apar"), kv(str("dc"), v)) }},
		{"apar_un", func(v []byte) []byte { return stxnWith(nil, str("apar"), kv(str("un"), v)) }},
		{"apbx_elem", func(v []byte) []byte { return stxnWith(nil, str("apbx"), arr(v)) }},
		{"apbx_n", func(v []byte) []byte { return stxnWith(nil, str("apbx"), arr(kv(str("n"), v))) }},
		{"al_h", func(v []byte) []byte { return stxnWith(nil, str("al"), arr(kv(str("h"), v))) }},
		{"apas_elem", func(v []byte) []byte { return stxnWith(nil, str("apas"), arr(v)) }},
		{"apaa_elem", func(v []byte) []byte { return stxnWith(nil, str("apaa"), arr(v)) }},
		{"apat_elem", func(v []byte) []byte { return stxnWith(nil, str("apat"), arr(v)) }},
		{"apls_nui", func(v []byte) []byte { return stxnWith(nil, str("apls"), kv(str("nui"), v)) }},
		{"sp_r", func(v []byte) []byte { return stxnWith(nil, str("sp"), kv(str("r"), v)) }},
		{"sp_r_val", func(v []byte) []byte { return stxnWith(nil, str("sp"), kv(str("r"), kv(u(1), v))) }},
		{"sp_r_key", func(v []byte) []byte { return stxnWith(nil, str("sp"), kv(str("r"), kv(v, kv()))) }},
		{"sp_pr", func(v []byte) []byte { return stxnWith(nil, str("sp"), kv(str("pr"), v)) }},
		{"sp_pr_elem", func(v []byte) []byte { return stxnWith(nil, str("sp"), kv(str("pr"), arr(v))) }},
		{"sp_v", func(v []byte) []byte { return stxnWith(nil, str("sp"), kv(str("v"), v)) }},
		{"sp_s_hsh_t", func(v []byte) []byte { return stxnWith(nil, str("sp"), kv(str("S"), kv(str("hsh"), kv(str("t"), v)))) }},
		{"sp_s_pth", func(v []byte) []byte { return stxnWith(nil, str("sp"), kv(str("S"), kv(str("pth"), v))) }},
		{"hb_kd", func(v []byte) []byte { return stxnWith(nil, str("hb"), kv(str("kd"), v)) }},
		{"hb_prf", func(v []byte) []byte { return stxnWith(nil, str("hb"), kv(str("prf"), v)) }},
		{"hb_c", func(v []byte) []byte { return stxnWith(nil, str("hb"), kv(str("c"), v)) }},
		{"spmsg_b", func(v []byte) []byte { return stxnWith(nil, str("spmsg"), kv(str("b"), v)) }},
	}
	for _, f := range nested {
		for i, v := range values {
			add(fmt.Sprintf("nested_%s_%02d", f.name, i), f.build(v))
		}
	}

	// ---- struct keys of every type, at the SignedTxn and the Transaction
	for i, k := range [][]byte{
		u(1), nilB, {0xc3}, {0xff}, {0xd0, 0x80}, {0xcd, 0x01, 0x00}, {0xca, 0, 0, 0, 0}, arr(u(0x73), u(0x69), u(0x67)),
		arr(), arr(u(256)), arr(nilB), arr(str("s")), bin([]byte("sig")), bin(nil), str(""), str("zz"), str("Sig"),
		str("sig\xff"), {0xd9, 0x03, 's', 'i', 'g'}, kv(), {0xd4, 0x01, 0x02}, {0xc1}, str("txn\x00"),
		str("\xff\xfe\x01\x00\x01\x00"), str("\xfe"), str("\xfcfee\xff\x00\x05"),
	} {
		add(fmt.Sprintf("key_stxn_%02d", i), cat(mapN(2), k, sig, str("txn"), txnOf()))
		add(fmt.Sprintf("key_txn_%02d", i), kv(str("sig"), sig, str("txn"), cat(mapN(9), cat(payFields...), k, u(5))))
	}

	// ---- structs sent as arrays, slices sent as maps
	for i, b := range [][]byte{
		arr(sig, nilB, nilB, nilB, txnOf()),
		arr(sig, nilB, nilB, nilB, txnOf(), snd),
		arr(sig, nilB, nilB, nilB, txnOf(), nilB, nilB),
		arr(sig, nilB, nilB, nilB, txnOf(), nilB, u(1)),
		arr(sig),
		arr(nilB, nilB, nilB, nilB, arr(str("pay"), snd, u(1000), u(1), u(1000))),
		arr(nilB, nilB, nilB, nilB, arr(str("pay"), u(5))),
		arr(nilB, kv(), nilB, nilB, nilB),
		arr(nilB, arr(u(1), u(1), arr(arr(bin(zeros(32)))))),
		arr(nilB, arr(u(1), u(1), arr(arr(bin(zeros(32)), bin(zeros(64)), u(1))))),
		arr(nilB, nilB, arr(bin([]byte{0x06, 0x81, 0x01}))),
		{0xdc, 0x00, 0x01, 0xc0},
		{0xdd, 0x00, 0x00, 0x00, 0x00},
		stxnWith(nil, str("apbx"), arr(arr(u(0), bin([]byte("x"))))),
		stxnWith(nil, str("apbx"), arr(arr(u(0), bin([]byte("x")), u(1)))),
		stxnWith(nil, str("apls"), arr(u(1), u(2)), str("apgs"), arr(u(3))),
		stxnWith(nil, str("apaa"), kv(bin([]byte("a")), bin([]byte("b")))),
		stxnWith(nil, str("apas"), kv(u(1), u(2))),
		stxnWith(nil, str("apar"), arr(u(1000), u(0), []byte{0xc2}, str("U"), str("Asset"))),
		stxnWith(nil, str("hb"), arr(snd, arr(bin(zeros(64))), nilB, nilB, u(5), []byte{0xc3})),
		stxnWith(nil, str("hb"), nilB),
		stxnWith(nil, str("hb"), kv()),
		stxnWith(nil, str("hb"), arr()),
		stxnWith(nil, str("sp"), kv(str("r"), kv(u(1), arr(arr(nilB, u(2)), arr(nilB, u(3)))))),
		stxnWith([][]byte{str("msig"), kv(str("subsig"), kv(kv(str("pk"), bin(zeros(32))), kv()))}),
	} {
		add(fmt.Sprintf("shape_%02d", i), b)
	}

	// ---- repeated keys
	sigOne := bin([]byte{9})
	// a state proof reveal holding the merkle signature `sig`
	sigslot := func(sig []byte) []byte { return kv(str("s"), kv(str("s"), sig)) }
	for i, b := range [][]byte{
		stxnWith(nil, str("fee"), u(5)),
		stxnWith(nil, str("note"), bin([]byte("abc")), str("note"), bin([]byte("x"))),
		stxnWith([][]byte{str("sig"), sigOne}),
		stxnWith([][]byte{str("txn"), kv(str("fee"), u(7))}),
		stxnWith([][]byte{str("txn"), kv()}),
		stxnWith([][]byte{str("txn"), nilB}),
		stxnWith(nil, str("gh"), bin([]byte{1, 2})),
		stxnWith(nil, str("gh"), arr(u(7))),
		stxnWith([][]byte{
			str("msig"), kv(str("subsig"), arr(kv(str("pk"), bin(zeros(32))), kv(str("s"), bin(zeros(64))), kv())),
			str("msig"), kv(str("subsig"), arr(kv(str("s"), bin(zeros(64))))),
		}),
		stxnWith([][]byte{
			str("msig"), kv(str("subsig"), arr(kv(str("pk"), bin([]byte{1})), kv(str("pk"), bin([]byte{2})), kv(str("pk"), bin([]byte{3})))),
			str("msig"), kv(str("subsig"), arr(kv(str("s"), bin([]byte{4})))),
			str("msig"), kv(str("subsig"), arr(kv(), kv(str("s"), bin([]byte{5})))),
		}),
		stxnWith([][]byte{
			str("msig"), kv(str("subsig"), arr(kv(str("pk"), bin([]byte{1})))),
			str("msig"), kv(str("subsig"), arr(kv(str("s"), bin([]byte{4})), kv(str("s"), bin([]byte{6})))),
		}),
		stxnWith(nil, str("apbx"), arr(kv(str("i"), u(1), str("n"), bin([]byte("a")))), str("apbx"), arr(kv(str("n"), bin([]byte("b"))))),
		stxnWith(nil, str("apaa"), arr(bin([]byte("aa")), bin([]byte("bb"))), str("apaa"), arr(bin([]byte("c")))),
		stxnWith(nil, str("apas"), arr(u(1), u(2), u(3)), str("apas"), arr(u(9))),
		stxnWith(nil, str("sp"), kv(str("r"), kv(u(1), kv(str("p"), kv(str("w"), u(5))), u(1), kv(str("s"), kv(str("l"), u(6)))))),
		stxnWith(nil, str("sp"), kv(str("r"), kv(u(1), kv(str("p"), kv(str("w"), u(5))), u(1), kv(str("p"), kv(str("lf"), u(6)))))),
		stxnWith(nil, str("sp"), kv(str("r"), kv(u(1), sigslot(kv(str("sig"), bin([]byte("a")))), u(1), sigslot(kv(str("sig"), bin([]byte("b"))))))),
		stxnWith(nil, str("sp"), kv(str("r"), kv(u(1), sigslot(kv(str("prf"), kv(str("pth"), arr(bin([]byte("a")))))), u(1), sigslot(kv(str("prf"), kv(str("pth"), arr(bin([]byte("b")), bin([]byte("c"))))))))),
		stxnWith(nil, str("sp"), kv(str("r"), kv(u(1), kv(str("p"), kv(str("w"), u(5))), u(1), nilB))),
		stxnWith(nil, str("sp"), kv(str("pr"), arr(u(1), u(2)), str("pr"), arr(u(3)))),
		stxnWith(nil, str("hb"), kv(str("kd"), u(5)), str("hb"), kv(str("c"), []byte{0xc3})),
		stxnWith(nil, str("hb"), kv(str("kd"), u(5)), str("hb"), nilB),
		stxnWith(nil, str("apar"), kv(str("t"), u(5)), str("apar"), kv(str("dc"), u(2))),
	} {
		add(fmt.Sprintf("repeat_%02d", i), b)
	}

	// ---- encodings go-codec accepts that msgp's canonical form never writes
	for i, b := range [][]byte{
		kv(str("txn"), txnOf(), str("sig"), sig),
		kv(str("sig"), sig, str("txn"), kv(str("type"), str("pay"), str("snd"), snd, str("fee"), []byte{0xcf, 0, 0, 0, 0, 0, 0, 0x03, 0xe8}, str("fv"), []byte{0xd0, 0x01}, str("lv"), []byte{0xcd, 0x03, 0xe8})),
		kv(str("sig"), sig, str("txn"), txnOf(str("note"), bin(nil), str("close"), bin(zeros(32)), str("apid"), u(0))),
		kv(str("sig"), sig, str("txn"), txnOf(str("note"), str("text note"), str("gen"), bin([]byte("devnet-v1")))),
		cat([]byte{0xde, 0x00, 0x02}, str("sig"), sig, str("txn"), txnOf()),
		cat([]byte{0xdf, 0x00, 0x00, 0x00, 0x02}, str("sig"), sig, str("txn"), txnOf()),
		kv(cat([]byte{0xd9, 0x03}, []byte("sig")), sig, str("txn"), txnOf()),
		kv(str("sig"), cat([]byte{0xc5, 0x00, 0x40}, st.Sig[:]), str("txn"), txnOf()),
		kv(str("sig"), cat([]byte{0xc6, 0, 0, 0, 0x40}, st.Sig[:]), str("txn"), txnOf()),
		kv(str("sig"), cat([]byte{0xd9, 0x40}, st.Sig[:]), str("txn"), txnOf()),
		kv(str("sgnr"), snd, str("txn"), txnOf()),
		kv(str("txn"), txnOf(str("grp"), bin(zeros(32)))),
		kv(str("txn"), txnOf(str("type"), str("xyz"))),
		kv(str("txn"), txnOf(str("type"), str("appl"), str("apid"), u(5), str("apaa"), arr(bin(nil), bin([]byte("x"))))),
		kv(str("txn"), kv(str("type"), str("pay"))),
		kv(str("txn"), kv(str("type"), str("pay\xff"))),
		kv(str("txn"), kv(str("gen"), str("\xe2\x82"), str("type"), str("pay"))),
	} {
		add(fmt.Sprintf("lenient_%02d", i), b)
	}

	// ---- past msgp's allocbounds (go-codec has none)
	many := func(k int, item []byte) []byte {
		var items [][]byte
		for i := 0; i < k; i++ {
			items = append(items, item)
		}
		return cat([]byte{0xdc, byte(k >> 8), byte(k)}, cat(items...))
	}
	bin16 := func(b []byte) []byte { return cat([]byte{0xc5, byte(len(b) >> 8), byte(len(b))}, b) }
	for i, b := range [][]byte{
		stxnWith(nil, str("gen"), str(string(bytes.Repeat([]byte("g"), 100)))),
		stxnWith(nil, str("apaa"), many(20, bin([]byte("a")))),
		stxnWith(nil, str("apat"), many(10, bin(zeros(32)))),
		stxnWith(nil, str("apas"), many(10, u(1))),
		stxnWith(nil, str("apfa"), many(10, u(1))),
		stxnWith(nil, str("apbx"), many(20, kv(str("i"), u(1)))),
		stxnWith(nil, str("al"), many(30, kv(str("s"), u(1)))),
		stxnWith(nil, str("note"), bin16(zeros(2000))),
		stxnWith(nil, str("apap"), bin16(zeros(10000))),
		stxnWith(nil, str("apar"), kv(str("an"), str(string(bytes.Repeat([]byte("n"), 200))))),
		stxnWith(nil, str("apar"), kv(str("au"), str(string(bytes.Repeat([]byte("u"), 200))))),
		stxnWith(nil, str("sp"), kv(str("pr"), many(1100, u(1)))),
		stxnWith(nil, str("sp"), kv(str("S"), kv(str("pth"), many(40, bin([]byte("p")))))),
		stxnWith([][]byte{str("msig"), kv(str("subsig"), many(300, kv()))}),
		stxnWith([][]byte{str("lsig"), kv(str("l"), bin16(zeros(2000)))}),
		stxnWith([][]byte{str("lsig"), kv(str("arg"), many(300, bin([]byte("x"))))}),
		stxnWith([][]byte{str("pqsig"), kv(str("pk"), bin16(zeros(3000)))}),
		stxnWith(nil, str("type"), str(string(bytes.Repeat([]byte("t"), 100)))),
	} {
		add(fmt.Sprintf("bounds_%02d", i), b)
	}

	// ---- huge declared lengths
	for i, b := range [][]byte{
		kv(str("sig"), []byte{0xc6, 0xff, 0xff, 0xff, 0xff}),
		kv(str("txn"), kv(str("note"), []byte{0xc6, 0x7f, 0xff, 0xff, 0xff})),
		kv(str("txn"), kv(str("note"), cat([]byte{0xc6, 0x00, 0x04, 0x00, 0x01}, zeros(1000)))),
		kv(str("txn"), kv(str("apaa"), []byte{0xdd, 0x7f, 0xff, 0xff, 0xff})),
		kv(str("txn"), kv(str("apaa"), []byte{0xdf, 0x7f, 0xff, 0xff, 0xff})),
		[]byte{0xdf, 0xff, 0xff, 0xff, 0xff},
		[]byte{0xdd, 0xff, 0xff, 0xff, 0xff},
		kv(str("txn"), kv(str("sp"), kv(str("r"), []byte{0xdf, 0x7f, 0xff, 0xff, 0xff}))),
		kv(cat([]byte{0xdb, 0x7f, 0xff, 0xff, 0xff}, []byte("sig")), nilB),
		kv(str("txn"), kv(str("type"), []byte{0xdb, 0x7f, 0xff, 0xff, 0xff})),
	} {
		add(fmt.Sprintf("huge_%02d", i), b)
	}
	return cases
}
