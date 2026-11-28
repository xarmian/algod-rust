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

// Parity oracle for algod-rust issue #2556: go-algorand v5.1.1-stable's
// `algokey salted` (cmd/algokey/salted*.go) on fixed inputs, one JSON object
// per case: key derivation for every scheme, scheme parsing/formatting, the
// key-file decoder with mutated files, `sign` and `sign-program` byte for
// byte (Falcon signing is deterministic, so are the signed bytes), `import`,
// `generate`'s failure texts, `info` and `check-address`. The Rust test
// crates/tools/algokey-rust/src/commands/salted/oracle_tests.rs replays them.
//
// The test is staged into cmd/algokey of a go-algorand checkout at the pin
// (`make libsodium` first):
//
//	cp tools/salted-oracle/oracle_test.go \
//	   ../go-algorand/cmd/algokey/zz_algod_rust_salted_oracle_test.go
//	(cd ../go-algorand && ORACLE_OUT=$PWD/out.jsonl go test -count=1 \
//	   -run '^TestAlgodRustSaltedOracle$' ./cmd/algokey/)
//	cp ../go-algorand/out.jsonl \
//	   crates/tools/algokey-rust/tests/fixtures/salted_oracle.jsonl
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/protocol"
)

type oracleRow map[string]any

func hx(b []byte) string { return hex.EncodeToString(b) }

func errText(err error, dir string) string {
	if err == nil {
		return ""
	}
	return strings.ReplaceAll(err.Error(), dir, "<DIR>")
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdout
	os.Stdout = w
	fn()
	require.NoError(t, w.Close())
	os.Stdout = old
	b, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(b)
}

func oracleEntropy(kind int) crypto.Seed {
	var e crypto.Seed
	switch kind {
	case 1:
		for i := range e {
			e[i] = byte(i + 1)
		}
	case 2:
		e[31] = 0xff
		e[0] = 7
	}
	return e
}

func oracleTxn(sender basics.Address, note string) transactions.SignedTxn {
	var rcv basics.Address
	rcv[0] = 0x42
	return transactions.SignedTxn{
		Txn: transactions.Transaction{
			Type: protocol.PaymentTx,
			Header: transactions.Header{
				Sender:     sender,
				Fee:        basics.MicroAlgos{Raw: 1000},
				FirstValid: 10,
				LastValid:  1010,
				Note:       []byte(note),
			},
			PaymentTxnFields: transactions.PaymentTxnFields{
				Receiver: rcv,
				Amount:   basics.MicroAlgos{Raw: 12345},
			},
		},
	}
}

func TestAlgodRustSaltedOracle(t *testing.T) {
	outPath := os.Getenv("ORACLE_OUT")
	require.NotEmpty(t, outPath, "set ORACLE_OUT")
	f, err := os.Create(outPath)
	require.NoError(t, err)
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	emit := func(r oracleRow) { require.NoError(t, enc.Encode(r)) }

	dir := t.TempDir()
	schemes := []protocol.SigScheme{protocol.SigSchemeFalcon1024, protocol.SigSchemeFalcon512, protocol.SigSchemeEd25519}

	// derive: entropy -> key file, mnemonic, info text, address.
	signings := map[string]saltedSigningMaterial{}
	for _, scheme := range schemes {
		for kind := 0; kind < 3; kind++ {
			entropy := oracleEntropy(kind)
			signing, err := deriveSaltedSigningMaterialFromEntropy(scheme, entropy)
			require.NoError(t, err)
			mnemonic, err := mnemonicFromSeed(entropy)
			require.NoError(t, err)
			var info, mn bytes.Buffer
			require.NoError(t, printSaltedKeyInfo(&info, signing.Public))
			require.NoError(t, printSaltedMnemonic(&mn, entropy))
			seed := deriveSigSchemeKeySeed(scheme, entropy)
			emit(oracleRow{
				"kind": "derive", "scheme": scheme.String(), "entropy": hx(entropy[:]),
				"seed": hx(seed[:]), "keyfile": hx(protocol.Encode(&signing)), "mnemonic": mnemonic,
				"info": info.String(), "mnemonic_text": mn.String(), "address": signing.Public.address().String(),
			})
			signings[scheme.String()+string(rune('0'+kind))] = signing
		}
	}

	// scheme_parse / scheme_format.
	for _, v := range []string{
		"falcon-1024", "Falcon-1024", " FALCON-512\t", "ed25519", "ED25519", "Ed25519\n", "f1", "f5", "ed", "ls", "zz",
		"", " ", "f", "abc", "é", "日", "\u0001\u0002", "falcon-1024x", "\"q\"", "a\nb", "falcon-1024 x", " f1 ",
		"ſ1", "F1", "ED", "\\x", "\t", " ",
	} {
		r := oracleRow{"kind": "scheme_parse", "value": v}
		scheme, err := parseSigScheme(v)
		if err != nil {
			r["err"] = err.Error()
		} else {
			r["scheme"] = hx(scheme[:])
			r["format"] = formatSigScheme(scheme)
		}
		emit(r)
	}
	for _, raw := range [][]byte{{'z', 'z'}, {'l', 's'}, {'f', '1'}, {'f', '5'}, {'e', 'd'}, {0, 1}, {'a', '\n'}, {0xc3, 0xa9}, {0xff, 'a'}} {
		var s protocol.SigScheme
		copy(s[:], raw)
		emit(oracleRow{"kind": "scheme_format", "scheme": hx(raw), "format": formatSigScheme(s)})
	}

	// keyfile: the key file decoder + validate on mutated files.
	keyfileCase := func(name string, data []byte) {
		r := oracleRow{"kind": "keyfile", "name": name, "hex": hx(data)}
		signing, err := decodeSaltedPrivateKeyFileBytes(data)
		if err != nil {
			r["err"] = err.Error()
		} else {
			var info bytes.Buffer
			require.NoError(t, printSaltedKeyInfo(&info, signing.Public))
			r["info"] = info.String()
			r["reencoded"] = hx(protocol.Encode(&signing))
		}
		emit(r)
	}
	for _, scheme := range schemes {
		base := signings[scheme.String()+"0"]
		name := scheme.String()
		enc0 := protocol.Encode(&base)
		keyfileCase(name+"-valid", enc0)
		keyfileCase(name+"-trailing", append(append([]byte{}, enc0...), 0xc0, 0x01))
		keyfileCase(name+"-truncated", enc0[:len(enc0)-1])
		keyfileCase(name+"-half", enc0[:len(enc0)/2])

		short := base
		short.Public.PublicKey = base.Public.PublicKey[:len(base.Public.PublicKey)-1]
		keyfileCase(name+"-short-public", protocol.Encode(&short))
		long := base
		long.Public.PublicKey = append(append([]byte{}, base.Public.PublicKey...), 0)
		keyfileCase(name+"-long-public", protocol.Encode(&long))
		shortSK := base
		shortSK.PrivateKey = base.PrivateKey[:len(base.PrivateKey)-1]
		keyfileCase(name+"-short-private", protocol.Encode(&shortSK))
		noSK := base
		noSK.PrivateKey = nil
		keyfileCase(name+"-no-private", protocol.Encode(&noSK))
		for _, zz := range []protocol.SigScheme{{'z', 'z'}, {'l', 's'}, {0, 0}, {'f', '5'}, {'f', '1'}, {'e', 'd'}} {
			bad := base
			bad.Public.Scheme = zz
			keyfileCase(name+"-as-"+hx(zz[:]), protocol.Encode(&bad))
		}
		for i := 0; i <= 255; i++ {
			cand := base
			cand.Public.Salt = basics.AddressSalt(i)
			if !cand.Public.address().IsOffEd25519Curve() {
				keyfileCase(name+"-on-curve-salt", protocol.Encode(&cand))
				break
			}
		}
		for _, salt := range []basics.AddressSalt{0, 1, 255} {
			cand := base
			cand.Public.Salt = salt
			keyfileCase(name+"-salt-"+string(rune('0'+int(salt)%10)), protocol.Encode(&cand))
		}
		flipped := base
		flipped.Public.PublicKey = append([]byte{}, base.Public.PublicKey...)
		flipped.Public.PublicKey[0] ^= 1
		keyfileCase(name+"-flipped-public", protocol.Encode(&flipped))
	}
	var rawSeed crypto.Seed
	keyfileCase("zeros32", rawSeed[:])
	keyfileCase("empty", nil)
	keyfileCase("mnemonic", []byte("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"))
	keyfileCase("nil", []byte{0xc0})
	keyfileCase("empty-map", []byte{0x80})
	keyfileCase("empty-array", []byte{0x90})
	keyfileCase("fixarray-1", []byte{0x91, 0xc0})
	keyfileCase("int", []byte{0x01})
	// ed25519 whose private key tail does not match its seed: valid per
	// validate (sizes + off-curve only), signs with the stored tail.
	edBase := signings["ed0"]
	edBad := edBase
	edBad.PrivateKey = append([]byte{}, edBase.PrivateKey...)
	edBad.PrivateKey[40] ^= 0x55
	keyfileCase("ed25519-inconsistent-tail", protocol.Encode(&edBad))
	edBadSeed := edBase
	edBadSeed.PrivateKey = append([]byte{}, edBase.PrivateKey...)
	edBadSeed.PrivateKey[3] ^= 0x01
	keyfileCase("ed25519-inconsistent-seed", protocol.Encode(&edBadSeed))
	edZeroTail := edBase
	edZeroTail.PrivateKey = append(append([]byte{}, edBase.PrivateKey[:32]...), make([]byte, 32)...)
	keyfileCase("ed25519-zero-tail", protocol.Encode(&edZeroTail))
	edTailOnCurve := edBase
	edTailOnCurve.PrivateKey = append(append([]byte{}, edBase.PrivateKey[:32]...), bytes.Repeat([]byte{0xff}, 32)...)
	keyfileCase("ed25519-ff-tail", protocol.Encode(&edTailOnCurve))

	// Hand-built msgpack: every way the generated decoder can fail.
	{
		fs := func(s string) []byte { return append([]byte{0xa0 | byte(len(s))}, s...) }
		mapN := func(n byte) []byte { return []byte{0x80 | n} }
		bin8 := func(b []byte) []byte { return append([]byte{0xc4, byte(len(b))}, b...) }
		cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
		pub := fs("public")
		priv := fs("private-key")
		scheme := fs("scheme")
		salt := fs("salt")
		pk := fs("public-key")
		sg := signings["ed1"]
		goodSK := bin8(sg.PrivateKey)
		goodPK := bin8(sg.Public.PublicKey)
		goodPublic := cat(mapN(3), scheme, bin8([]byte("ed")), salt, []byte{byte(sg.Public.Salt)}, pk, goodPK)
		if sg.Public.Salt > 127 {
			goodPublic = cat(mapN(3), scheme, bin8([]byte("ed")), salt, []byte{0xcc, byte(sg.Public.Salt)}, pk, goodPK)
		}
		cases := map[string][]byte{
			"hb-good":               cat(mapN(2), pub, goodPublic, priv, goodSK),
			"hb-unknown-top":        cat(mapN(1), fs("zz"), []byte{1}),
			"hb-unknown-top-after":  cat(mapN(3), pub, goodPublic, priv, goodSK, fs("zz"), []byte{1}),
			"hb-unknown-nested":     cat(mapN(1), pub, mapN(1), fs("zz"), []byte{1}),
			"hb-key-int":            cat(mapN(1), []byte{1, 1}),
			"hb-key-nil":            cat(mapN(1), []byte{0xc0, 0xc0}),
			"hb-key-bin":            cat(mapN(2), []byte{0xc4, 6}, []byte("public"), goodPublic, priv, goodSK),
			"hb-key-str8":           cat(mapN(2), []byte{0xd9, 6}, []byte("public"), goodPublic, priv, goodSK),
			"hb-key-str16":          cat(mapN(2), []byte{0xda, 0, 6}, []byte("public"), goodPublic, priv, goodSK),
			"hb-key-array":          cat(mapN(1), []byte{0x90, 1}),
			"hb-map16":              cat([]byte{0xde, 0, 2}, pub, goodPublic, priv, goodSK),
			"hb-map32":              cat([]byte{0xdf, 0, 0, 0, 2}, pub, goodPublic, priv, goodSK),
			"hb-map-short-count":    cat(mapN(3), pub, goodPublic, priv, goodSK),
			"hb-map16-short":        {0xde, 0},
			"hb-map32-short":        {0xdf, 0, 0, 0},
			"hb-invalid-prefix":     {0xc1},
			"hb-str-top":            fs("abc"),
			"hb-float-top":          {0xca, 0, 0, 0, 0},
			"hb-bool-top":           {0xc3},
			"hb-ext-top":            {0xd4, 1, 1},
			"hb-nil-top":            {0xc0},
			"hb-public-int":         cat(mapN(1), pub, []byte{5}),
			"hb-public-nil":         cat(mapN(2), pub, []byte{0xc0}, priv, goodSK),
			"hb-public-array":       cat(mapN(1), pub, []byte{0x90}),
			"hb-scheme-int":         cat(mapN(1), pub, mapN(1), scheme, []byte{5}),
			"hb-scheme-3":           cat(mapN(1), pub, mapN(1), scheme, bin8([]byte("abc"))),
			"hb-scheme-1":           cat(mapN(1), pub, mapN(1), scheme, bin8([]byte("a"))),
			"hb-scheme-str":         cat(mapN(1), pub, mapN(1), scheme, fs("ed")),
			"hb-scheme-nil":         cat(mapN(1), pub, mapN(1), scheme, []byte{0xc0}),
			"hb-scheme-array":       cat(mapN(1), pub, mapN(1), scheme, []byte{0x92, 0x65, 0x64}),
			"hb-scheme-array-3":     cat(mapN(1), pub, mapN(1), scheme, []byte{0x93, 0x65, 0x64, 1}),
			"hb-scheme-array-bad":   cat(mapN(1), pub, mapN(1), scheme, []byte{0x92, 0x65, 0xa0}),
			"hb-scheme-array-over":  cat(mapN(1), pub, mapN(1), scheme, []byte{0x92, 0x65, 0xcd, 1, 0}),
			"hb-scheme-short":       cat(mapN(1), pub, mapN(1), scheme, []byte{0xc4}),
			"hb-salt-over":          cat(mapN(1), pub, mapN(1), salt, []byte{0xcd, 1, 0}),
			"hb-salt-neg":           cat(mapN(1), pub, mapN(1), salt, []byte{0xff}),
			"hb-salt-neg8":          cat(mapN(1), pub, mapN(1), salt, []byte{0xd0, 0xfe}),
			"hb-salt-str":           cat(mapN(1), pub, mapN(1), salt, fs("x")),
			"hb-salt-nil":           cat(mapN(1), pub, mapN(1), salt, []byte{0xc0}),
			"hb-salt-uint64":        cat(mapN(1), pub, mapN(1), salt, []byte{0xcf, 0, 0, 0, 0, 0, 0, 0, 7}),
			"hb-salt-float":         cat(mapN(1), pub, mapN(1), salt, []byte{0xca, 0, 0, 0, 0}),
			"hb-salt-short":         cat(mapN(1), pub, mapN(1), salt, []byte{0xcd, 1}),
			"hb-public-key-int":     cat(mapN(1), pub, mapN(1), pk, []byte{5}),
			"hb-public-key-array":   cat(mapN(1), pub, mapN(1), pk, []byte{0x92, 1, 2}),
			"hb-public-key-str":     cat(mapN(1), pub, mapN(1), pk, fs("abc")),
			"hb-public-key-nil":     cat(mapN(1), pub, mapN(1), pk, []byte{0xc0}),
			"hb-public-key-short":   cat(mapN(1), pub, mapN(1), pk, []byte{0xc4, 9, 1}),
			"hb-public-key-arr-ovf": cat(mapN(1), pub, mapN(1), pk, []byte{0x91, 0xcd, 1, 0}),
			"hb-public-key-arr-neg": cat(mapN(1), pub, mapN(1), pk, []byte{0x91, 0xff}),
			"hb-public-key-map":     cat(mapN(1), pub, mapN(1), pk, []byte{0x81, 1, 2}),
			"hb-private-int":        cat(mapN(1), priv, []byte{5}),
			"hb-private-array":      cat(mapN(1), priv, []byte{0x93, 1, 2, 3}),
			"hb-private-nil":        cat(mapN(2), pub, goodPublic, priv, []byte{0xc0}),
			"hb-private-str":        cat(mapN(2), pub, goodPublic, priv, fs("abc")),
			"hb-dup-private":        cat(mapN(3), pub, goodPublic, priv, goodSK, priv, []byte{0xc4, 1, 1}),
			"hb-dup-public":         cat(mapN(3), pub, goodPublic, priv, goodSK, pub, mapN(0)),
			"hb-only-public":        cat(mapN(1), pub, goodPublic),
			"hb-only-private":       cat(mapN(1), priv, goodSK),
			"hb-empty-public":       cat(mapN(2), pub, mapN(0), priv, goodSK),
			"hb-trailing-garbage":   cat(mapN(2), pub, goodPublic, priv, goodSK, []byte{0xc1, 0xc1}),
		}
		names := make([]string, 0, len(cases))
		for name := range cases {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			keyfileCase(name, cases[name])
		}
		// every truncation of a valid ed25519 key file
		valid := protocol.Encode(&sg)
		for i := 0; i < len(valid); i++ {
			keyfileCase("trunc-ed-"+string(rune('a'+i/26))+string(rune('a'+i%26)), valid[:i])
		}
	}

	// info: runSaltedInfo on a key file (global flag), stdout captured.
	infoCase := func(name string, data []byte) {
		path := filepath.Join(dir, "info-"+name)
		if data != nil {
			require.NoError(t, os.WriteFile(path, data, 0600))
		}
		saltedInfoKeyfile = path
		var runErr error
		out := captureStdout(t, func() { runErr = runSaltedInfo() })
		emit(oracleRow{"kind": "info", "name": name, "hex": hx(data), "missing": data == nil, "stdout": out, "err": errText(runErr, dir)})
	}
	for _, scheme := range schemes {
		s := signings[scheme.String()+"1"]
		infoCase(scheme.String(), protocol.Encode(&s))
	}
	infoCase("garbage", []byte("hello world"))
	infoCase("missing", nil)

	// sign: byte for byte.
	keyfileFor := func(s saltedSigningMaterial) []byte { return protocol.Encode(&s) }
	var otherSender basics.Address
	otherSender[0] = 9
	var stale basics.Address
	stale[0] = 10
	signCase := func(name string, keyfile []byte, mnemonic, scheme string, txdata []byte, overwrite bool) {
		kfPath := ""
		if keyfile != nil {
			kfPath = filepath.Join(dir, "sign-"+name+".key")
			require.NoError(t, os.WriteFile(kfPath, keyfile, 0600))
		}
		txPath := filepath.Join(dir, "sign-"+name+".tx")
		require.NoError(t, os.WriteFile(txPath, txdata, 0600))
		outPath := filepath.Join(dir, "sign-"+name+".out")
		os.Remove(outPath)
		runErr := runSaltedSignWithOptions(saltedSignOptions{
			keyfile: kfPath, mnemonic: mnemonic, scheme: scheme, txfile: txPath, outfile: outPath, overwrite: overwrite,
		})
		r := oracleRow{
			"kind": "sign", "name": name, "mnemonic": mnemonic, "scheme": scheme, "txfile": hx(txdata),
			"overwrite": overwrite, "err": errText(runErr, dir),
		}
		if keyfile != nil {
			r["keyfile"] = hx(keyfile)
		}
		if runErr == nil {
			out, err := os.ReadFile(outPath)
			require.NoError(t, err)
			r["out"] = hx(out)
		}
		emit(r)
	}
	for _, scheme := range schemes {
		name := scheme.String()
		sg := signings[name+"1"]
		kf := keyfileFor(sg)
		own := oracleTxn(sg.Public.address(), "own")
		other := oracleTxn(otherSender, "other")
		signCase(name+"-own", kf, "", "", protocol.Encode(&own), false)
		signCase(name+"-other", kf, "", "", protocol.Encode(&other), false)
		both := append(protocol.Encode(&own), protocol.Encode(&other)...)
		signCase(name+"-two", kf, "", "", both, false)
		e1 := oracleEntropy(1)
		mn, err := mnemonicFromSeed(e1)
		require.NoError(t, err)
		long := formatSigScheme(scheme)
		signCase(name+"-mnemonic", nil, mn, long, protocol.Encode(&own), false)
		signCase(name+"-mnemonic-short", nil, mn, name, protocol.Encode(&other), false)
		signCase(name+"-mnemonic-padded", nil, "  "+mn+"\n", strings.ToUpper(long), protocol.Encode(&own), false)
		signCase(name+"-keyfile-with-scheme", kf, "", long, protocol.Encode(&own), false)
		signCase(name+"-mnemonic-no-scheme", nil, mn, "", protocol.Encode(&own), false)
		signCase(name+"-both-sources", kf, mn, long, protocol.Encode(&own), false)
		signCase(name+"-empty-file", kf, "", "", nil, false)
		signCase(name+"-garbage", kf, "", "", []byte("not msgpack at all"), false)
		trunc := protocol.Encode(&own)
		signCase(name+"-truncated", kf, "", "", trunc[:len(trunc)-3], false)
		signCase(name+"-second-truncated", kf, "", "", append(append([]byte{}, trunc...), trunc[:5]...), false)
	}
	{
		sg := signings["f10"]
		kf := keyfileFor(sg)
		signed := func(mut func(*transactions.SignedTxn)) []byte {
			s := oracleTxn(sg.Public.address(), "pre")
			mut(&s)
			return protocol.Encode(&s)
		}
		sigSet := signed(func(s *transactions.SignedTxn) { s.Sig[0] = 1 })
		signCase("pre-sig", kf, "", "", sigSet, false)
		signCase("pre-sig-overwrite", kf, "", "", sigSet, true)
		signCase("pre-lsig", kf, "", "", signed(func(s *transactions.SignedTxn) { s.Lsig.Logic = []byte{6, 0x81, 1} }), false)
		signCase("pre-lsig-overwrite", kf, "", "", signed(func(s *transactions.SignedTxn) { s.Lsig.Logic = []byte{6, 0x81, 1} }), true)
		signCase("pre-msig", kf, "", "", signed(func(s *transactions.SignedTxn) { s.Msig.Version = 1; s.Msig.Threshold = 1 }), false)
		signCase("pre-msig-overwrite", kf, "", "", signed(func(s *transactions.SignedTxn) { s.Msig.Version = 1; s.Msig.Threshold = 1 }), true)
		skset := signed(func(s *transactions.SignedTxn) {
			s.SKsig = transactions.SaltedKeySig{Scheme: protocol.SigSchemeFalcon1024, Salt: 3, PublicKey: []byte{1}, Signature: []byte{2}}
			s.AuthAddr = stale
		})
		signCase("pre-sksig", kf, "", "", skset, false)
		signCase("pre-sksig-overwrite", kf, "", "", skset, true)
		signCase("stale-authaddr", kf, "", "", signed(func(s *transactions.SignedTxn) { s.AuthAddr = stale }), false)
		signCase("stale-authaddr-other", kf, "", "", signed(func(s *transactions.SignedTxn) { s.Txn.Sender = otherSender; s.AuthAddr = stale }), false)
		signCase("pre-sig-second", kf, "", "", append(signed(func(*transactions.SignedTxn) {}), sigSet...), false)
		signCase("pre-sig-second-overwrite", kf, "", "", append(signed(func(*transactions.SignedTxn) {}), sigSet...), true)
		// an on-curve salt is refused at validate (key file read)
		for i := 0; i <= 255; i++ {
			cand := sg
			cand.Public.Salt = basics.AddressSalt(i)
			if !cand.Public.address().IsOffEd25519Curve() {
				signCase("on-curve-salt", keyfileFor(cand), "", "", sigSet, false)
				break
			}
		}
	}
	{
		// A SignedTxn whose map keys are spelled as arrays of uint8: the
		// generated decoder reads them (`ReadMapKeyZC`), so go signs them.
		sg := signings["ed1"]
		kf := keyfileFor(sg)
		own := oracleTxn(sg.Public.address(), "arraykey")
		enc := protocol.Encode(&own)
		topKey := append([]byte{0x81, 0x93, 't', 'x', 'n'}, enc[5:]...)
		signCase("array-key-top", kf, "", "", topKey, false)
		sndKey := bytes.Replace(enc, []byte{0xa3, 's', 'n', 'd'}, []byte{0x93, 's', 'n', 'd'}, 1)
		signCase("array-key-nested", kf, "", "", sndKey, false)
		binKey := bytes.Replace(enc, []byte{0xa3, 's', 'n', 'd'}, []byte{0xc4, 3, 's', 'n', 'd'}, 1)
		signCase("bin-key-nested", kf, "", "", binKey, false)
		badKey := bytes.Replace(enc, []byte{0xa3, 's', 'n', 'd'}, []byte{0x93, 's', 'n', 'e'}, 1)
		signCase("array-key-unknown", kf, "", "", badKey, false)
	}
	{
		// ed25519 key files whose tail disagrees with the seed.
		edBase := signings["ed1"]
		own := oracleTxn(edBase.Public.address(), "tail")
		for _, c := range []struct {
			name string
			mut  func(*saltedSigningMaterial)
		}{
			{"tail", func(m *saltedSigningMaterial) { m.PrivateKey[40] ^= 0x55 }},
			{"seed", func(m *saltedSigningMaterial) { m.PrivateKey[3] ^= 0x01 }},
			{"zero", func(m *saltedSigningMaterial) { copy(m.PrivateKey[32:], make([]byte, 32)) }},
			{"ff", func(m *saltedSigningMaterial) { copy(m.PrivateKey[32:], bytes.Repeat([]byte{0xff}, 32)) }},
			{"clean", func(m *saltedSigningMaterial) {}},
		} {
			m := edBase
			m.PrivateKey = append([]byte{}, edBase.PrivateKey...)
			c.mut(&m)
			signCase("ed25519-inconsistent-"+c.name, keyfileFor(m), "", "", protocol.Encode(&own), false)
		}
	}

	// sign-program.
	programCase := func(name, fileName string, keyfile []byte, mnemonic, scheme string, program []byte) {
		kfPath := ""
		if keyfile != nil {
			kfPath = filepath.Join(dir, "prog-"+name+".key")
			require.NoError(t, os.WriteFile(kfPath, keyfile, 0600))
		}
		progPath := filepath.Join(dir, fileName)
		require.NoError(t, os.WriteFile(progPath, program, 0600))
		outPath := filepath.Join(dir, "prog-"+name+".lsig")
		os.Remove(outPath)
		runErr := runSaltedSignProgramWithOptions(saltedSignProgramOptions{
			keyfile: kfPath, mnemonic: mnemonic, scheme: scheme, program: progPath, outfile: outPath,
		})
		r := oracleRow{
			"kind": "sign_program", "name": name, "file_name": fileName, "mnemonic": mnemonic, "scheme": scheme,
			"program": hx(program), "err": errText(runErr, dir),
		}
		if keyfile != nil {
			r["keyfile"] = hx(keyfile)
		}
		if runErr == nil {
			out, err := os.ReadFile(outPath)
			require.NoError(t, err)
			r["out"] = hx(out)
		}
		emit(r)
	}
	compiled := []byte{0x06, 0x81, 0x01}
	for _, scheme := range schemes {
		name := scheme.String()
		sg := signings[name+"1"]
		kf := keyfileFor(sg)
		mn, err := mnemonicFromSeed(oracleEntropy(1))
		require.NoError(t, err)
		programCase(name+"-ok", "program.teal.tok", kf, "", "", compiled)
		programCase(name+"-mnemonic", "program.teal.tok", nil, mn, name, compiled)
		programCase(name+"-ok-long", "long.tok", kf, "", "", append([]byte{0x08, 0x20, 0x01, 0x00, 0x22}, bytes.Repeat([]byte{0x80, 0x01}, 100)...))
		programCase(name+"-empty", "empty.tok", kf, "", "", []byte{})
		programCase(name+"-teal-ext", "program.teal", kf, "", "", compiled)
		programCase(name+"-teal-text", "text.tok", kf, "", "", []byte("#pragma version 1\nint 1"))
		programCase(name+"-pragmaless", "pragmaless.tok", kf, "", "", []byte("int 1"))
		programCase(name+"-crlf-text", "crlf.tok", kf, "", "", []byte("int 1\r\nreturn\r\n"))
		programCase(name+"-tilde", "tilde.tok", kf, "", "", []byte("~"))
		programCase(name+"-del", "del.tok", kf, "", "", []byte("int 1\x7f"))
		programCase(name+"-nul", "nul.tok", kf, "", "", []byte("int 1\x00"))
		programCase(name+"-high", "high.tok", kf, "", "", []byte{0x80})
		programCase(name+"-both", "both.tok", kf, mn, name, compiled)
		programCase(name+"-keyfile-scheme", "ks.tok", kf, "", name, compiled)
		programCase(name+"-mnemonic-no-scheme", "mns.tok", nil, mn, "", compiled)
	}

	// import.
	importCase := func(name, mnemonic, scheme string, keyfileInDir bool) {
		path := filepath.Join(dir, "import-"+name+".key")
		if !keyfileInDir {
			path = filepath.Join(dir, "no-such-dir", "import.key")
		}
		os.Remove(path)
		var runErr error
		out := captureStdout(t, func() { runErr = runSaltedImportWithOptions(mnemonic, scheme, path) })
		r := oracleRow{"kind": "import", "name": name, "mnemonic": mnemonic, "scheme": scheme, "stdout": out, "err": errText(runErr, dir), "dir_ok": keyfileInDir}
		if data, err := os.ReadFile(path); err == nil {
			r["keyfile"] = hx(data)
		}
		emit(r)
	}
	for _, scheme := range schemes {
		name := scheme.String()
		mn, err := mnemonicFromSeed(oracleEntropy(2))
		require.NoError(t, err)
		importCase(name, mn, name, true)
		importCase(name+"-padded", "\t "+mn+" \n", strings.ToUpper(name), true)
		importCase(name+"-nodir", mn, name, false)
		importCase(name+"-badscheme", mn, "zz", true)
		importCase(name+"-noscheme", mn, "", true)
		importCase(name+"-badmnemonic", "not a valid mnemonic", name, true)
		importCase(name+"-emptymnemonic", "", name, true)
		importCase(name+"-badmnemonic-noscheme", "not a valid mnemonic", "", true)
		importCase(name+"-badmnemonic-badscheme", "not a valid mnemonic", "zz", true)
	}
	{
		mn, err := mnemonicFromSeed(oracleEntropy(0))
		require.NoError(t, err)
		words := strings.Split(mn, " ")
		bad := append([]string{}, words...)
		bad[len(bad)-1] = "abandon"
		importCase("checksum", strings.Join(bad, " "), "f1", true)
		importCase("short", strings.Join(words[:10], " "), "f1", true)
		importCase("upper", strings.ToUpper(mn), "f1", true)
		importCase("double-space", strings.ReplaceAll(mn, " ", "  "), "f1", true)
		importCase("unknown-word", strings.Replace(mn, words[0], "zzzzzz", 1), "f1", true)
	}

	// generate: only the deterministic failure paths.
	generateCase := func(name, scheme string, keyfileInDir bool) {
		path := filepath.Join(dir, "gen-"+name+".key")
		if !keyfileInDir {
			path = filepath.Join(dir, "no-such-dir", "gen.key")
		}
		saltedGenerateScheme = scheme
		saltedGenerateKeyfile = path
		var runErr error
		out := captureStdout(t, func() { runErr = runSaltedGenerate() })
		emit(oracleRow{"kind": "generate", "name": name, "scheme": scheme, "stdout_empty": out == "", "err": errText(runErr, dir), "dir_ok": keyfileInDir})
	}
	generateCase("badscheme", "zz", true)
	generateCase("noscheme", "", true)
	generateCase("nodir-f1", "f1", false)
	generateCase("nodir-ed", "ed25519", false)
	generateCase("raw-bytes", "é", true)

	// check-address.
	var seed crypto.Seed
	onCurve := basics.Address(crypto.GenerateSignatureSecrets(seed).SignatureVerifier)
	offCurve := signings["f10"].Public.address()
	lower := strings.ToLower(offCurve.String())
	badChecksum := offCurve.String()[:57] + "A"
	for _, a := range []string{
		offCurve.String(), onCurve.String(), "not-an-address", "", lower, badChecksum, offCurve.String()[:40],
		offCurve.String() + "AA", " " + offCurve.String(), offCurve.String() + "\n", "AAAA", strings.Repeat("A", 58),
		basics.Address{}.String(),
	} {
		var runErr error
		out := captureStdout(t, func() { runErr = runSaltedCheckAddress(a) })
		emit(oracleRow{"kind": "check_address", "address": a, "stdout": out, "err": errText(runErr, dir)})
	}
}
