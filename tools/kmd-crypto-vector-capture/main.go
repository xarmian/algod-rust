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

// kmd-crypto-vector-capture generates JSON test vectors for the
// kmd wallet crypto envelope (scrypt + nacl/secretbox + go-codec
// canonical msgpack). The fixture is consumed by `algo-kmd`'s
// integration tests to verify the Rust port produces and accepts the
// same bytes as go-algorand.
//
// The encryption logic here is a faithful reimplementation of
// ../../../go-algorand/daemon/kmd/wallet/driver/sqlite_crypto.go
// (v4.6.0-stable). The Go reference functions are package-private, so
// we mirror them with public primitives — same algorithms, same
// constants, same go-codec settings. If those drift, the
// schema-equality test in algo-kmd will trip first.
//
// Regenerate with:
//
//	cd tools/kmd-crypto-vector-capture && \
//	  go run . > ../../crates/node/algo-kmd/tests/fixtures/kmd_crypto_vectors.json
package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"

	"github.com/algorand/go-codec/codec"
)

// Constants mirror sqlite_crypto.go.
const (
	saltLen      = 32
	nonceLen     = 24
	masterKeyLen = 32
)

// ScryptParams mirrors config.ScryptParams.
type ScryptParams struct {
	ScryptN int `codec:"scrypt_n"`
	ScryptR int `codec:"scrypt_r"`
	ScryptP int `codec:"scrypt_p"`
}

// typedPlaintext mirrors sqlite_crypto.go:58–61.
type typedPlaintext struct {
	Plaintext []byte `codec:"plaintext"`
	Type      string `codec:"plaintext_type"`
}

// encryptedDBBlob mirrors sqlite_crypto.go:65–71.
type encryptedDBBlob struct {
	ScryptParams
	DoScrypt   bool           `codec:"do_scrypt"`
	Ciphertext []byte         `codec:"ciphertext"`
	Nonce      [nonceLen]byte `codec:"nonce"`
	Salt       [saltLen]byte  `codec:"salt"`
}

// codecHandle is configured identically to kmd's (sqlite.go:111–119).
var codecHandle *codec.MsgpackHandle

func init() {
	codecHandle = new(codec.MsgpackHandle)
	codecHandle.ErrorIfNoField = true
	codecHandle.ErrorIfNoArrayExpand = true
	codecHandle.Canonical = true
	codecHandle.RecursiveEmptyCheck = true
	codecHandle.WriteExt = true
	codecHandle.PositiveIntUnsigned = true
}

func msgpackEncode(obj interface{}) []byte {
	var b []byte
	enc := codec.NewEncoderBytes(&b, codecHandle)
	enc.MustEncode(obj)
	return b
}

// encryptScrypt mirrors encryptBlobWithPasswordBlankOK with cfg != nil
// (sqlite_crypto.go:131) but takes the nonce and salt as parameters so
// the test vector is deterministic.
func encryptScrypt(plaintext []byte, ptType string, password []byte, params ScryptParams,
	nonce [nonceLen]byte, salt [saltLen]byte) []byte {
	keySlice, err := scrypt.Key(password, salt[:], params.ScryptN, params.ScryptR, params.ScryptP, masterKeyLen)
	if err != nil {
		panic(err)
	}
	var key [masterKeyLen]byte
	copy(key[:], keySlice)

	typedPT := typedPlaintext{Plaintext: plaintext, Type: ptType}
	encoded := msgpackEncode(typedPT)
	ct := secretbox.Seal(nil, encoded, &nonce, &key)

	blob := encryptedDBBlob{
		ScryptParams: params,
		DoScrypt:     true,
		Ciphertext:   ct,
		Nonce:        nonce,
		Salt:         salt,
	}
	return msgpackEncode(blob)
}

// encryptKey mirrors encryptBlobWithKey (sqlite_crypto.go:124) but with
// caller-supplied nonce.
func encryptKey(plaintext []byte, ptType string, key [masterKeyLen]byte, nonce [nonceLen]byte) []byte {
	typedPT := typedPlaintext{Plaintext: plaintext, Type: ptType}
	encoded := msgpackEncode(typedPT)
	ct := secretbox.Seal(nil, encoded, &nonce, &key)

	blob := encryptedDBBlob{
		DoScrypt:   false,
		Ciphertext: ct,
		Nonce:      nonce,
	}
	return msgpackEncode(blob)
}

// hkdfDerive mirrors extractKeyWithIndex (sqlite_crypto.go:234) for use
// in TASK-205; included here so a single regen produces every vector.
func hkdfDerive(derivationKey []byte, index uint64) []byte {
	info := []byte(fmt.Sprintf("AlgorandDeterministicKey-%d", index))
	stream := hkdf.Expand(sha512.New512_256, derivationKey, info)
	seed := make([]byte, 32)
	if _, err := io.ReadFull(stream, seed); err != nil {
		panic(err)
	}
	return seed
}

type vector struct {
	Description   string `json:"description"`
	Path          string `json:"path"`
	Password      string `json:"password_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	PlaintextType string `json:"plaintext_type"`
	NonceHex      string `json:"nonce_hex"`
	SaltHex       string `json:"salt_hex"`
	ScryptN       int    `json:"scrypt_n"`
	ScryptR       int    `json:"scrypt_r"`
	ScryptP       int    `json:"scrypt_p"`
	BlobHex       string `json:"blob_hex"`
}

type hkdfVector struct {
	Description     string `json:"description"`
	DerivationKey   string `json:"derivation_key_hex"`
	Index           uint64 `json:"index"`
	DerivedSeedHex  string `json:"derived_seed_hex"`
}

func main() {
	// Deterministic inputs. Weak scrypt params keep regen fast; the
	// algorithm output is independent of cost.
	password := []byte("correct horse battery staple")
	plaintext := []byte("my secret payload from Go")
	var nonce [nonceLen]byte
	copy(nonce[:], "nonce_24_bytes_for_test.")
	var salt [saltLen]byte
	copy(salt[:], "0123456789abcdef0123456789abcdef")
	params := ScryptParams{ScryptN: 1024, ScryptR: 1, ScryptP: 1}

	scryptBlob := encryptScrypt(plaintext, "master_key", password, params, nonce, salt)

	var rawKey [masterKeyLen]byte
	for i := range rawKey {
		rawKey[i] = byte(i + 1) // 0x01, 0x02, ..., 0x20
	}
	keyPlaintext := []byte("payload encrypted under raw 32-byte key")
	keyBlob := encryptKey(keyPlaintext, "secret_key", rawKey, nonce)

	output := struct {
		Scrypt vector       `json:"scrypt"`
		RawKey vector       `json:"raw_key"`
		Hkdf   []hkdfVector `json:"hkdf"`
	}{
		Scrypt: vector{
			Description:   "scrypt path; deterministic salt+nonce; matches sqlite_crypto.go:131 with cfg!=nil",
			Path:          "encryptBlobWithPasswordBlankOK (scrypt)",
			Password:      hex.EncodeToString(password),
			PlaintextHex:  hex.EncodeToString(plaintext),
			PlaintextType: "master_key",
			NonceHex:      hex.EncodeToString(nonce[:]),
			SaltHex:       hex.EncodeToString(salt[:]),
			ScryptN:       params.ScryptN,
			ScryptR:       params.ScryptR,
			ScryptP:       params.ScryptP,
			BlobHex:       hex.EncodeToString(scryptBlob),
		},
		RawKey: vector{
			Description:   "raw-key path; password IS the 32-byte secretbox key; matches sqlite_crypto.go:124",
			Path:          "encryptBlobWithKey",
			Password:      hex.EncodeToString(rawKey[:]),
			PlaintextHex:  hex.EncodeToString(keyPlaintext),
			PlaintextType: "secret_key",
			NonceHex:      hex.EncodeToString(nonce[:]),
			SaltHex:       "",
			ScryptN:       0,
			ScryptR:       0,
			ScryptP:       0,
			BlobHex:       hex.EncodeToString(keyBlob),
		},
		Hkdf: []hkdfVector{
			{
				Description:    "extractKeyWithIndex with MDK=ones, index=0; consumed by TASK-205",
				DerivationKey:  hex.EncodeToString(bytesOf(0x11, 32)),
				Index:          0,
				DerivedSeedHex: hex.EncodeToString(hkdfDerive(bytesOf(0x11, 32), 0)),
			},
			{
				Description:    "extractKeyWithIndex with MDK=ones, index=42",
				DerivationKey:  hex.EncodeToString(bytesOf(0x11, 32)),
				Index:          42,
				DerivedSeedHex: hex.EncodeToString(hkdfDerive(bytesOf(0x11, 32), 42)),
			},
		},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		panic(err)
	}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
