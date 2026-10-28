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

package main

import (
	"crypto/sha512"
	"fmt"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
)

// keyDomain separates every key this generator derives from any other use of
// the same seed string. Bumping it is a generator-version change.
const keyDomain = "algod-rust/bench-corpus/v1"

// deriveSeed is the only source of key material: SHA-512/256 over the domain,
// the corpus seed, a label and an index. Nothing reads crypto/rand, so the
// same --seed always yields the same accounts, participation keys and
// therefore the same genesis and txids.
func deriveSeed(seed, label string, idx uint64) [32]byte {
	return sha512.Sum512_256([]byte(fmt.Sprintf("%s|%s|%s|%d", keyDomain, seed, label, idx)))
}

// key is a deterministic ed25519 account key.
type key struct {
	secrets *crypto.SignatureSecrets
	addr    basics.Address
}

func deriveKey(seed, label string, idx uint64) key {
	s := crypto.GenerateSignatureSecrets(crypto.Seed(deriveSeed(seed, label, idx)))
	return key{secrets: s, addr: basics.Address(s.SignatureVerifier)}
}

// partKeys are the public participation keys of an online registration. The
// node never votes (DevMode), so only the public halves are used: a real
// ed25519 key for the vote key, a real VRF key for the selection key and a
// derived 64-byte state-proof commitment (go-algorand checks it is non-empty,
// not that it commits to anything; see apply/keyreg.go).
type partKeys struct {
	vote      crypto.OneTimeSignatureVerifier
	selection crypto.VRFVerifier
	stateProf merklesignature.Commitment
}

func derivePartKeys(seed, label string, idx uint64) partKeys {
	v := crypto.GenerateSignatureSecrets(crypto.Seed(deriveSeed(seed, label+"/vote", idx)))
	selPub, _ := crypto.VrfKeygenFromSeed(deriveSeed(seed, label+"/sel", idx))
	sp := sha512.Sum512([]byte(fmt.Sprintf("%s|%s|%s/stprf|%d", keyDomain, seed, label, idx)))
	var pk partKeys
	copy(pk.vote[:], v.SignatureVerifier[:])
	pk.selection = crypto.VRFVerifier(selPub)
	copy(pk.stateProf[:], sp[:])
	return pk
}
