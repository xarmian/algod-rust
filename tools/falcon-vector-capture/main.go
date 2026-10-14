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

// falcon-vector-capture produces crates/core/algo-falcon/tests/fixtures/
// falcon/vectors.jsonl, the deterministic Falcon-1024 (det1024) parity
// corpus, from go-algorand's own crypto package (issue #1928, epic #1926).
//
// The corpus definition (seeds, messages, negative cases, record format and
// order) is duplicated verbatim in crates/core/algo-falcon/examples/
// gen_vectors.rs, which produces the same file from the vendored C library
// (and, from Phase 21 stage 11, from the pure-Rust port). CI
// (.github/workflows/falcon-vectors.yml) runs this tool and fails on any
// byte difference against the committed file. JSON lines are written by
// hand with a fixed field order and lowercase hex so no encoder detail can
// change a byte.
//
// Usage: cd tools/falcon-vector-capture && go run . [--out PATH] [--allow-unpinned]
//
// Like tools/vrf-vector-capture, it refuses to run unless ../go-algorand is
// checked out at exactly expectedGoAlgorandPin with a clean crypto/ tree.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/algorand/go-algorand/crypto"
)

const expectedGoAlgorandPin = "v5.0.3-stable"

// go-algorand data/transactions/logic/crypto_test.go, BenchmarkVerify,
// "falcon_verify" case. The Go source's comments label the second and third
// byte constants "public key" and "sig", but falcon_verify pops
// (data, signature, pubkey): the 0xba00… value is the signature (det1024
// compressed header 0xBA, salt version 0) and the 0x0a… value is the
// public key (header 0x00 | logn = 10).
const (
	goMsgHex    = "62fdfc072182654f163f5f0f9a621d729566c74d0aa413bf009c9800418c19cd"
	goSigHex    = "ba00a5222fbaa5e2a1a61f708198a4dbc3de94b60d925042d9fa5a299ebb4be27156b1d86a174df4939342f11b776dffb8a0e874714f23318ca9acb823e9aeb14a926ed5cf76e736faa0b22e4bdedf7910decd19329f353b926ae4b404653dbc6db1885c010052b94675d4cc209ef2cf3cfe910c4ef51b6af16d8c7ab6651e57934ab19c89f771058f389ad80474740c529d59a3ea9ab9db228415fb9315dee23e8c7229398c4b0a2b7c5d6eff6e7d8cf1a776ae37f6272082796c0b2a0af637f7ce8fa7f1675dfbd1766543cbf3f19544d635298ea1fafe96ad1bb06fcc6ae9ff9c34acacb88653555c37f2ad6c4eb408478b0d2b6269841243f29b18fa8e0d5050f4f93878e53aac466dc4eb5a7194cb2213c26a2b8c7ccea06f89af26ae85315454da1b15952be639bb94fe3e99236291c4a1edfbe9faf8f32589bf47eb536b28e2cfbdea799d9cf4c88ef85ae45d451e1ab3431c247b796cbf12e63b737cc4894ad7a204f680a449cbbd2e86deca1069b3592977bd8ac7c5b5e1c1b436cde65177b6e82b2e666117a8e37b58122d1a31307ca112311e665b32c68bd42531b4e6bc79957d3d865f6470b8213db8175e5c7115f4ad520a4711b12d9004e661346c4da4cb3e95954ac58e075a320b862a6a317e0988d8fc376fb14562773b9d35d5a44ba951d866a3a06ac93a55e1a26fa91718db49a53e78d9e61d6120dfadd2b4929579ac56ccaac0f8e704826b55b4ca6d8020e42a6e62b5e41708e2e6848cd047385fa1df4f51733df35dbee25c96c4176eae332ca4df31c695fff8be31b4be62e63c3e049483c89384fb1d802e58db5514a59eb96e527b202d0cf45dc760fa0439afbc661868b9408e67254c8cf7c689c50d2f29bccd59c71ea7b6dd368de68669fdf889ac1f8cd390ea17894dd0538ff6e7c740bbf03b4fe32ad66c483c823548eea84f85826da44016bd8cdf2315b07a96a9737ebc7cb244547be3f759bdf50b467552c58333ed7e61cde799346bccc29d5d377d9d5364c369ffd88a83f90a699b3622184436b518e9196524ac9b55385b39ec099d9c18386e06b9dcad2499ddb9673cb87c652209ee60511c9249f1b7ab2b948b5e8b9115c218d5b793d65b96e2fc9e2c6c40ba63791bb89d7d96c33536ad7e6668a85e52ec7e1450a69f25766deeaeb41bcd249394b8ab65a286312db461c363cebe431c4dd5fd3b6bb5d26ae2c597799f400abb3ba160522e2e6da5ebd170a45c9ce80b135a5b330656aab26399bcacd857a7f237dfd2b14ecbfbcaabc7291ba78fe19ac2ecf005b66bb9771bf64f090269a2341967e79702733dc617b469ac12123faeb4c70d6fffac25f9fcd7dbd12ca363985b9bd845e939e6caf328e2bf8e53725bae94fbe30bfdbbc21e584ba72d7badbc2a0915c9faf9c69ad3703cf99a16399b38df157be8ec3a78f20d24b2131f9c25b3c1da70fc6c0c7aa9e9da3108368ca6211dcfa4988b1ace3c28b15b0559224570fbe3cde364734c7a66a0525c1d41e26788cd1c8a3888f344c9385804364f8430ca7d22338cc941917da3dc47a00aae13e3e972af49940c8fa179574694e369a3d5e67db6c91bf843151ca0fff512d9c322c690063ae9bd671815e9d03b3a841952ce04683509e415b8d5aebfcdbd6bd55efbffb2463cf2b96ccb8650a6cee732c8d4ce6409b9a747317866759553f1c5bcc392c98d14a034ccaaa6df5723bb88c38e80"
	goPubkeyHex = "0a85ea3bb342a95a3941a4c2280c686729c76bc164092c0e203388460c556273e6f0a92640650c37e9d5b08fbd8d6bcca940acac9964e64a9e78bd28086b52898812264985e19c3d26318be2ec8852ca2ae2380746428cd08124cf792790d127d3dad09fe891cbadefef36269ae7d584b77ec428d794a6c3b7555956db00314d14a0aa14936830c8622623916639743b218243344224472240cfd158819190ede108394063c3df9c474eb16aa750e48663515d8229d3849670e30891142b632a6a282d915273a5f219d65ebe6b9e6c88170ac62c16a44895a950bfec82819221dab1358861bf0aa6b6342477016d50502a298840ddc42b3ade784b643c63c5e47993ada37dfdc0d56a1c7e4690b5a1d6485900b84f0b61425383b14d4b7ccc0abe8284a47a6f22050838b0482ad8ad389151c25e790ad670d5530f9b3dc518bb0a410f64346a74dc824238026daaa4ad97518d93670a48cf8f86ece593d23ab3a0d601d49a975db291f0d76263551e9f0b8a1b42396a27d9a122210330c692d5545d67c808b50560fc3d4933fa70c463513d7183e8aa091f34dd4426272620fe4b357deea710c687bb7a475d0ed0a40a26ae8f2a357e7a8fa5d5434050c1a36beaa7a90ee4db213a126db8151f2f4bbb4889d4e42bbd19f62dd7285def148071fb7f4f16b28c1d145d2e621fee275161a3d5b9319e7a59527c3d5c2838ef503e4166f2c22118b22bf80e8a1fc1bbbba00f231d2b1a8d3e592bdcc5fd40a2ecebb5ad27a51e7867715b54185a3e62951a5d808d80c31a59e6a3ca53a51eadc34c76dfd6aac22a6e805163b5e9ac8090869a9cd1e2972af7192bcd1da39c30f423ebc86d1976e8f52052262521d3b8ae7eb99d0ad623d811bac636f447e7dc9dcef6f52befd95861f1917116517b0e9b56a85967ab701ff8f1d4de443efce1b2a3d85b592df7a8c87814e8981575ef4e72757c5afa6bec4358e2f29966ad2830e4782f9a293351dfcaac1d0ca30ec1b5fd08a40a6e82938427a68641b96252a85443141c081982ba4d3c8ab05a1a545ea49c23ee07643ec5f013c2676db09cb834ef61817e615ad19c5829216026e5635dc13cad5ffb8bc267bf58d4ebbf100c3045e250c02c10772e96c580db049c80fdd3188e19ad893d16ac100052c557378416929319c9c262c21b768e6058a09b4e4800ae624c892117ec71504a283f558c623a212d048d5d401b00448b18ac25e1c99ab35d91f78badebcd651e86f3465ef99a0afa1721d2153e4a7b51d22b344a8dd102e7411abfe4bd5b8e2d62015edc08fc461fa90cfa666a9a42a0a86e11d6988913ba0259096cb846a1fd311c4cb693c4e3e1ed2ab57e2a5e0bd4616a79e22b28caa6d10dd09225e44bbdbfa1b7b23887055a90918220252777d5a620351cb013cc28346fc69d348165a39d03243a84a9c9bcd4d557a8e9607256baab893a0a5644520686be935e9ead84501f743a489a431cf10b8c27d3901c87b8771ce65e3130a7fe6ad62b709c23bbef1381b1ed49222f487db16af3c9d6779c01c986ea9f823be017fb8bce8e00f2b32840d54e8f656139a4c492257ee8743a8c5f51450c0366655e2b02d27619d07e556001430b04454891247813c8bc31bdee926d039a5038bfca8dc35e57789950442ad7ab3cfc031a8354bd9c462a37052d0b62066bcee0c292b890a71f4ea65895a7d837283404842c59f08414b20ec1b4fda6cc0c4d62216e8ead74ba90196168bc449a2050b442181ea57b915581bc387ed412e4cd5970fd0fb83c94fbbf960d05ffe6d0a26171c249809604a0b2b411e2d6622145c936e31258baf2b7d3c413a9a1d67bc4026d01b47a10b6c5b87f6a36ba1cedd681ca55b9c042bf9afcfcb636040793e08158dd877c49c16658f819129e26237427a1d80b941fbabb4abd4f1da0b6d428a59fbc450620eeb1651849e5972fb12e6dc8092a9fda70206a48d9dc2645641a147626350cf45b1a7d57724fcab0a594df7c023928a3c7a2fc3c9d33e9af10ae5ed282c475a611671d20d90752f2a28db48b7e5d9184212432fa948fbc885f866c93a0b7f510329aea4d53ecf9482f42974beaf289086afdb4797aa129d10639948f46a805ea4000cf1554505f4bd9d775d5894da115f5840913d5070c860b3a623eb261f5f928a31cbcec17c4274b5d1b28fdb231cc8f606c9dc324db5c12f97518fd03466541f7881762c25d711976c6d4f9271d29fa51dc263f650a32010343a51e7dab344e2f6d768864072ddb5df58486434998a280aad94886ea7a11132184e6274d4cd59a5deabf8a4dbbe29e9c234a52d3972608d0a3ea92a78e08531bb938384444246be5bc594ed4d06168e870924e8913f8242bd35f7c9d5ee238cb6db17496047acce0183f2d10a4cf2bbc8e39daf44e630393a0473b8983863b1998c17026ff35ec32a8058fd603ec369b80a94cb7b555cb469f6468de3909b21293b8d0a53a5c813d218d7c630f4d47bb1eb88253e6e1af721ba8a4453e"
)

type named struct {
	name string
	data []byte
}

func seeds() []named {
	out := []named{
		{"seed_zero", make([]byte, 32)},
		{"seed_all_01", fill(0x01, 32)},
		{"seed_all_ff", fill(0xff, 32)},
		{"seed_counter", counter(32)},
	}
	for n := 0; n < 8; n++ {
		d := sha256.Sum256([]byte(fmt.Sprintf("algod-rust falcon vector %d", n)))
		out = append(out, named{fmt.Sprintf("seed_sha_%d", n), d[:]})
	}
	return out
}

func messages() []named {
	return []named{
		{"msg_empty", []byte{}},
		{"msg_one_72", []byte{0x72}},
		{"msg_32_count", counter(32)},
		{"msg_64_ff", fill(0xff, 64)},
		{"msg_1000_alt", alternating(1000)},
		{"msg_go_crypto_test", mustHex(goMsgHex)},
	}
}

func fill(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func counter(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func alternating(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		if i%2 == 0 {
			out[i] = 0x55
		} else {
			out[i] = 0xaa
		}
	}
	return out
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }

type negative struct {
	name   string
	sig    []byte
	msg    []byte
	pubkey []byte // nil = the right one
}

// negatives derives the malformed/mismatched cases from one valid triple.
// Order and names are part of the corpus identity (mirrors gen_vectors.rs).
func negatives(sig, msg, otherPubkey []byte) []negative {
	var v []negative
	s := clone(sig)
	s[0] ^= 0x01
	v = append(v, negative{"header_xor_01", s, clone(msg), nil})
	s = clone(sig)
	s[0] = 0xda
	v = append(v, negative{"header_ct", s, clone(msg), nil})
	s = clone(sig)
	s[0] = 0x3a
	v = append(v, negative{"header_salted_bit_clear", s, clone(msg), nil})
	s = clone(sig)
	s[1] = 0x01
	v = append(v, negative{"salt_version_1", s, clone(msg), nil})
	s = clone(sig)
	s[2] ^= 0x01
	v = append(v, negative{"body_xor_01", s, clone(msg), nil})
	v = append(v, negative{"truncated_1", clone(sig[:len(sig)-1]), clone(msg), nil})
	v = append(v, negative{"truncated_half", clone(sig[:len(sig)/2]), clone(msg), nil})
	v = append(v, negative{"trailing_00", append(clone(sig), 0x00), clone(msg), nil})
	v = append(v, negative{"empty", []byte{}, clone(msg), nil})
	v = append(v, negative{"header_only", []byte{0xba}, clone(msg), nil})
	s = make([]byte, 1424)
	s[0] = 0xba
	v = append(v, negative{"oversized_1424", s, clone(msg), nil})
	s = make([]byte, 1423)
	s[0] = 0xba
	v = append(v, negative{"max_len_zeros", s, clone(msg), nil})
	v = append(v, negative{"wrong_pubkey", clone(sig), clone(msg), clone(otherPubkey)})
	m := clone(msg)
	m[0] ^= 0x01
	v = append(v, negative{"wrong_msg", clone(sig), m, nil})
	return v
}

func verifyOK(pubkey, sig, msg []byte) bool {
	var fv crypto.FalconVerifier
	copy(fv.PublicKey[:], pubkey)
	return fv.VerifyBytes(msg, crypto.FalconSignature(sig)) == nil
}

type negInput struct {
	prefix string
	pubkey []byte
	sig    []byte
}

func generate() []byte {
	var sb strings.Builder
	var negInputs []negInput
	msgs := messages()
	for si, sd := range seeds() {
		var seed crypto.FalconSeed
		copy(seed[:], sd.data)
		signer, err := crypto.GenerateFalconSigner(seed)
		if err != nil {
			panic(fmt.Sprintf("%s: keygen: %v", sd.name, err))
		}
		again, _ := crypto.GenerateFalconSigner(seed)
		if again.PublicKey != signer.PublicKey || again.PrivateKey != signer.PrivateKey {
			panic(fmt.Sprintf("%s: keygen is not deterministic", sd.name))
		}
		pk := signer.PublicKey[:]
		fmt.Fprintf(&sb, "{\"kind\":\"key\",\"name\":\"%s\",\"seed\":\"%s\",\"pubkey\":\"%s\",\"privkey\":\"%s\"}\n",
			sd.name, hex.EncodeToString(sd.data), hex.EncodeToString(pk), hex.EncodeToString(signer.PrivateKey[:]))
		for _, m := range msgs {
			sig, err := signer.SignBytes(m.data)
			if err != nil {
				panic(fmt.Sprintf("%s/%s: sign: %v", sd.name, m.name, err))
			}
			sig2, _ := signer.SignBytes(m.data)
			if string(sig2) != string(sig) {
				panic(fmt.Sprintf("%s/%s: signing is not deterministic", sd.name, m.name))
			}
			if !verifyOK(pk, sig, m.data) {
				panic(fmt.Sprintf("%s/%s: self-verify failed", sd.name, m.name))
			}
			if !sig.IsSaltVersionEqual(0) {
				panic(fmt.Sprintf("%s/%s: unexpected salt version", sd.name, m.name))
			}
			ct, err := sig.GetFixedLengthHashableRepresentation()
			if err != nil {
				panic(fmt.Sprintf("%s/%s: CT conversion: %v", sd.name, m.name, err))
			}
			fmt.Fprintf(&sb, "{\"kind\":\"sig\",\"name\":\"%s/%s\",\"seed\":\"%s\",\"msg\":\"%s\",\"sig_compressed\":\"%s\",\"sig_ct\":\"%s\",\"salt_version\":0}\n",
				sd.name, m.name, hex.EncodeToString(sd.data), hex.EncodeToString(m.data), hex.EncodeToString(sig), hex.EncodeToString(ct))
			if m.name == "msg_32_count" && (si == 0 || si == 4) {
				negInputs = append(negInputs, negInput{"neg/" + sd.name + "/" + m.name, clone(pk), clone(sig)})
			}
		}
	}

	msg32 := counter(32)
	for i, in := range negInputs {
		other := negInputs[1-i].pubkey
		for _, n := range negatives(in.sig, msg32, other) {
			pk := in.pubkey
			if n.pubkey != nil {
				pk = n.pubkey
			}
			if verifyOK(pk, n.sig, n.msg) {
				panic(fmt.Sprintf("%s/%s: must be rejected", in.prefix, n.name))
			}
			fmt.Fprintf(&sb, "{\"kind\":\"negative\",\"name\":\"%s/%s\",\"pubkey\":\"%s\",\"msg\":\"%s\",\"sig\":\"%s\",\"expect\":\"reject\"}\n",
				in.prefix, n.name, hex.EncodeToString(pk), hex.EncodeToString(n.msg), hex.EncodeToString(n.sig))
		}
	}

	if !verifyOK(mustHex(goPubkeyHex), mustHex(goSigHex), mustHex(goMsgHex)) {
		panic("go-algorand hard-coded vector must verify")
	}
	fmt.Fprintf(&sb, "{\"kind\":\"verify_only\",\"name\":\"go/crypto_test_falcon_verify\",\"pubkey\":\"%s\",\"msg\":\"%s\",\"sig\":\"%s\",\"expect\":\"accept\"}\n",
		goPubkeyHex, goMsgHex, goSigHex)
	return []byte(sb.String())
}

func repoRoot() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("..", "..")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

func defaultOutPath() string {
	return filepath.Join(repoRoot(), "crates", "core", "algo-falcon", "tests", "fixtures", "falcon", "vectors.jsonl")
}

func goAlgorandPath() string {
	return filepath.Clean(filepath.Join(repoRoot(), "..", "go-algorand"))
}

// verifyGoAlgorandPin exits non-zero unless the go-algorand checkout we link
// against is exactly at expectedGoAlgorandPin with a clean crypto/ tree.
func verifyGoAlgorandPin(path string) error {
	out, err := exec.Command("git", "-C", path, "describe", "--tags", "--exact-match", "HEAD").Output()
	if err != nil {
		rev, _ := exec.Command("git", "-C", path, "rev-parse", "HEAD").Output()
		return fmt.Errorf("go-algorand at %q is not pinned to %s (HEAD=%s); fix with: cd %s && git fetch --tags && git checkout %s, or pass --allow-unpinned",
			path, expectedGoAlgorandPin, strings.TrimSpace(string(rev)), path, expectedGoAlgorandPin)
	}
	if got := strings.TrimSpace(string(out)); got != expectedGoAlgorandPin {
		return fmt.Errorf("go-algorand at %q is on tag %q, expected %q (or pass --allow-unpinned)", path, got, expectedGoAlgorandPin)
	}
	out, err = exec.Command("git", "-C", path, "status", "--porcelain").Output()
	if err != nil {
		return fmt.Errorf("checking %s working tree: %w", path, err)
	}
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if len(line) >= 4 && strings.Contains(line[3:], "crypto/") {
			return fmt.Errorf("go-algorand at %q has uncommitted changes under crypto/ (%s); clean the tree or pass --allow-unpinned", path, strings.TrimSpace(line))
		}
	}
	return nil
}

func main() {
	outPath := flag.String("out", defaultOutPath(), "fixture path to write")
	allowUnpinned := flag.Bool("allow-unpinned", false, "skip the go-algorand pin/clean-tree check")
	flag.Parse()

	if !*allowUnpinned {
		if err := verifyGoAlgorandPin(goAlgorandPath()); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}
	data := generate()
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	f, err := os.Create(*outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	if _, err := w.Write(data); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", *outPath, len(data))
}
