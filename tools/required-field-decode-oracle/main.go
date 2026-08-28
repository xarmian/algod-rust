// Command required-field-decode-oracle is a byte-level parity oracle for
// algod-rust issue #618: it builds the exact hand-rolled msgpack byte
// sequences used by the Rust unit tests in
// crates/core/algo-types/src/transaction.rs (required_field_decode_tests
// module) and feeds them to go-algorand v5.0.0-stable's own generated
// UnmarshalMsg decoders, confirming the real Go decoder accepts/rejects
// each case the same way the Rust port does.
//
// Exit codes: 0 all cases match, 2 a mismatch was found, 1 usage/IO error.
package main

import (
	"fmt"
	"os"

	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/stateproof"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/msgp/msgp"
)

type wantErrSubstr = string

type caseResult struct {
	name       string
	wantAccept bool
	wantErrHas wantErrSubstr // substring expected in the rejection error, ignored if wantAccept
	err        error
}

func main() {
	var results []caseResult

	// ── Transaction.Type / Header.Sender ────────────────────────
	results = append(results, decodeTransaction("transaction_type_omitted_is_rejected", false, "type",
		func(b []byte) []byte {
			b = msgp.AppendMapHeader(b, 1)
			b = msgp.AppendString(b, "snd")
			b = msgp.AppendBytes(b, bytesOf(32, 7))
			return b
		}))
	results = append(results, decodeTransaction("transaction_type_explicit_empty_string_is_rejected", false, "type",
		func(b []byte) []byte {
			b = msgp.AppendMapHeader(b, 2)
			b = msgp.AppendString(b, "type")
			b = msgp.AppendString(b, "")
			b = msgp.AppendString(b, "snd")
			b = msgp.AppendBytes(b, bytesOf(32, 7))
			return b
		}))
	results = append(results, decodeTransaction("transaction_sender_omitted_is_rejected", false, "snd",
		func(b []byte) []byte {
			b = msgp.AppendMapHeader(b, 1)
			b = msgp.AppendString(b, "type")
			b = msgp.AppendString(b, "pay")
			return b
		}))
	results = append(results, decodeTransaction("transaction_sender_explicit_zero_is_rejected", false, "snd",
		func(b []byte) []byte {
			b = msgp.AppendMapHeader(b, 2)
			b = msgp.AppendString(b, "type")
			b = msgp.AppendString(b, "pay")
			b = msgp.AppendString(b, "snd")
			b = msgp.AppendBytes(b, bytesOf(32, 0))
			return b
		}))
	results = append(results, decodeTransaction("transaction_with_type_and_sender_present_decodes_successfully", true, "",
		func(b []byte) []byte {
			b = msgp.AppendMapHeader(b, 2)
			b = msgp.AppendString(b, "type")
			b = msgp.AppendString(b, "pay")
			b = msgp.AppendString(b, "snd")
			b = msgp.AppendBytes(b, bytesOf(32, 7))
			return b
		}))

	// ── MultisigSig.{Version,Threshold,Subsigs} ─────────────────
	subsigBytes := func(b []byte) []byte {
		b = msgp.AppendArrayHeader(b, 1)
		b = msgp.AppendMapHeader(b, 1)
		b = msgp.AppendString(b, "pk")
		b = msgp.AppendBytes(b, bytesOf(32, 9))
		return b
	}
	results = append(results, decodeMultisig("multisig_version_omitted_is_rejected", false, "field: v",
		func(b []byte) []byte {
			b = msgp.AppendMapHeader(b, 2)
			b = msgp.AppendString(b, "thr")
			b = msgp.AppendUint64(b, 1)
			b = msgp.AppendString(b, "subsig")
			b = subsigBytes(b)
			return b
		}))
	results = append(results, decodeMultisig("multisig_version_explicit_zero_is_rejected", false, "field: v",
		func(b []byte) []byte {
			b = msgp.AppendMapHeader(b, 3)
			b = msgp.AppendString(b, "v")
			b = msgp.AppendUint64(b, 0)
			b = msgp.AppendString(b, "thr")
			b = msgp.AppendUint64(b, 1)
			b = msgp.AppendString(b, "subsig")
			b = subsigBytes(b)
			return b
		}))
	results = append(results, decodeMultisig("multisig_threshold_omitted_is_rejected", false, "field: thr",
		func(b []byte) []byte {
			b = msgp.AppendMapHeader(b, 2)
			b = msgp.AppendString(b, "v")
			b = msgp.AppendUint64(b, 1)
			b = msgp.AppendString(b, "subsig")
			b = subsigBytes(b)
			return b
		}))
	results = append(results, decodeMultisig("multisig_subsig_omitted_is_rejected", false, "field: subsig",
		func(b []byte) []byte {
			b = msgp.AppendMapHeader(b, 2)
			b = msgp.AppendString(b, "v")
			b = msgp.AppendUint64(b, 1)
			b = msgp.AppendString(b, "thr")
			b = msgp.AppendUint64(b, 1)
			return b
		}))
	results = append(results, decodeMultisig("multisig_with_all_required_fields_decodes_successfully", true, "",
		func(b []byte) []byte {
			b = msgp.AppendMapHeader(b, 3)
			b = msgp.AppendString(b, "v")
			b = msgp.AppendUint64(b, 1)
			b = msgp.AppendString(b, "thr")
			b = msgp.AppendUint64(b, 1)
			b = msgp.AppendString(b, "subsig")
			b = subsigBytes(b)
			return b
		}))

	// ── basics.Participant.PK ───────────────────────────────────
	verifierBytes := func(b []byte) []byte {
		b = msgp.AppendMapHeader(b, 1)
		b = msgp.AppendString(b, "cmt")
		b = msgp.AppendBytes(b, bytesOf(64, 3))
		return b
	}
	results = append(results, decodeParticipant("participant_pk_omitted_is_rejected", false, "field: p",
		func(b []byte) []byte {
			b = msgp.AppendMapHeader(b, 1)
			b = msgp.AppendString(b, "w")
			b = msgp.AppendUint64(b, 5)
			return b
		}))
	results = append(results, decodeParticipant("participant_pk_explicit_zero_verifier_is_rejected", false, "field: p",
		func(b []byte) []byte {
			b = msgp.AppendMapHeader(b, 1)
			b = msgp.AppendString(b, "p")
			b = msgp.AppendMapHeader(b, 0)
			return b
		}))
	results = append(results, decodeParticipant("participant_with_pk_decodes_successfully", true, "",
		func(b []byte) []byte {
			b = msgp.AppendMapHeader(b, 1)
			b = msgp.AppendString(b, "p")
			b = verifierBytes(b)
			return b
		}))

	// ── stateproof.Reveal.Part ──────────────────────────────────
	results = append(results, decodeReveal("reveal_part_omitted_is_rejected", false, "field: p",
		func(b []byte) []byte {
			return msgp.AppendMapHeader(b, 0)
		}))
	results = append(results, decodeReveal("reveal_part_with_zero_pk_is_rejected", false, "field: p",
		func(b []byte) []byte {
			b = msgp.AppendMapHeader(b, 1)
			b = msgp.AppendString(b, "p")
			b = msgp.AppendMapHeader(b, 1)
			b = msgp.AppendString(b, "w")
			b = msgp.AppendUint64(b, 1)
			return b
		}))
	results = append(results, decodeReveal("reveal_with_part_decodes_successfully", true, "",
		func(b []byte) []byte {
			b = msgp.AppendMapHeader(b, 1)
			b = msgp.AppendString(b, "p")
			b = msgp.AppendMapHeader(b, 1)
			b = msgp.AppendString(b, "p")
			b = verifierBytes(b)
			return b
		}))

	mismatches := 0
	for _, r := range results {
		accepted := r.err == nil
		ok := accepted == r.wantAccept
		if ok && !r.wantAccept && r.wantErrHas != "" {
			ok = containsSubstr(r.err.Error(), r.wantErrHas)
		}
		status := "OK"
		if !ok {
			status = "MISMATCH"
			mismatches++
		}
		fmt.Printf("[%s] %-65s accept=%v err=%v\n", status, r.name, accepted, r.err)
	}

	if mismatches > 0 {
		fmt.Printf("\n%d/%d cases mismatched go-algorand v5.0.0-stable's real decoder\n", mismatches, len(results))
		os.Exit(2)
	}
	fmt.Printf("\nall %d cases match go-algorand v5.0.0-stable's real decoder\n", len(results))
}

func decodeTransaction(name string, wantAccept bool, wantErrHas string, build func([]byte) []byte) caseResult {
	buf := build(nil)
	var t transactions.Transaction
	_, err := t.UnmarshalMsg(buf)
	return caseResult{name: name, wantAccept: wantAccept, wantErrHas: wantErrHas, err: err}
}

func decodeMultisig(name string, wantAccept bool, wantErrHas string, build func([]byte) []byte) caseResult {
	buf := build(nil)
	var s crypto.MultisigSig
	_, err := s.UnmarshalMsg(buf)
	return caseResult{name: name, wantAccept: wantAccept, wantErrHas: wantErrHas, err: err}
}

func decodeParticipant(name string, wantAccept bool, wantErrHas string, build func([]byte) []byte) caseResult {
	buf := build(nil)
	var p basics.Participant
	_, err := p.UnmarshalMsg(buf)
	return caseResult{name: name, wantAccept: wantAccept, wantErrHas: wantErrHas, err: err}
}

func decodeReveal(name string, wantAccept bool, wantErrHas string, build func([]byte) []byte) caseResult {
	buf := build(nil)
	var r stateproof.Reveal
	_, err := r.UnmarshalMsg(buf)
	return caseResult{name: name, wantAccept: wantAccept, wantErrHas: wantErrHas, err: err}
}

func bytesOf(n int, fill byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return b
}

func containsSubstr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
