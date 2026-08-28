// cert-authenticate: authenticate algod-rust-observed certificates under
// go-algorand's OWN `agreement.Certificate.Authenticate`.
//
// Issue #470 §2 (Epic 42c, "Rust → Go" direction). `algo-cert-crossverify`
// already verifies Go-produced certificates under algod-rust's verifier.
// This tool closes the loop: it takes the certificates committed by the
// mixed cluster during rounds where the **Rust** node was voting and runs
// them through go-algorand v5.0.0-stable's verifier, so a certificate
// containing Rust votes is proven to authenticate under both
// implementations.
//
// # Input
//
// A JSON file written by `algo-cert-crossverify --export-go-input`:
//
//	{
//	  "rust_account": "GACN…",
//	  "rounds": [
//	    {
//	      "round": 412,
//	      "block_cert_msgpack_b64": "…",   // raw {block,cert} envelope
//	      "rust_block_digest_hex": "…",    // Rust's digest, for comparison
//	      "consensus_version": "future",
//	      "params_round": 410, "balance_round": 92, "seed_round": 411,
//	      "seed_b64": "…", "circulation": 4000000000000,
//	      "accounts": [ {"address": "…", "micro_algos": …, …} ],
//	      "rust_vote_present": true
//	    }
//	  ]
//	}
//
// The ledger facts come from the Rust node's own ledger. That is
// deliberate: if Rust's view of the seed / stake / circulation diverged
// from what the votes actually committed to, the Go verifier rejects the
// certificate and this tool fails. Go recomputes the block digest itself
// from the raw msgpack, so `rust_block_digest_hex` is compared rather
// than trusted (a mismatch is reported as its own outcome).
//
// # Output
//
// A JSON report to `--out` (and a one-line summary on stdout). Exit
// codes:
//
//	0 — every round authenticated (and the --require-rust-votes gate,
//	    if any, was satisfied)
//	1 — usage / IO error
//	2 — at least one round failed to authenticate, or too few rounds
//	    carried a Rust vote
//
// # Building
//
// go-algorand's `crypto` package links a vendored libsodium fork via
// cgo, so `go build` needs `make libsodium` to have been run in the
// go-algorand checkout first (same constraint as every other Go helper
// in `tools/`). `run-in-docker.sh` next to this file does that inside a
// `golang:1.25-bookworm` container, which is also what CI does — see
// `.github/workflows/algokey-e2e.yml` for the apt packages required.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/algorand/go-algorand/agreement"
	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/crypto/merklesignature"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/rpcs"
)

// ── input schema (mirrors algo_cert_crossverify::GoVerifyInput) ─────────

type goVerifyAccount struct {
	Address         string `json:"address"`
	MicroAlgos      uint64 `json:"micro_algos"`
	VoteIDB64       string `json:"vote_id_b64"`
	SelectionIDB64  string `json:"selection_id_b64"`
	VoteFirstValid  uint64 `json:"vote_first_valid"`
	VoteLastValid   uint64 `json:"vote_last_valid"`
	VoteKeyDilution uint64 `json:"vote_key_dilution"`
	IncentiveEligible bool `json:"incentive_eligible"`
	LastProposed    uint64 `json:"last_proposed"`
	LastHeartbeat   uint64 `json:"last_heartbeat"`
	StateProofIDB64 string `json:"state_proof_id_b64"`
}

type goVerifyRound struct {
	Round               uint64            `json:"round"`
	BlockCertMsgpackB64 string            `json:"block_cert_msgpack_b64"`
	RustBlockDigestHex  string            `json:"rust_block_digest_hex"`
	ConsensusVersion    string            `json:"consensus_version"`
	ParamsRound         uint64            `json:"params_round"`
	BalanceRound        uint64            `json:"balance_round"`
	SeedRound           uint64            `json:"seed_round"`
	SeedB64             string            `json:"seed_b64"`
	Circulation         uint64            `json:"circulation"`
	Accounts            []goVerifyAccount `json:"accounts"`
	RustVotePresent     bool              `json:"rust_vote_present"`
}

type goVerifyInput struct {
	RustAccount *string         `json:"rust_account"`
	Rounds      []goVerifyRound `json:"rounds"`
}

// ── output schema ───────────────────────────────────────────────────────

type roundResult struct {
	Round           uint64 `json:"round"`
	Outcome         string `json:"outcome"`
	Error           string `json:"error,omitempty"`
	Votes           int    `json:"votes"`
	CertRound       uint64 `json:"cert_round"`
	CertPeriod      uint64 `json:"cert_period"`
	GoBlockDigest   string `json:"go_block_digest_hex"`
	RustBlockDigest string `json:"rust_block_digest_hex"`
	DigestsMatch    bool   `json:"digests_match"`
	RustVotePresent bool   `json:"rust_vote_present"`
}

type report struct {
	GoAlgorandPin      string        `json:"go_algorand_pin"`
	RustAccount        string        `json:"rust_account,omitempty"`
	RoundsTotal        int           `json:"rounds_total"`
	RoundsOK           int           `json:"rounds_ok"`
	RoundsFailed       int           `json:"rounds_failed"`
	RoundsWithRustVote int           `json:"rounds_with_rust_vote"`
	RequireRustVotes   int           `json:"require_rust_votes"`
	Results            []roundResult `json:"results"`
}

// expectedGoAlgorandPin documents which go-algorand this helper is meant
// to be built against; it is recorded in the report so a stale build is
// visible in the artifact. The pin is enforced by the caller (the docker
// runner checks out this tag).
const expectedGoAlgorandPin = "v5.0.0-stable"

// ── the LedgerReader Go's verifier will consult ─────────────────────────

// factLedger answers exactly the questions `unauthenticatedBundle.verify`
// asks while authenticating ONE round's certificate, from the facts the
// Rust exporter recorded. Any question outside that round is an error
// rather than a plausible-looking zero — a silently wrong Circulation or
// Seed would turn a real divergence into a false pass.
type factLedger struct {
	rec      goVerifyRound
	params   config.ConsensusParams
	seed     committee.Seed
	accounts map[basics.Address]basics.OnlineAccountData
}

func newFactLedger(rec goVerifyRound) (*factLedger, error) {
	params, ok := config.Consensus[protocol.ConsensusVersion(rec.ConsensusVersion)]
	if !ok {
		return nil, fmt.Errorf("unknown consensus version %q — is go-algorand newer/older than the cluster?", rec.ConsensusVersion)
	}

	seedBytes, err := base64.StdEncoding.DecodeString(rec.SeedB64)
	if err != nil {
		return nil, fmt.Errorf("decoding seed_b64: %w", err)
	}
	if len(seedBytes) != len(committee.Seed{}) {
		return nil, fmt.Errorf("seed is %d bytes, want %d", len(seedBytes), len(committee.Seed{}))
	}
	var seed committee.Seed
	copy(seed[:], seedBytes)

	accounts := make(map[basics.Address]basics.OnlineAccountData, len(rec.Accounts))
	for _, a := range rec.Accounts {
		addr, err := basics.UnmarshalChecksumAddress(a.Address)
		if err != nil {
			return nil, fmt.Errorf("account %q: %w", a.Address, err)
		}
		oad, err := a.toOnlineAccountData()
		if err != nil {
			return nil, fmt.Errorf("account %q: %w", a.Address, err)
		}
		accounts[addr] = oad
	}

	return &factLedger{rec: rec, params: params, seed: seed, accounts: accounts}, nil
}

func (a goVerifyAccount) toOnlineAccountData() (basics.OnlineAccountData, error) {
	var oad basics.OnlineAccountData

	voteID, err := base64.StdEncoding.DecodeString(a.VoteIDB64)
	if err != nil {
		return oad, fmt.Errorf("vote_id_b64: %w", err)
	}
	if len(voteID) != len(crypto.OneTimeSignatureVerifier{}) {
		return oad, fmt.Errorf("vote_id is %d bytes, want %d", len(voteID), len(crypto.OneTimeSignatureVerifier{}))
	}
	selectionID, err := base64.StdEncoding.DecodeString(a.SelectionIDB64)
	if err != nil {
		return oad, fmt.Errorf("selection_id_b64: %w", err)
	}
	if len(selectionID) != len(crypto.VRFVerifier{}) {
		return oad, fmt.Errorf("selection_id is %d bytes, want %d", len(selectionID), len(crypto.VRFVerifier{}))
	}
	stateProofID, err := base64.StdEncoding.DecodeString(a.StateProofIDB64)
	if err != nil {
		return oad, fmt.Errorf("state_proof_id_b64: %w", err)
	}
	if len(stateProofID) != len(merklesignature.Commitment{}) {
		return oad, fmt.Errorf("state_proof_id is %d bytes, want %d", len(stateProofID), len(merklesignature.Commitment{}))
	}

	oad.MicroAlgosWithRewards = basics.MicroAlgos{Raw: a.MicroAlgos}
	copy(oad.VoteID[:], voteID)
	copy(oad.SelectionID[:], selectionID)
	copy(oad.StateProofID[:], stateProofID)
	oad.VoteFirstValid = basics.Round(a.VoteFirstValid)
	oad.VoteLastValid = basics.Round(a.VoteLastValid)
	oad.VoteKeyDilution = a.VoteKeyDilution
	oad.IncentiveEligible = a.IncentiveEligible
	oad.LastProposed = basics.Round(a.LastProposed)
	oad.LastHeartbeat = basics.Round(a.LastHeartbeat)
	return oad, nil
}

func (l *factLedger) NextRound() basics.Round { return basics.Round(l.rec.Round + 1) }

func (l *factLedger) Wait(basics.Round) chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func (l *factLedger) Seed(r basics.Round) (committee.Seed, error) {
	if uint64(r) != l.rec.SeedRound {
		return committee.Seed{}, fmt.Errorf("Seed(%d): exporter only recorded the seed for round %d", r, l.rec.SeedRound)
	}
	return l.seed, nil
}

func (l *factLedger) LookupAgreement(r basics.Round, addr basics.Address) (basics.OnlineAccountData, error) {
	if uint64(r) != l.rec.BalanceRound {
		return basics.OnlineAccountData{}, fmt.Errorf("LookupAgreement(%d, %s): exporter only recorded balances for round %d", r, addr, l.rec.BalanceRound)
	}
	oad, ok := l.accounts[addr]
	if !ok {
		return basics.OnlineAccountData{}, fmt.Errorf("LookupAgreement(%d, %s): no exported record — the cert names a voter the exporter did not see", r, addr)
	}
	return oad, nil
}

func (l *factLedger) Circulation(rnd basics.Round, voteRnd basics.Round) (basics.MicroAlgos, error) {
	if uint64(rnd) != l.rec.BalanceRound || uint64(voteRnd) != l.rec.Round {
		return basics.MicroAlgos{}, fmt.Errorf("Circulation(%d, %d): exporter only recorded (%d, %d)", rnd, voteRnd, l.rec.BalanceRound, l.rec.Round)
	}
	return basics.MicroAlgos{Raw: l.rec.Circulation}, nil
}

func (l *factLedger) LookupDigest(r basics.Round) (crypto.Digest, error) {
	// Certificate authentication never needs a historical entry digest —
	// that path is for seed derivation inside a real ledger. Fail loudly
	// rather than returning a zero digest that could mask a bug.
	return crypto.Digest{}, fmt.Errorf("LookupDigest(%d) is not available in the exported facts", r)
}

func (l *factLedger) ConsensusParams(r basics.Round) (config.ConsensusParams, error) {
	if uint64(r) != l.rec.ParamsRound {
		return config.ConsensusParams{}, fmt.Errorf("ConsensusParams(%d): exporter only recorded round %d", r, l.rec.ParamsRound)
	}
	return l.params, nil
}

func (l *factLedger) ConsensusVersion(r basics.Round) (protocol.ConsensusVersion, error) {
	if uint64(r) != l.rec.ParamsRound {
		return "", fmt.Errorf("ConsensusVersion(%d): exporter only recorded round %d", r, l.rec.ParamsRound)
	}
	return protocol.ConsensusVersion(l.rec.ConsensusVersion), nil
}

// authenticateRound runs one exported round through go-algorand's own
// certificate verifier. `avv` is shared across rounds by the caller.
func authenticateRound(rec goVerifyRound, avv *agreement.AsyncVoteVerifier) roundResult {
	res := roundResult{
		Round:           rec.Round,
		RustBlockDigest: rec.RustBlockDigestHex,
		RustVotePresent: rec.RustVotePresent,
	}

	raw, err := base64.StdEncoding.DecodeString(rec.BlockCertMsgpackB64)
	if err != nil {
		res.Outcome, res.Error = "decode_failed", fmt.Sprintf("block_cert_msgpack_b64: %v", err)
		return res
	}

	var bc rpcs.EncodedBlockCert
	if err := protocol.Decode(raw, &bc); err != nil {
		res.Outcome, res.Error = "decode_failed", fmt.Sprintf("decoding EncodedBlockCert: %v", err)
		return res
	}

	res.Votes = len(bc.Certificate.Votes)
	res.CertRound = uint64(bc.Certificate.Round)
	res.CertPeriod = uint64(bc.Certificate.Period)

	goDigest := bc.Block.Digest()
	res.GoBlockDigest = hex.EncodeToString(goDigest[:])
	res.DigestsMatch = res.GoBlockDigest == rec.RustBlockDigestHex
	if !res.DigestsMatch {
		// Report this distinctly: it is a codec/hashing divergence
		// between the two implementations, not a consensus failure, and
		// `Authenticate` would only say "wrong hash".
		res.Outcome = "digest_mismatch"
		res.Error = fmt.Sprintf("Go computed block digest %s, Rust reported %s", res.GoBlockDigest, rec.RustBlockDigestHex)
		return res
	}

	ledger, err := newFactLedger(rec)
	if err != nil {
		res.Outcome, res.Error = "ledger_facts_invalid", err.Error()
		return res
	}

	if err := bc.Certificate.Authenticate(bc.Block, ledger, avv); err != nil {
		res.Outcome, res.Error = "authenticate_failed", err.Error()
		return res
	}
	res.Outcome = "ok"
	return res
}

func run() int {
	inPath := flag.String("input", "", "JSON bundle from `algo-cert-crossverify --export-go-input` (required)")
	outPath := flag.String("out", "", "Write the JSON report here (default: stdout only)")
	requireRustVotes := flag.Int("require-rust-votes", 0, "Fail unless at least N of the rounds carry a vote from the Rust account (0 = disabled)")
	flag.Parse()

	if *inPath == "" {
		fmt.Fprintln(os.Stderr, "error: --input is required")
		flag.Usage()
		return 1
	}

	blob, err := os.ReadFile(*inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", *inPath, err)
		return 1
	}
	var input goVerifyInput
	if err := json.Unmarshal(blob, &input); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing %s: %v\n", *inPath, err)
		return 1
	}
	if len(input.Rounds) == 0 {
		fmt.Fprintf(os.Stderr, "error: %s contains no rounds — nothing to verify\n", *inPath)
		return 1
	}

	// A nil verification pool makes MakeAsyncVoteVerifier allocate its
	// own backlog pool, which is what we want for a one-shot tool.
	avv := agreement.MakeAsyncVoteVerifier(nil)
	defer avv.Quit()

	rep := report{
		GoAlgorandPin:    expectedGoAlgorandPin,
		RoundsTotal:      len(input.Rounds),
		RequireRustVotes: *requireRustVotes,
	}
	if input.RustAccount != nil {
		rep.RustAccount = *input.RustAccount
	}

	for _, rec := range input.Rounds {
		res := authenticateRound(rec, avv)
		rep.Results = append(rep.Results, res)
		if res.Outcome == "ok" {
			rep.RoundsOK++
		} else {
			rep.RoundsFailed++
			fmt.Printf("FAIL round=%d outcome=%s: %s\n", res.Round, res.Outcome, res.Error)
		}
		if res.RustVotePresent {
			rep.RoundsWithRustVote++
		}
	}

	if *outPath != "" {
		encoded, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: encoding report: %v\n", err)
			return 1
		}
		if err := os.WriteFile(*outPath, append(encoded, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", *outPath, err)
			return 1
		}
	}

	fmt.Printf("cert-authenticate (go-algorand %s): rounds=%d ok=%d failed=%d rust_vote_rounds=%d\n",
		rep.GoAlgorandPin, rep.RoundsTotal, rep.RoundsOK, rep.RoundsFailed, rep.RoundsWithRustVote)

	if rep.RoundsFailed > 0 {
		return 2
	}
	if *requireRustVotes > 0 && rep.RoundsWithRustVote < *requireRustVotes {
		fmt.Printf("FAIL: only %d of %d certificates carry a Rust vote; wanted at least %d\n",
			rep.RoundsWithRustVote, rep.RoundsTotal, *requireRustVotes)
		return 2
	}
	return 0
}

func main() { os.Exit(run()) }
