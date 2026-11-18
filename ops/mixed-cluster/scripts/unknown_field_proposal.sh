#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Checks for the opt-in `unknown-field-proposal` negative cases (issues #2394,
# #2398), sourced by ops/mixed-cluster/scripts/negative-conformance.sh and
# ops/mixed-cluster-p2p/scripts/negative-conformance.sh. Pure functions over a
# log file or a report value, so unknown_field_proposal_shell_test.sh can run
# them without a cluster.
#
# The injected payload is a captured honest PP with one key, `zzunk`, that no
# go-algorand struct has. Both implementations must drop it AT DECODE and for
# THAT key (not because of a msgp allocbound, #2427, or a repeated key, #2424),
# and neither disconnects the sender (go's agreement/demux.go
# `tokenizeMessages`; algod-rust's demux.rs `handle_raw_proposal`, #2431).

UFP_KEY=zzunk
UFP_DROP_LINE="dropping proposal that failed to decode"

# ufp_go_dropped <log>: go-algorand logged the decode drop naming the key
# (msgp.ErrNoField prints "Unknown field: zzunk").
ufp_go_dropped() {
    grep -F "$UFP_DROP_LINE" "$1" 2>/dev/null | grep -qF "Unknown field: $UFP_KEY"
}

# ufp_rust_dropped <log>: algod-rust logged the decode drop naming the key
# (rmp_decode's UnknownFieldError: "... decoding stream map with key zzunk").
ufp_rust_dropped() {
    grep -F "$UFP_DROP_LINE" "$1" 2>/dev/null | grep -qF "with key $UFP_KEY"
}

# ufp_rust_decoder_reason <text>: the injector's `rust_decode_error` report
# field is the unknown-key error and not another decode failure.
ufp_rust_decoder_reason() {
    case "$1" in
        *"no matching struct field found"*"with key $UFP_KEY"*) return 0 ;;
        *) return 1 ;;
    esac
}

# ufp_not_disconnected <report `disconnected` value>: the receiver kept the
# injector's connection for the whole observe window ("False" in the report).
ufp_not_disconnected() {
    [ "$1" = "False" ]
}

# ufp_same_block_hash <hash-a> <hash-b>: both non-empty and equal (the
# algod-rust node committed the same block as go at the injected round).
ufp_same_block_hash() {
    [ -n "$1" ] && [ "$1" = "$2" ]
}
