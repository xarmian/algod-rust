#!/usr/bin/env bash
# Entrypoint for the algod-go-vfuture capture target (issue #548).
#
# The stock algorand/algod image entrypoint (docker/files/run/run.sh in
# go-algorand) only copies a fixed allowlist of /etc/algorand/* files
# (config.json, algod.token, algod.admin.token, logging.config) into the
# node's data directory, with no hook for a consensus.json override. We
# need one here (config.ConfigurableConsensusProtocolsFilename, loaded by
# cmd/algod/main.go at daemon startup) to shrink MaxTxnBytesPerBlock for
# the "future" protocol so a handful of payment transactions can push a
# block over the 50%-full threshold that makes CongestionTax non-zero
# (data/bookkeeping/block.go's NextCongestionTax) — flooding the real 5MiB
# default would take thousands of transactions per round.
#
# So this script drives `goal network create` + the consensus.json copy
# directly instead of relying on run.sh's automatic flow. See
# docs/DEV_WORKFLOW.md -> "vFuture Fixture Capture".
set -euo pipefail

ALGORAND_DATA="${ALGORAND_DATA:-/algod/data}"
NETROOT="$(dirname "$ALGORAND_DATA")"

mkdir -p "$NETROOT"

if [ ! -f "$NETROOT/network.json" ]; then
    goal network create --noclean -n vfuture -r "$NETROOT" -t /etc/algorand/template.json

    # config.ConfigurableConsensusProtocolsFilename — must land in the
    # node's own data dir before algod starts (cmd/algod/main.go calls
    # config.LoadConfigurableConsensusProtocols(dataDir) at boot).
    cp /etc/algorand/vfuture-consensus.json "$ALGORAND_DATA/consensus.json"

    # The template's generated config.json defaults EndpointAddress to a
    # loopback address with an ephemeral port; without this the REST API
    # is unreachable from outside the container (stock run.sh does the
    # same override via configure_data_dir(), which we bypass above).
    algocfg -d "$ALGORAND_DATA" set -p EndpointAddress -v "0.0.0.0:8080"

    if [ -n "${TOKEN:-}" ]; then
        echo "$TOKEN" >"$ALGORAND_DATA/algod.token"
    fi
    if [ -n "${ADMIN_TOKEN:-}" ]; then
        echo "$ADMIN_TOKEN" >"$ALGORAND_DATA/algod.admin.token"
    fi
fi

goal network start -r "$NETROOT"

# Keep the container alive with useful output, same convention as the
# stock run.sh's start_private_network().
tail -f "$ALGORAND_DATA/node.log"
