#!/bin/bash
# Transaction generator sidecar.
# Periodically sends payment transactions to the Go algod devnet
# to ensure blocks contain transactions (not just empty blocks).
#
# This script is designed to run inside the same container as algod
# (mounted as a background script) or in a separate container with
# ALGOD_ADDR set to the algod REST endpoint.

set -e

ALGOD_DATA="${ALGOD_DATA:-/algod/data}"
ALGOD_ADDR="${ALGOD_ADDR:-}"
ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
INTERVAL="${TXN_INTERVAL:-5}"
BATCH_SIZE="${TXN_BATCH_SIZE:-1}"

echo "Transaction generator starting..."
echo "  ALGOD_DATA: ${ALGOD_DATA}"
echo "  Interval:   ${INTERVAL}s"
echo "  Batch size: ${BATCH_SIZE}"

# If ALGOD_ADDR is set, we're running in a separate container.
# Use curl-based REST API approach instead of `goal`.
if [ -n "${ALGOD_ADDR}" ]; then
    echo "  ALGOD_ADDR: ${ALGOD_ADDR}"
    echo "Using REST API mode (curl)..."

    # Wait for algod to be ready
    until curl -sf -H "X-Algo-API-Token: ${ALGOD_TOKEN}" "${ALGOD_ADDR}/v2/status" > /dev/null 2>&1; do
        echo "Waiting for algod at ${ALGOD_ADDR}..."
        sleep 2
    done
    echo "algod is ready at ${ALGOD_ADDR}."

    # In DEV_MODE, we can trigger empty blocks by using /v2/transactions
    # But signing requires private keys. Fall back to goal if data dir available.
    if [ -d "${ALGOD_DATA}" ]; then
        # goal is available but we override algod.net to point to the remote
        echo "Data dir available — overriding algod.net for remote access"
        echo "${ALGOD_ADDR#http://}" > "${ALGOD_DATA}/algod.net"
    fi
fi

# Wait for node to be ready via goal
until goal node status -d "${ALGOD_DATA}" > /dev/null 2>&1; do
    echo "Waiting for algod (via goal)..."
    sleep 2
done

echo "algod is ready. Discovering accounts..."

# Get the first two accounts from the wallet
ACCOUNTS=$(goal account list -d "${ALGOD_DATA}" 2>/dev/null | awk '{print $2}')
FROM=$(echo "${ACCOUNTS}" | head -1)
TO=$(echo "${ACCOUNTS}" | tail -1)

if [ -z "${FROM}" ] || [ -z "${TO}" ]; then
    echo "ERROR: Could not discover accounts"
    echo "NOTE: goal account list requires KMD to be running in the same"
    echo "      container. Use the wrapper entrypoint approach instead."
    exit 1
fi

echo "  FROM: ${FROM}"
echo "  TO:   ${TO}"
echo "Sending transactions every ${INTERVAL}s..."

SEQ=0
while true; do
    for i in $(seq 1 "${BATCH_SIZE}"); do
        SEQ=$((SEQ + 1))
        goal clerk send \
            -a 1000 \
            -f "${FROM}" \
            -t "${TO}" \
            -d "${ALGOD_DATA}" \
            -n "sidecar-txn-${SEQ}" 2>&1 || echo "WARN: txn ${SEQ} failed"
    done
    sleep "${INTERVAL}"
done
