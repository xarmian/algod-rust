#!/bin/bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Wrapper entrypoint for go-relay that starts algod normally and then
# runs the transaction generator in the background.
#
# This avoids the cross-container KMD access problem: `goal clerk send`
# needs both algod and KMD running in the same container.

# Start algod via the normal entrypoint (in background)
/node/run/run.sh &
ALGOD_PID=$!

# Wait for algod to be ready
ALGOD_DATA="${ALGOD_DATA:-/algod/data}"
until goal node status -d "${ALGOD_DATA}" > /dev/null 2>&1; do
    echo "[relay-with-txns] Waiting for algod..."
    sleep 2
done
echo "[relay-with-txns] algod is ready."

# Discover accounts
ACCOUNTS=$(goal account list -d "${ALGOD_DATA}" 2>/dev/null | awk '{print $2}')
FROM=$(echo "${ACCOUNTS}" | head -1)
TO=$(echo "${ACCOUNTS}" | tail -1)

if [ -z "${FROM}" ] || [ -z "${TO}" ]; then
    echo "[relay-with-txns] ERROR: Could not discover accounts"
    wait ${ALGOD_PID}
    exit 1
fi

echo "[relay-with-txns] FROM: ${FROM}"
echo "[relay-with-txns] TO:   ${TO}"

INTERVAL="${TXN_INTERVAL:-5}"
BATCH_SIZE="${TXN_BATCH_SIZE:-1}"
echo "[relay-with-txns] Sending ${BATCH_SIZE} txn(s) every ${INTERVAL}s..."

SEQ=0
while kill -0 ${ALGOD_PID} 2>/dev/null; do
    for i in $(seq 1 "${BATCH_SIZE}"); do
        SEQ=$((SEQ + 1))
        goal clerk send \
            -a 1000 \
            -f "${FROM}" \
            -t "${TO}" \
            -d "${ALGOD_DATA}" \
            -n "sidecar-txn-${SEQ}" 2>&1 || echo "[relay-with-txns] WARN: txn ${SEQ} failed"
    done
    sleep "${INTERVAL}"
done

wait ${ALGOD_PID}
