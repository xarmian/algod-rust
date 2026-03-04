#!/bin/bash
# Transaction generator sidecar.
# Periodically sends payment transactions to the Go algod devnet
# to ensure blocks contain transactions (not just empty blocks).

set -e

ALGOD_DATA="${ALGOD_DATA:-/algod/data}"
INTERVAL="${TXN_INTERVAL:-5}"
BATCH_SIZE="${TXN_BATCH_SIZE:-1}"

echo "Transaction generator starting..."
echo "  ALGOD_DATA: ${ALGOD_DATA}"
echo "  Interval:   ${INTERVAL}s"
echo "  Batch size: ${BATCH_SIZE}"

# Wait for node to be ready (goal will talk to the local node via data dir)
until goal node status -d "${ALGOD_DATA}" > /dev/null 2>&1; do
    echo "Waiting for algod..."
    sleep 2
done

echo "algod is ready. Discovering accounts..."

# Get the first two accounts from the wallet
ACCOUNTS=$(goal account list -d "${ALGOD_DATA}" 2>/dev/null | awk '{print $2}')
FROM=$(echo "${ACCOUNTS}" | head -1)
TO=$(echo "${ACCOUNTS}" | tail -1)

if [ -z "${FROM}" ] || [ -z "${TO}" ]; then
    echo "ERROR: Could not discover accounts"
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
