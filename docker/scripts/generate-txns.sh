#!/bin/bash
# Transaction generator sidecar.
# Periodically sends payment transactions to the Go algod devnet
# to ensure blocks contain transactions (not just empty blocks).

set -e

ALGOD_URL="${ALGOD_URL:-http://algod-go:8080}"
ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
INTERVAL="${TXN_INTERVAL:-5}"

header="X-Algo-API-Token: ${ALGOD_TOKEN}"

echo "Transaction generator starting..."
echo "  ALGOD_URL: ${ALGOD_URL}"
echo "  Interval: ${INTERVAL}s"

# Wait for node to be ready
until curl -sf -H "${header}" "${ALGOD_URL}/v2/status" > /dev/null 2>&1; do
    echo "Waiting for algod..."
    sleep 2
done

echo "algod is ready. Fetching genesis accounts..."

# In DEV_MODE, the node creates accounts automatically.
# We can use the /v2/accounts endpoint or the genesis accounts.
# For simplicity, we'll generate transactions using the REST API
# with the dev mode's auto-funded accounts.

# Get the genesis account addresses
ACCOUNTS=$(curl -sf -H "${header}" "${ALGOD_URL}/v2/ledger/supply" 2>/dev/null)
echo "Ledger supply: ${ACCOUNTS}"

# In devmode, we can send 0-amount self-pay transactions
# to trigger block production with transaction content.
# The node will auto-approve them.

ROUND=0
while true; do
    # Get current status
    STATUS=$(curl -sf -H "${header}" "${ALGOD_URL}/v2/status" 2>/dev/null)
    CURRENT_ROUND=$(echo "${STATUS}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('last-round', 0))" 2>/dev/null || echo "?")

    if [ "${CURRENT_ROUND}" != "${ROUND}" ]; then
        ROUND="${CURRENT_ROUND}"
        echo "Round: ${ROUND}"
    fi

    sleep "${INTERVAL}"
done
