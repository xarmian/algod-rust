#!/bin/bash
# Generate diverse transaction types on the devnet localnet.
# This script runs inside (or via docker exec into) the algod-go container.
# It creates: pay, acfg (ASA create), axfer (opt-in + transfer), afrz,
# appl (app create + call), and keyreg (online) transactions.

set -euo pipefail

ALGOD_DATA="${ALGOD_DATA:-/algod/data}"

echo "=== Diverse Transaction Generator ==="
echo "  ALGOD_DATA: ${ALGOD_DATA}"

# ── Discover accounts ────────────────────────────────────────────
ACCOUNTS=$(goal account list -d "${ALGOD_DATA}" 2>/dev/null | awk '{print $2}')
FROM=$(echo "${ACCOUNTS}" | head -1)
TO=$(echo "${ACCOUNTS}" | tail -1)

if [ -z "${FROM}" ] || [ -z "${TO}" ]; then
    echo "ERROR: Could not discover accounts. Is the localnet running?"
    exit 1
fi

echo "  FROM: ${FROM}"
echo "  TO:   ${TO}"
echo ""

# ── 1. Payment (pay) ────────────────────────────────────────────
echo "[1/9] Sending payment transaction..."
goal clerk send \
    -a 1000000 \
    -f "${FROM}" \
    -t "${TO}" \
    -d "${ALGOD_DATA}" \
    -n "diverse-pay"
echo "  Payment sent."

# ── 2. Create ASA (acfg) ────────────────────────────────────────
echo "[2/9] Creating ASA..."
CREATE_OUTPUT=$(goal asset create \
    --total 1000000 \
    --decimals 0 \
    --unitname TST \
    --name "TestAsset" \
    --creator "${FROM}" \
    --freezer "${FROM}" \
    --clawback "${FROM}" \
    -d "${ALGOD_DATA}" 2>&1)
echo "${CREATE_OUTPUT}"

ASSET_ID=$(echo "${CREATE_OUTPUT}" | grep -o 'Created asset with asset index [0-9]*' | grep -o '[0-9]*')
if [ -z "${ASSET_ID}" ]; then
    echo "ERROR: Could not parse asset ID from output"
    exit 1
fi
echo "  ASA created: asset ID ${ASSET_ID}"

# ── 3. Opt-in to ASA (axfer, self-transfer with 0 amount) ──────
echo "[3/9] Opting in to ASA (account ${TO})..."
goal asset optin \
    --assetid "${ASSET_ID}" \
    --account "${TO}" \
    -d "${ALGOD_DATA}"
echo "  Opt-in complete."

# ── 4. Transfer ASA (axfer) ─────────────────────────────────────
echo "[4/9] Transferring ASA..."
goal asset send \
    --assetid "${ASSET_ID}" \
    --amount 100 \
    --from "${FROM}" \
    --to "${TO}" \
    -d "${ALGOD_DATA}"
echo "  ASA transfer complete."

# ── 5. Freeze ASA (afrz) ────────────────────────────────────────
echo "[5/9] Freezing ASA for account ${TO}..."
goal asset freeze \
    --assetid "${ASSET_ID}" \
    --freezer "${FROM}" \
    --account "${TO}" \
    --freeze \
    -d "${ALGOD_DATA}"
echo "  ASA freeze complete."

# ── 6. Create application (appl) ────────────────────────────────
echo "[6/9] Creating application..."
APP_OUTPUT=$(goal app create \
    --creator "${FROM}" \
    --approval-prog /scripts/approval.teal \
    --clear-prog /scripts/clear.teal \
    --global-byteslices 0 \
    --global-ints 1 \
    --local-byteslices 0 \
    --local-ints 0 \
    -d "${ALGOD_DATA}" 2>&1)
echo "${APP_OUTPUT}"

APP_ID=$(echo "${APP_OUTPUT}" | grep -o 'Created app with app index [0-9]*' | grep -o '[0-9]*')
if [ -z "${APP_ID}" ]; then
    echo "ERROR: Could not parse app ID from output"
    exit 1
fi
echo "  Application created: app ID ${APP_ID}"

# ── 7. Call application (appl) ──────────────────────────────────
echo "[7/9] Calling application ${APP_ID}..."
goal app call \
    --app-id "${APP_ID}" \
    --from "${FROM}" \
    -d "${ALGOD_DATA}"
echo "  Application call complete."

# ── 8. Generate participation key and register online (keyreg) ──
echo "[8/9] Generating participation key for ${FROM}..."

# Get the current round to set participation key validity range
STATUS_OUTPUT=$(goal node status -d "${ALGOD_DATA}" 2>&1)
CURRENT_ROUND=$(echo "${STATUS_OUTPUT}" | grep "Last committed block:" | grep -o '[0-9]*')
if [ -z "${CURRENT_ROUND}" ]; then
    echo "ERROR: Could not determine current round"
    exit 1
fi

FIRST_VALID=${CURRENT_ROUND}
LAST_VALID=$((CURRENT_ROUND + 10000))

echo "  Current round: ${CURRENT_ROUND}"
echo "  Key validity: ${FIRST_VALID} - ${LAST_VALID}"

goal account addpartkey \
    --address "${FROM}" \
    --roundFirstValid "${FIRST_VALID}" \
    --roundLastValid "${LAST_VALID}" \
    -d "${ALGOD_DATA}"
echo "  Participation key generated."

# ── 9. Register online (keyreg with all fields) ─────────────────
echo "[9/9] Registering account online (keyreg)..."
goal account changeonlinestatus \
    --address "${FROM}" \
    --online \
    -d "${ALGOD_DATA}"
echo "  Account registered online."

# ── Done ─────────────────────────────────────────────────────────
echo ""
echo "=== All diverse transactions submitted successfully ==="
echo "  Transactions generated:"
echo "    1. pay      - Payment"
echo "    2. acfg     - ASA create (asset ID ${ASSET_ID})"
echo "    3. axfer    - ASA opt-in"
echo "    4. axfer    - ASA transfer"
echo "    5. afrz     - ASA freeze"
echo "    6. appl     - App create (app ID ${APP_ID})"
echo "    7. appl     - App call"
echo "    8. keyreg   - Participation key generation (no txn)"
echo "    9. keyreg   - Register online"
echo ""
echo "  Total on-chain transactions: 8 (addpartkey does not produce a txn)"
