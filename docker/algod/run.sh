#!/usr/bin/env bash
# Copyright (C) 2019-2026 Algorand Foundation Ltd.
# Modifications Copyright (C) 2026 Algod DAO
# This file is part of algod-rust, a modified work based on go-algorand
# (https://github.com/algorand/go-algorand).
#
# algod-rust is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# algod-rust is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Container entrypoint of the algod-rust `algod` image (issue #1991): the
# counterpart of go-algorand's docker/files/run/run.sh, honouring the same
# environment variables, /etc/algorand files and data-directory layout so that
# `algorand/algod` users can switch by changing only the image name.
#
# Differences from go's script (see docs/DOCKER_MIGRATION.md):
#   * `algocfg` flags come after the sub-command (`algocfg set -p K -v V -d .`);
#   * NODE_EXPORTER is not configured (algod-rust has none);
#   * telemetry options are accepted and ignored (diagcfg is a no-op);
#   * START_KMD=1 runs `kmd serve` directly (`goal kmd start` is not ported);
#   * private networks (no NETWORK) need `goal network create`, which is not
#     ported yet (issue #1993) -- the script says so and exits 1;
#   * algod is `exec`ed so that `docker stop`'s SIGTERM reaches it.
#
# The script is also `source`d by its shell test (docker/algod/run_sh_test.sh),
# which replaces `exec_algod` / `start_kmd`; `main` only runs when executed.

set -e

: "${ALGORAND_DATA:=/algod/data}"
: "${ALGOD_PORT:=8080}"
: "${KMD_PORT:=7833}"
GENESIS_DIR="${GENESIS_DIR:-/node/run/genesis}"
ETC_DIR="${ETC_DIR:-/etc/algorand}"
CATCHUP_DELAY="${CATCHUP_DELAY:-5}"

if [ "$ALGORAND_DATA" != "/algod/data" ] && [ -z "${ALGOD_ENTRYPOINT_TEST:-}" ]; then
  echo "Do not override 'ALGORAND_DATA' environment variable."
  exit 1
fi

if [ "$DEBUG" = "1" ]; then
  set -x
fi

set_or_not() {
  if [ -n "$1" ]; then echo "Set"; else echo "Not Set"; fi
}

die() {
  echo "$*" >&2
  exit 1
}

# To allow mounting the data directory we need to change permissions to our
# algorand user. The script is initially run as root in order to change them,
# afterwards it is re-launched as the algorand user (gosu replaces the process,
# so signals keep reaching the final algod).
drop_privileges() {
  if [ "$(id -u)" = '0' ] && [ -z "${ALGOD_ENTRYPOINT_TEST:-}" ]; then
    chown -R algorand:algorand "$ALGORAND_DATA"
    exec gosu algorand "$(readlink -f "$0")" "$@"
  fi
}

####################
# Helper functions #
####################

catchup() {
  sleep "$CATCHUP_DELAY"
  goal node catchup --force --min 1000000
}

exec_algod() {
  exec algod "$@"
}

start_kmd() {
  if [ "$START_KMD" = "1" ]; then
    kmd serve -d "$ALGORAND_DATA/kmd-v0.5" -a "0.0.0.0:${KMD_PORT}" --allow-origin '*'
  fi
}

configure_data_dir() {
  cd "$ALGORAND_DATA"

  # check for config file overrides.
  if [ -f "$ETC_DIR/config.json" ]; then
    cp "$ETC_DIR/config.json" config.json
  fi
  if [ -f "$ETC_DIR/algod.token" ]; then
    cp "$ETC_DIR/algod.token" algod.token
  fi
  if [ -f "$ETC_DIR/algod.admin.token" ]; then
    cp "$ETC_DIR/algod.admin.token" algod.admin.token
  fi
  if [ -f "$ETC_DIR/logging.config" ]; then
    cp "$ETC_DIR/logging.config" logging.config
  fi

  # initialize config with profile.
  if [ "$PROFILE" != "" ]; then
    algocfg profile set "$PROFILE" --yes -d "$ALGORAND_DATA"
  fi

  # set profile overrides
  if [ "$GOSSIP_PORT" != "" ]; then
    algocfg set -p NetAddress -v "0.0.0.0:${GOSSIP_PORT}" -d .
    algocfg set -p DisableNetworking -v "false" -d .
    algocfg set -p IncomingConnectionsLimit -v "1000" -d .
  fi

  algocfg set -p EndpointAddress -v "0.0.0.0:${ALGOD_PORT}" -d .

  # set token overrides
  for dir in "${ALGORAND_DATA}"/../*/; do
    if [ "$TOKEN" != "" ]; then
      printf '%s\n' "$TOKEN" >"$dir/algod.token"
    fi
    if [ "$ADMIN_TOKEN" != "" ]; then
      printf '%s\n' "$ADMIN_TOKEN" >"$dir/algod.admin.token"
    fi
  done

  # configure telemetry (accepted for compatibility; algod-rust has none)
  if [ "$TELEMETRY_NAME" != "" ]; then
    echo "TELEMETRY_NAME is accepted but ignored: algod-rust has no telemetry." >&2
    diagcfg telemetry name -n "$TELEMETRY_NAME" -d "$ALGORAND_DATA"
    if [ "$TELEMETRY_URL" != "" ]; then
      diagcfg telemetry endpoint -e "$TELEMETRY_URL" -d "$ALGORAND_DATA"
    fi
    diagcfg telemetry enable -d "$ALGORAND_DATA"
  elif ! [ -f "$ETC_DIR/logging.config" ]; then
    diagcfg telemetry disable
  fi

  # prepare kmd
  if [ "$START_KMD" = "1" ]; then
    local KMD_DIR="kmd-v0.5"
    # on initial bootstrap, this directory won't exist.
    mkdir -p "$KMD_DIR"
    chmod 0700 "$KMD_DIR"
    cd "$KMD_DIR"
    if [ -f "$ETC_DIR/kmd_config.json" ]; then
      cp "$ETC_DIR/kmd_config.json" kmd_config.json
    else
      echo "{ \"address\":\"0.0.0.0:${KMD_PORT}\", \"allowed_origins\":[\"*\"] }" >kmd_config.json
    fi

    if [ "$KMD_TOKEN" != "" ]; then
      printf '%s\n' "$KMD_TOKEN" >kmd.token
    fi
    cd "$ALGORAND_DATA"
  fi
}

start_public_network() {
  cd "$ALGORAND_DATA"

  configure_data_dir
  start_kmd &

  if [ "$FAST_CATCHUP" = "1" ]; then
    catchup &
  fi

  if [ "$PEER_ADDRESS" != "" ]; then
    echo "Using peer(s): $PEER_ADDRESS"
    exec_algod -o -p "$PEER_ADDRESS"
  else
    # redirect output to stdout
    exec_algod -o
  fi
}

start_new_public_network() {
  mkdir -p "$ALGORAND_DATA"
  cd "$ALGORAND_DATA"

  # initialize genesis.json
  if [ "$GENESIS_ADDRESS" != "" ]; then
    # download genesis file from peer
    echo "Attempting to download genesis file from $GENESIS_ADDRESS"
    # -f: an HTTP error must not leave an error page behind as genesis.json
    # (every later start would take the "existing data dir" branch with it)
    if ! curl -fsS "$GENESIS_ADDRESS/genesis" -o genesis.json; then
      rm -f genesis.json
      echo "Unable to download the genesis file from $GENESIS_ADDRESS" >&2
      exit 1
    fi
  elif [ -n "$NETWORK" ] && [ -d "$GENESIS_DIR/${NETWORK}" ]; then
    echo "Installing genesis file for ${NETWORK}"
    cp "$GENESIS_DIR/${NETWORK}/genesis.json" genesis.json
  else
    echo "No genesis file for '$NETWORK' is available."
    exit 1
  fi

  configure_data_dir

  # if the peer address is set, it will be used instead of the DNS bootstrap ID
  if [ "$PEER_ADDRESS" != "" ]; then
    local ID
    case $NETWORK in
    mainnet) ID="<network>.algorand.network" ;;
    testnet) ID="<network>.algorand.network" ;;
    betanet) ID="<network>.algodev.network" ;;
    alphanet) ID="<network>.algodev.network" ;;
    devnet) ID="<network>.algodev.network" ;;
    fnet) ID="<network>.algorand.tech" ;;
    *)
      echo "Unknown network."
      exit 1
      ;;
    esac
    echo Setting DNS Bootstrap ID to "$ID"
    algocfg set -p DNSBootstrapID -v "$ID" -d "$ALGORAND_DATA"
  elif [ "$NETWORK" = "fnet" ]; then
    echo Setting FNet DNS Bootstrap ID
    algocfg set -p DNSBootstrapID -v "<network>.algorand.tech" -d "$ALGORAND_DATA"
  fi

  start_public_network
}

private_network_unsupported() {
  die "Private networks (no NETWORK, or an existing network.json) need 'goal network create/start', which algod-rust does not implement yet (issue #1993). Set NETWORK to mainnet, testnet, betanet, devnet, alphanet or fnet, or mount a data directory that contains genesis.json."
}

##############
# Entrypoint #
##############

main() {
  drop_privileges "$@"

  echo "Starting Algod Docker Container"
  echo "   ALGORAND_DATA:   $ALGORAND_DATA"
  echo "   NETWORK:         $NETWORK"
  echo "   PROFILE:         $PROFILE"
  echo "   DEV_MODE:        $DEV_MODE"
  echo "   START_KMD:       ${START_KMD:-"Not Set"}"
  echo "   FAST_CATCHUP:    $FAST_CATCHUP"
  # (go prints the token values; the admin token is full control of the node
  # and `docker logs` is routinely shipped, so only whether they are set)
  echo "   TOKEN:           $(set_or_not "$TOKEN")"
  echo "   ADMIN_TOKEN:     $(set_or_not "$ADMIN_TOKEN")"
  echo "   KMD_TOKEN:       $(set_or_not "$KMD_TOKEN")"

  echo "   TELEMETRY_NAME:  $TELEMETRY_NAME"
  echo "   TELEMETRY_URL:   $TELEMETRY_URL"
  echo "   NUM_ROUNDS:      $NUM_ROUNDS"
  echo "   GENESIS_ADDRESS: $GENESIS_ADDRESS"
  echo "   PEER_ADDRESS:    $PEER_ADDRESS"
  echo "   GOSSIP_PORT:     $GOSSIP_PORT"
  echo "   ALGOD_PORT:      $ALGOD_PORT"

  # If the data directory is initialized, start the existing environment.
  if [ -f "$ALGORAND_DATA/../network.json" ]; then
    private_network_unsupported
  elif [ -f "$ALGORAND_DATA/genesis.json" ]; then
    start_public_network
    exit 1
  fi

  # Initialize and start the network.
  if [ "$NETWORK" == "" ] && [ "$PEER_ADDRESS" == "" ]; then
    private_network_unsupported
  else
    start_new_public_network
  fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
