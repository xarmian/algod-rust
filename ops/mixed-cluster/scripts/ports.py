#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

"""Host-port table of the mixed-cluster harness (issue #1956).

Every node's REST API is published on ``127.0.0.1:<base>+N`` where N is the
node number (go-node-1..3, rust-node-4, go-node-5) and ``base`` is
``PHASE6_HOST_PORT_BASE`` (default 4000, i.e. the historical 4001..4005).
``start.sh`` persists the base it started the cluster with in
``netroot/.phase6-env``; when the variable is unset, that file is the
fallback, so a checker run later in another shell still talks to the right
ports. ``ports.sh`` is the shell twin of this module; ``docker-compose.yml``
takes the per-node ``PHASE6_*_PORT`` variables the shell side exports.
"""
import os
import sys

ENV_VAR = "PHASE6_HOST_PORT_BASE"
DEFAULT_BASE = 4000
# Highest base that keeps every node's port <= 65535.
MAX_BASE = 65535 - 5

NODE_NUMBERS = {
    "go-node-1": 1,
    "go-node-2": 2,
    "go-node-3": 3,
    "rust-node-4": 4,
    "go-node-5": 5,
}

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ENV_FILE = os.path.join(os.path.dirname(_HERE), "netroot", ".phase6-env")
ENV_FILE_VAR = "PHASE6_ENV_FILE"  # same path override ports.sh honours


def parse_base(raw):
    """Validate a base given as text; ValueError names the variable."""
    text = str(raw)
    if not text.isdigit() or not (1 <= int(text) <= MAX_BASE):
        raise ValueError(
            "{}={!r} is not a port base in 1..{}".format(ENV_VAR, text, MAX_BASE))
    return int(text)


def _read_env_file(path):
    """The value of ENV_VAR in start.sh's KEY=VALUE env file, or None."""
    if not path:
        return None
    try:
        with open(path) as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    value = None
    for line in lines:
        line = line.strip()
        if line.startswith(ENV_VAR + "="):
            value = line[len(ENV_VAR) + 1:].strip()
    return value or None


def host_port_base(environ=None, env_file=DEFAULT_ENV_FILE):
    """PHASE6_HOST_PORT_BASE from the environment, else from the env file
    start.sh wrote (PHASE6_ENV_FILE overrides its path, as in ports.sh),
    else DEFAULT_BASE."""
    environ = os.environ if environ is None else environ
    if env_file is DEFAULT_ENV_FILE and environ.get(ENV_FILE_VAR):
        env_file = environ[ENV_FILE_VAR]
    raw = environ.get(ENV_VAR) or _read_env_file(env_file)
    if raw is None:
        return DEFAULT_BASE
    return parse_base(raw)


def node_port(name, base=None):
    """Host port of one node (KeyError for an unknown node name)."""
    base = host_port_base() if base is None else base
    return base + NODE_NUMBERS[name]


def node_ports(base=None):
    """name -> host port for every node."""
    base = host_port_base() if base is None else base
    return {name: base + n for name, n in NODE_NUMBERS.items()}


def nodes(names, base=None):
    """((name, port), ...) in the given order."""
    base = host_port_base() if base is None else base
    return tuple((name, base + NODE_NUMBERS[name]) for name in names)


def table(names):
    """nodes(names) for a checker's module-level table: an invalid base
    (a hand-edited netroot/.phase6-env, a bad variable) is one clean
    `error:` line on stderr and exit 2, not an import-time traceback."""
    try:
        return nodes(names)
    except ValueError as e:
        print("error: {}".format(e), file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    for name, port in sorted(node_ports().items(), key=lambda kv: kv[1]):
        print("{} {}".format(name, port))
