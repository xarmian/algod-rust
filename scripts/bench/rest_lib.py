# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Pure logic of the bench-compare `rest` tier (issue #2107, epic #2101).

Everything here is deterministic and free of Docker, network and clock so it
runs in the default unit tests (test_rest.py); the tier script
(tiers/rest.py) does the I/O and calls into this module:

  * the fixed request set both nodes are asked (request_set), the simulate
    request body (a hand-rolled msgpack encoder: the repo adds no dependency
    for forty lines) and the deterministic choice of the hot / cold account;
  * the response-equality gate: per-endpoint normalisation of fields that
    legitimately differ between two nodes serving the same ledger (VOLATILE,
    each with its reason, each documented in docs/BENCHMARK_COMPARISON.md) and
    the issue-linked allowlist of real differences found so far
    (KNOWN_DIFFERENCES: every entry names the issue that tracks it, and a
    stale entry fails the gate so the list cannot rot);
  * the container shape that keeps both nodes under identical limits;
  * the result rows (schema bench-result/v1).
"""
import base64
import copy
import hashlib
import json
import struct
import urllib.parse

TIER = "rest"
REST_PORT = 8080
MIB = 1024 * 1024

# Profiles of the tier (BENCH_REST_PROFILE). `smoke` is the CI profile: it
# proves the machinery (both nodes up on one ledger, the gate, one load step
# per endpoint) and its numbers mean nothing.
PROFILES = {
    "smoke": {"duration_s": 1.0, "warmup_s": 0.0, "concurrency": [4]},
    "full": {"duration_s": 5.0, "warmup_s": 1.0, "concurrency": [1, 16, 64]},
}


def parse_concurrency(text):
    """`1,16,64` -> [1, 16, 64]. ValueError on an empty, non-positive,
    non-numeric or repeated level."""
    out = []
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            n = int(part)
        except ValueError:
            raise ValueError(f"concurrency level {part!r} is not an integer") from None
        if n < 1 or n in out:
            raise ValueError(f"concurrency levels must be distinct and >= 1, got {text!r}")
        out.append(n)
    if not out:
        raise ValueError("no concurrency levels")
    return out


# ---- the volatile-field normalisation and the allowlist ------------------------

# Fields that legitimately differ between two nodes that serve the SAME ledger:
# they depend on wall-clock time or on how long a node has been up, not on
# ledger state. endpoint name -> {dotted path: reason}. `*` matches any list
# index or map key. Every path is listed in docs/BENCHMARK_COMPARISON.md (a
# unit test enforces it), so an exclusion cannot be added silently.
VOLATILE = {
    "status": {
        "time-since-last-round": "nanoseconds since the node last advanced a round; wall-clock "
                                 "dependent, so two nodes queried at different instants differ",
        "catchup-time": "nanoseconds the node has spent catching up; a wall-clock duration of "
                        "the node's own history, not ledger state",
    },
}

# Real response differences found between the two nodes, each tracked by an
# issue. NOT volatile fields: these are bugs (or accepted divergences), kept
# out of the gate only so the throughput comparison can run while the issue
# is open. Entry: {"endpoint", "path", "kind", "issue", "reason", "corpus"
# [, "rust_value"]}. An entry excuses exactly ONE difference: the one at
# exactly `path` (`*` matches one segment; nothing below or above it is
# covered) and of exactly `kind`:
#   only-go    algod-rust lacks the key that go has (if both sides have a
#              value at that path, they must be equal: that is a "value"
#              difference, which this kind does not excuse);
#   only-rust  go lacks the key that algod-rust has (`rust_value`, when
#              given, pins the value algod-rust may have);
#   value      both sides have a value at that path and the values differ.
# A stale entry (one that no longer matches any difference) fails the gate:
# remove it when the issue is fixed.
KINDS = ("only-go", "only-rust", "value")


def _kd(endpoint, path, kind, issue, reason, **extra):
    return dict({"endpoint": endpoint, "path": path, "kind": kind, "issue": issue,
                 "reason": reason, "corpus": "small"}, **extra)


KNOWN_DIFFERENCES = [
    # pending rewards are not applied to the looked-up account.
    _kd("account_hot", "amount", "value", 2157, "pending rewards not applied"),
    _kd("account_hot", "pending-rewards", "value", 2157, "pending rewards not applied"),
    _kd("account_hot", "rewards", "value", 2157, "pending rewards not applied"),
    _kd("account_hot", "reward-base", "value", 2157, "pending rewards not applied"),
    _kd("tx_params", "fee", "value", 2158,
        "fee reports min-fee, go reports the pool fee per byte"),
    # the stored `{rnd}` certificate is re-encoded with step=2 (decoded structurally).
    _kd("blocks_msgpack", "cert.step", "only-rust", 2159, "cert re-encoded with step=2",
        rust_value=2),
    _kd("simulate", "txn-groups.0.txn-results.0.txn-result.txn.txn.gh", "value", 2160,
        "gh rendered as an integer array"),
    _kd("simulate", "txn-groups.0.txn-results.0.txn-result.sender-rewards", "only-go", 2161,
        "sender-rewards omitted"),
]

KD_TABLE_START = "<!-- known-differences:start -->"
KD_TABLE_END = "<!-- known-differences:end -->"


def known_differences_table(entries=None):
    """The Markdown table of KNOWN_DIFFERENCES that docs/BENCHMARK_COMPARISON.md
    embeds between KD_TABLE_START and KD_TABLE_END (a test keeps them equal)."""
    rows = ["| Endpoint | Path | Kind | Issue | Reason |", "|---|---|---|---|---|"]
    for e in KNOWN_DIFFERENCES if entries is None else entries:
        rows.append(f"| `{e['endpoint']}` | `{e['path']}` | {e['kind']} | "
                    f"[#{e['issue']}](https://github.com/xarmian/algod-rust/issues/{e['issue']}) "
                    f"| {e['reason']} |")
    return "\n".join(rows)


def check_allowlist(entries):
    """Refuse a malformed allowlist: every entry names an endpoint, a path,
    a kind, the tracking issue (an int) and a reason."""
    for e in entries:
        if not isinstance(e.get("endpoint"), str) or not e["endpoint"]:
            raise ValueError(f"allowlist entry {e!r}: no endpoint")
        if not isinstance(e.get("path"), str) or not e["path"]:
            raise ValueError(f"allowlist entry {e!r}: no path")
        if e.get("kind") not in KINDS:
            raise ValueError(f"allowlist entry {e!r}: `kind` must be one of {', '.join(KINDS)}")
        if "rust_value" in e and e["kind"] != "only-rust":
            raise ValueError(f"allowlist entry {e!r}: `rust_value` only applies to only-rust")
        if not isinstance(e.get("issue"), int) or isinstance(e.get("issue"), bool):
            raise ValueError(f"allowlist entry {e!r}: `issue` must be the tracking issue number")
        if not isinstance(e.get("reason"), str) or not e["reason"].strip():
            raise ValueError(f"allowlist entry {e!r}: no reason")
        if "corpus" in e and not (isinstance(e["corpus"], str) and e["corpus"]):
            raise ValueError(f"allowlist entry {e!r}: `corpus` must be a corpus name")


def drop_paths(doc, paths):
    """A copy of `doc` without the dotted `paths` (`*` = any element or key).
    A path that is not present is ignored."""
    doc = copy.deepcopy(doc)
    for p in paths:
        _drop(doc, p.split("."))
    return doc


def _drop(node, segs):
    seg, rest = segs[0], segs[1:]
    if isinstance(node, dict):
        keys = list(node) if seg == "*" else ([seg] if seg in node else [])
        for k in keys:
            if rest:
                _drop(node[k], rest)
            else:
                del node[k]
    elif isinstance(node, list):
        idx = range(len(node)) if seg == "*" else (
            [int(seg)] if seg.isdigit() and int(seg) < len(node) else [])
        # delete from the end so earlier indexes stay valid
        for i in sorted(idx, reverse=True) if not rest else idx:
            if rest:
                _drop(node[i], rest)
            else:
                del node[i]


def _path_matches(entry_path, diff_path):
    """True when `entry_path` is exactly `diff_path`, segment by segment (`*`
    matches one segment). A prefix does not cover what is below it."""
    want, got = entry_path.split("."), diff_path.split(".")
    return len(got) == len(want) and all(w in ("*", g) for w, g in zip(want, got))


def _excuses(entry, endpoint, diff):
    if entry["endpoint"] != endpoint or entry["kind"] != diff["kind"]:
        return False
    if not _path_matches(entry["path"], diff["path"]):
        return False
    return "rust_value" not in entry or diff.get("rust") == entry["rust_value"]


# ---- comparison --------------------------------------------------------------

def _media_type(ctype):
    return (ctype or "").split(";")[0].strip().lower()


def _diff(path, kind, msg, go=None, rust=None):
    return {"path": path, "kind": kind, "msg": msg, "go": go, "rust": rust}


def json_diff(go, rust, path=""):
    """Differences between two decoded documents, as dicts {path, kind, msg,
    go, rust} (empty: equal). kind: only-go / only-rust (a key or element on
    one side only) or value."""
    if isinstance(go, dict) and isinstance(rust, dict):
        out = []
        for k in sorted(set(go) | set(rust), key=str):
            p = f"{path}.{k}" if path else str(k)
            if k not in rust:
                out.append(_diff(p, "only-go", f"{p}: only in go", go=go[k]))
            elif k not in go:
                out.append(_diff(p, "only-rust", f"{p}: only in rust", rust=rust[k]))
            else:
                out += json_diff(go[k], rust[k], p)
        return out
    if isinstance(go, list) and isinstance(rust, list):
        out = []
        for i in range(max(len(go), len(rust))):
            p = f"{path}.{i}" if path else str(i)
            if i >= len(rust):
                out.append(_diff(p, "only-go", f"{p}: only in go", go=go[i]))
            elif i >= len(go):
                out.append(_diff(p, "only-rust", f"{p}: only in rust", rust=rust[i]))
            else:
                out += json_diff(go[i], rust[i], p)
        return out
    if go != rust or type(go) is not type(rust):
        return [_diff(path or "$", "value", f"{path or '$'}: go {go!r} != rust {rust!r}",
                      go=go, rust=rust)]
    return []


def _decode_body(req, body):
    """(value, None) for a decodable json / msgpack body, else (None, reason)
    with the decoder's own error message."""
    try:
        if req.get("kind") == "json":
            return json.loads(body), None
        if req.get("kind") == "msgpack":
            return msgpack_decode(body), None
    except (ValueError, UnicodeDecodeError) as e:
        return None, str(e) or type(e).__name__
    return None, f"request kind {req.get('kind')!r} has no decoder"


def _diffs(req, go, rust):
    """Differences between two responses to `req`, before any allowlist
    (dicts as json_diff). VOLATILE fields are already dropped from JSON
    bodies. Non-body differences use the pseudo-paths `<status>` /
    `<content-type>`; an undecodable body, or a msgpack body that decodes to
    the same value with different bytes, `<body>` / `<encoding>`."""
    out = []
    if go["status"] != rust["status"]:
        out.append(_diff("<status>", "status", f"status: go {go['status']} != rust "
                                               f"{rust['status']}"))
    if _media_type(go["content_type"]) != _media_type(rust["content_type"]):
        out.append(_diff("<content-type>", "content-type",
                         f"content-type: go {go['content_type']!r} != rust "
                         f"{rust['content_type']!r}"))
    gb, rb = go["body"], rust["body"]
    (gj, gerr), (rj, rerr) = _decode_body(req, gb), _decode_body(req, rb)
    if gerr is None and rerr is None:
        vol = list(VOLATILE.get(req["name"], {})) if req.get("kind") == "json" else []
        found = json_diff(drop_paths(gj, vol), drop_paths(rj, vol))
        if not found and req.get("kind") == "msgpack" and gb != rb:
            i = next((n for n, (a, b) in enumerate(zip(gb, rb)) if a != b),
                     min(len(gb), len(rb)))
            found = [_diff("<encoding>", "encoding",
                           f"same value, different msgpack bytes (byte {i}; go {len(gb)} bytes, "
                           f"rust {len(rb)} bytes)")]
        return out + found
    if gb != rb:
        i = next((n for n, (a, b) in enumerate(zip(gb, rb)) if a != b), min(len(gb), len(rb)))
        why = "".join(f"; {side} body is not valid {req.get('kind')}: {err}"
                      for side, err in (("go", gerr), ("rust", rerr)) if err)
        out.append(_diff("<body>", "body", f"body differs at byte {i} (go {len(gb)} bytes, "
                                           f"rust {len(rb)} bytes){why}"))
    return out


def compare(req, go, rust):
    """Human-readable differences between the two nodes' responses to `req`
    (no allowlist applied)."""
    return [d["msg"] for d in _diffs(req, go, rust)]


def gate(requests, go_responses, rust_responses, allowlist, corpus=None):
    """The response-equality gate. `*_responses` map request name ->
    {status, content_type, body}. Returns the list of errors (empty: pass):
    a differing response, a request one node did not answer, a response for a
    request not in the set, and an allowlist entry that excused nothing."""
    check_allowlist(allowlist)
    # An entry with a `corpus` only applies to that corpus's ledger (what a
    # differing field holds depends on the accounts the corpus created); for
    # any other corpus it is neither used nor stale.
    allowlist = [e for e in allowlist if e.get("corpus") in (None, corpus)]
    errors = []
    names = {r["name"] for r in requests}
    for side, resps in (("go", go_responses), ("rust", rust_responses)):
        for extra in sorted(set(resps) - names):
            errors.append(f"{side}: response {extra!r} is not in the request set")
    used = set()
    for req in requests:
        n = req["name"]
        label = f"{n} ({req.get('method', 'GET')} {req['path']})"
        missing = [s for s, r in (("go", go_responses), ("rust", rust_responses)) if n not in r]
        for s in missing:
            errors.append(f"{label}: no response from {s}")
        if missing:
            continue
        for d in _diffs(req, go_responses[n], rust_responses[n]):
            hit = [i for i, e in enumerate(allowlist) if _excuses(e, n, d)]
            if hit:
                used.update(hit)
            else:
                errors.append(f"{label}: {d['msg']}")
    for i, e in enumerate(allowlist):
        if i not in used and e["endpoint"] in names:
            errors.append(f"allowlist entry {e['endpoint']}.{e['path']} (#{e['issue']}) no longer "
                          "matches any difference: remove it")
    return errors


def corrupt_response(req, go, rust, allowlist=(), corpus=None):
    """A copy of algod-rust's response `rust` with one deliberate change that
    the gate does NOT excuse, for the tier's negative test (BENCH_REST_CORRUPT).
    Leaves of the decoded body (JSON or msgpack) are altered one at a time, in
    a fixed order, until one produces a gate error that is not about the
    allowlist (a leaf under an allowlisted path is skipped: it would be
    excused or absent); undecodable bodies get a flipped byte instead.
    ValueError when no change makes the gate fail."""
    def fails(body):
        errs = gate([req], {req["name"]: go}, {req["name"]: dict(rust, body=body)},
                    allowlist, corpus)
        return any(not e.startswith("allowlist entry") for e in errs)

    for body in _mutations(req, rust["body"]):
        if fails(body):
            return dict(rust, body=body)
    raise ValueError(f"no corruption of {req['name']} fails the gate")


def _mutations(req, body):
    doc, err = _decode_body(req, body)
    if err is None:
        for path in _leaf_paths(doc):
            cand = copy.deepcopy(doc)
            _alter(cand, path)
            try:
                yield (json.dumps(cand).encode() if req.get("kind") == "json"
                       else msgpack(cand))
            except ValueError:
                continue  # not encodable by the minimal encoder
    for i in range(min(len(body), 64)):
        yield body[:i] + bytes([body[i] ^ 1]) + body[i + 1:]


def _leaf_paths(node, prefix=()):
    items = (sorted(node.items(), key=lambda kv: str(kv[0])) if isinstance(node, dict)
             else list(enumerate(node)) if isinstance(node, list) else None)
    if items is None:
        if isinstance(node, bool) or not isinstance(node, (int, str, bytes)):
            return
        yield prefix
        return
    for k, v in items:
        yield from _leaf_paths(v, prefix + (k,))


def _alter(node, path):
    for k in path[:-1]:
        node = node[k]
    k = path[-1]
    v = node[k]
    node[k] = (v + 1 if isinstance(v, int) else v + "x" if isinstance(v, str)
               else v[:-1] + bytes([v[-1] ^ 1]) if v else b"\x00")


# ---- msgpack and addresses (for the simulate request) ------------------------

def _u32(n):
    """A 4-byte length; ValueError (not OverflowError) beyond msgpack's limit."""
    if n >= 1 << 32:
        raise ValueError("msgpack length exceeds 32 bits")
    return n.to_bytes(4, "big")


def msgpack(v):
    """Minimal canonical msgpack encoder: maps with sorted keys, unsigned
    integers, str, bin, arrays, bool, nil. Enough for a SimulateRequest."""
    if v is None:
        return b"\xc0"
    if v is True:
        return b"\xc3"
    if v is False:
        return b"\xc2"
    if isinstance(v, int):
        if v < 0:
            raise ValueError("negative integers are not supported")
        if v < 128:
            return bytes([v])
        for marker, size in ((0xcc, 1), (0xcd, 2), (0xce, 4), (0xcf, 8)):
            if v < 1 << (8 * size):
                return bytes([marker]) + v.to_bytes(size, "big")
        raise ValueError("integer exceeds 64 bits")
    if isinstance(v, str):
        b = v.encode()
        if len(b) < 32:
            return bytes([0xa0 | len(b)]) + b
        if len(b) < 256:
            return b"\xd9" + bytes([len(b)]) + b
        if len(b) < 65536:
            return b"\xda" + len(b).to_bytes(2, "big") + b
        return b"\xdb" + _u32(len(b)) + b
    if isinstance(v, (bytes, bytearray)):
        n = len(v)
        head = (b"\xc4" + bytes([n]) if n < 256 else b"\xc5" + n.to_bytes(2, "big")
                if n < 65536 else b"\xc6" + _u32(n))
        return head + bytes(v)
    if isinstance(v, (list, tuple)):
        n = len(v)
        head = (bytes([0x90 | n]) if n < 16 else b"\xdc" + n.to_bytes(2, "big") if n < 65536
                else b"\xdd" + _u32(n))
        return head + b"".join(msgpack(x) for x in v)
    if isinstance(v, dict):
        n = len(v)
        head = (bytes([0x80 | n]) if n < 16 else b"\xde" + n.to_bytes(2, "big") if n < 65536
                else b"\xdf" + _u32(n))
        return head + b"".join(msgpack(k) + msgpack(v[k]) for k in sorted(v))
    raise ValueError(f"cannot encode {type(v).__name__}")


class _MpReader:
    def __init__(self, data):
        self.b, self.i = bytes(data), 0

    def take(self, n):
        if self.i + n > len(self.b):
            raise ValueError("truncated msgpack")
        chunk = self.b[self.i:self.i + n]
        self.i += n
        return chunk

    def uint(self, n):
        return int.from_bytes(self.take(n), "big")

    def array(self, n):
        return [self.value() for _ in range(n)]

    def map(self, n):
        out = {}
        for _ in range(n):
            k = self.value()
            v = self.value()
            try:
                out[k] = v
            except TypeError:
                raise ValueError("unhashable msgpack map key") from None
        return out

    def value(self):
        t = self.uint(1)
        if t < 0x80:
            return t
        if t >= 0xe0:
            return t - 256
        if t <= 0x8f:
            return self.map(t & 0x0f)
        if t <= 0x9f:
            return self.array(t & 0x0f)
        if t <= 0xbf:
            return self.take(t & 0x1f).decode("utf-8")
        if t in (0xc0, 0xc2, 0xc3):
            return {0xc0: None, 0xc2: False, 0xc3: True}[t]
        if t in (0xc4, 0xc5, 0xc6):
            return self.take(self.uint(1 << (t - 0xc4)))
        if t == 0xca:
            return struct.unpack(">f", self.take(4))[0]
        if t == 0xcb:
            return struct.unpack(">d", self.take(8))[0]
        if 0xcc <= t <= 0xcf:
            return self.uint(1 << (t - 0xcc))
        if 0xd0 <= t <= 0xd3:
            return int.from_bytes(self.take(1 << (t - 0xd0)), "big", signed=True)
        if t in (0xd9, 0xda, 0xdb):
            return self.take(self.uint(1 << (t - 0xd9))).decode("utf-8")
        if t in (0xdc, 0xdd):
            return self.array(self.uint(2 if t == 0xdc else 4))
        if t in (0xde, 0xdf):
            return self.map(self.uint(2 if t == 0xde else 4))
        if t in (0xd4, 0xd5, 0xd6, 0xd7, 0xd8):
            return self.ext(1 << (t - 0xd4))
        if t in (0xc7, 0xc8, 0xc9):
            return self.ext(self.uint(1 << (t - 0xc7)))
        raise ValueError(f"unsupported msgpack type 0x{t:02x}")

    def ext(self, n):
        """An ext value: `("timestamp", seconds, nanoseconds)` for type -1
        (the msgpack timestamp, 4/8/12 bytes), else `("ext", type, data)`."""
        kind = int.from_bytes(self.take(1), "big", signed=True)
        data = self.take(n)
        if kind == -1:
            if n == 4:
                return ("timestamp", int.from_bytes(data, "big"), 0)
            if n == 8:
                v = int.from_bytes(data, "big")
                return ("timestamp", v & ((1 << 34) - 1), v >> 34)
            if n == 12:
                return ("timestamp", int.from_bytes(data[4:], "big", signed=True),
                        int.from_bytes(data[:4], "big"))
            raise ValueError(f"msgpack timestamp with {n} data bytes")
        return ("ext", kind, data)


def msgpack_decode(data):
    """Decode one msgpack value that spans all of `data` (maps, arrays, str,
    bin, bool, nil, integers, floats, ext values as tagged tuples). ValueError
    on truncated or trailing input, an unknown type byte, or an unhashable map
    key; the message is the reason the gate reports."""
    r = _MpReader(data)
    v = r.value()
    if r.i != len(r.b):
        raise ValueError(f"trailing bytes after msgpack value at offset {r.i}")
    return v


def decode_address(addr):
    """The 32-byte public key of a 58-character Algorand address; ValueError
    on a wrong length or checksum."""
    if len(addr) != 58:
        raise ValueError(f"address {addr!r} is not 58 characters")
    try:
        raw = base64.b32decode(addr + "======")
    except ValueError as e:
        raise ValueError(f"address {addr!r}: {e}") from None
    pk, check = raw[:32], raw[32:]
    if hashlib.new("sha512_256", pk).digest()[-4:] != check:
        raise ValueError(f"address {addr!r}: bad checksum")
    return pk


def simulate_request(sender, receiver, params):
    """The POST /v2/transactions/simulate request: one unsigned 1-microalgo
    payment, empty signatures allowed, built only from the node-independent
    /v2/transactions/params values so both nodes get identical bytes."""
    last = int(params["last-round"])
    txn = {"type": "pay", "snd": decode_address(sender), "rcv": decode_address(receiver),
           "amt": 1, "fee": int(params["min-fee"]), "fv": last + 1, "lv": last + 1000,
           "gen": params["genesis-id"], "gh": base64.b64decode(params["genesis-hash"])}
    body = msgpack({"txn-groups": [{"txns": [{"txn": txn}]}], "allow-empty-signatures": True})
    return {"name": "simulate", "method": "POST", "path": "/v2/transactions/simulate?format=json",
            "kind": "json", "content_type": "application/msgpack",
            "body_b64": base64.b64encode(body).decode()}


# ---- the request set ---------------------------------------------------------

def pick_hot_cold(accounts):
    """(hot, cold) addresses from {address: /v2/accounts/{a} document}: the
    biggest and the smallest document by serialised size, ties broken by
    address, so the choice is a pure function of the ledger state."""
    if not accounts:
        raise ValueError("no accounts to choose from")
    size = {a: len(json.dumps(d, sort_keys=True)) for a, d in accounts.items()}
    hot = sorted(size, key=lambda a: (-size[a], a))[0]
    cold = sorted(size, key=lambda a: (size[a], a))[0]
    return hot, cold


def request_set(state, simulate=None):
    """The fixed request set, from the discovered ledger `state` ({hot, cold,
    app_id, box_name_b64, round}). Names are stable (they key the result
    rows). `simulate` is the optional request from simulate_request()."""
    for k in ("hot", "cold", "app_id", "box_name_b64", "round"):
        if state.get(k) in (None, ""):
            raise ValueError(f"discovered state has no {k!r}: the corpus must provide a hot and "
                             "a cold account, an application with a box and a block")
    box = urllib.parse.quote("b64:" + state["box_name_b64"], safe="")
    r = state["round"]
    reqs = [
        ("status", "/v2/status", "json"),
        ("account_hot", f"/v2/accounts/{state['hot']}", "json"),
        ("account_cold", f"/v2/accounts/{state['cold']}", "json"),
        ("account_assets", f"/v2/accounts/{state['hot']}/assets", "json"),
        ("application", f"/v2/applications/{state['app_id']}", "json"),
        ("box", f"/v2/applications/{state['app_id']}/box?name={box}", "json"),
        ("blocks_json", f"/v2/blocks/{r}", "json"),
        ("blocks_msgpack", f"/v2/blocks/{r}?format=msgpack", "msgpack"),
        ("tx_params", "/v2/transactions/params", "json"),
    ]
    out = [{"name": n, "method": "GET", "path": p, "kind": k} for n, p, k in reqs]
    if simulate is not None:
        out.append(dict(simulate))
    return out


def loadgen_requests(requests):
    """The request set as restload reads it (benchmarks/go-restload)."""
    out = []
    for r in requests:
        d = {"name": r["name"], "method": r.get("method", "GET"), "path": r["path"]}
        if r.get("content_type"):
            d["content_type"] = r["content_type"]
        if r.get("body_b64"):
            d["body_b64"] = r["body_b64"]
        if r.get("kind") == "msgpack":
            d["accept"] = "application/msgpack"
        out.append(d)
    return out


# ---- containers --------------------------------------------------------------

# Every container this tier starts carries this label, so a run killed before
# its cleanup can be swept (and nothing else is ever touched).
LABEL = "bench-rest"


def container_args(impl, *, name, image, data_dir, port, cpus, mem):
    """`docker run` arguments (after `docker`) of one node. Both
    implementations get the same CPU / memory / swap limits, the same
    published loopback port, and their ledger as the only mount at /data;
    only the entrypoint differs."""
    if impl == "go":
        entry = ["--entrypoint", "algod"]
        cmd = ["-d", "/data", "-l", f"0.0.0.0:{REST_PORT}"]
    elif impl == "rust":
        entry = ["--entrypoint", "algod-rust"]
        cmd = ["node", "start", "-d", "/data", "-l", f"0.0.0.0:{REST_PORT}"]
    else:
        raise ValueError(f"impl must be go or rust, not {impl!r}")
    return ["run", "-d", "--name", name, "--label", f"{LABEL}=1", "--cpus", str(float(cpus)),
            "--memory", mem, "--memory-swap", mem, "-p", f"127.0.0.1:{port}:{REST_PORT}",
            "-v", f"{data_dir}:/data", *entry, image, *cmd]


def limits_of(args):
    """What two containers must share to be comparable, read back from the
    `docker run` arguments: every resource option and the shape of the
    mounts / ports / labels. The host side of the port and of the mount (and
    the name, image and command) legitimately differ and are not in here."""
    def val(flag):
        return args[args.index(flag) + 1]
    bind, _, container_port = val("-p").rpartition(":")
    return {"cpus": val("--cpus"), "memory": val("--memory"), "memory-swap": val("--memory-swap"),
            "publish-bind": bind.split(":")[0], "publish-container-port": container_port,
            "mount-target": val("-v").rpartition(":")[2], "label": val("--label")}


def require_same_limits(go_args, rust_args):
    """ValueError naming every limit on which the two `docker run` argument
    lists differ; None when the two nodes run under the same limits."""
    g, r = limits_of(go_args), limits_of(rust_args)
    bad = [f"{k}: go {g[k]!r} != rust {r[k]!r}" for k in g if g[k] != r[k]]
    if bad:
        raise ValueError("the two containers do not run under the same limits: "
                         + "; ".join(bad))


# ---- result rows -------------------------------------------------------------

NO_DATA = ("no completed requests in the step: node too slow or duration too short "
           "(raise BENCH_REST_DURATION)")


def error_rate(e):
    """Fraction of attempted requests that failed (transport error or
    non-2xx). restload counts `ok` (successful) requests; only those enter
    its req/s and latency percentiles. ValueError when nothing was attempted:
    that is missing data, not a 100% error rate."""
    if e["requests"] <= 0:
        raise ValueError(NO_DATA)
    return (e["requests"] - e["ok"]) / e["requests"]


# A node whose requests fail more often than this is not being benchmarked,
# it is broken: the tier fails instead of publishing its numbers.
MAX_ERROR_RATE = 0.01


def check_error_rate(res, side, endpoint, limit=MAX_ERROR_RATE):
    """None when the error rate is within `limit`, else a message naming the
    node and the endpoint."""
    if res["requests"] <= 0:
        return f"{side} {endpoint}: {NO_DATA}"
    rate = error_rate(res)
    if rate <= limit:
        return None
    return (f"{side} answered {rate:.1%} of {endpoint} requests with an error "
            f"({res['errors']} transport errors, {res['non_2xx']} non-2xx of "
            f"{res['requests']}); limit {limit:.1%}")


MIN_DURATION_S = 0.1


def format_duration(seconds):
    """A Go duration string in fixed-point seconds (`0.500s`); never an
    exponent, which time.ParseDuration rejects."""
    return f"{float(seconds):.3f}s"


def pick_sender(accounts, reserved):
    """The funded account of the simulate request: the richest account in
    {address: /v2/accounts document} that is not one of the `reserved`
    addresses (RewardsPool, FeeSink); ties by address. ValueError when none."""
    cand = {a: d for a, d in accounts.items() if a not in set(reserved)}
    if not cand:
        raise ValueError("no non-reserved account to send the simulated payment from")
    return sorted(cand, key=lambda a: (-int(cand[a]["amount"]), a))[0]


def check_simulation(resp):
    """Problems that make a simulate response not a successful simulation
    (empty: it is one). The simulate row must measure a real simulation, not
    the cheap rejection of a bad request."""
    if resp["status"] != 200:
        return [f"simulate answered HTTP {resp['status']}: {resp['body'][:200]!r}"]
    try:
        doc = json.loads(resp["body"])
        group = doc["txn-groups"][0]
    except (ValueError, KeyError, IndexError, TypeError):
        return ["simulate response has no txn-groups[0]"]
    problems = []
    if group.get("failure-message"):
        problems.append(f"simulation failed: {group['failure-message']}")
    if "failed-at" in group:
        problems.append(f"simulation failed at {group['failed-at']}")
    for i, r in enumerate(group.get("txn-results", [])):
        err = r.get("txn-result", {}).get("pool-error")
        if err:
            problems.append(f"txn {i}: pool-error {err}")
    if not group.get("txn-results"):
        problems.append("simulate response has no txn-results")
    return problems


def window_samples(samples, start, end):
    """The resource samples that describe the measured window. A `docker
    stats --no-stream` call takes 1-2 s and reports the interval it spans, so a
    sample counts only when its WHOLE call ([`start`, `t`]) lies inside
    [start, end]; samples straddling either edge are dropped."""
    return [s for s in samples if s["start"] >= start and s["t"] <= end]


LOAD_METRICS = (
    ("rps", "req/s", "higher", lambda e: e["rps"]),
    ("p50_ms", "ms", "lower", lambda e: e["p50_ms"]),
    ("p95_ms", "ms", "lower", lambda e: e["p95_ms"]),
    ("p99_ms", "ms", "lower", lambda e: e["p99_ms"]),
    ("error_rate", "ratio", "lower", error_rate),
)
RESOURCE_METRICS = (("cpu_cores", "cores"), ("rss_mb", "MB"))


def result_rows(runs, concurrency, resources, meta):
    """Schema-v1 rows. `runs` is a list (one per repeat) of {impl: {endpoint:
    restload endpoint result}}; `resources` is {impl: {endpoint: {cpu_cores:
    [per-run], rss_mb: [per-run]}}}. Row name: `<endpoint>/c<concurrency>/<metric>`,
    one sample per run."""
    rows = []

    def row(impl, name, unit, better, samples):
        rows.append({"schema": "bench-result/v1", "tier": TIER, "name": name, "impl": impl,
                     "unit": unit, "better": better,
                     "samples": [round(float(s), 6) for s in samples],
                     "metadata": dict(meta, concurrency=concurrency)})

    for impl in ("go", "rust"):
        endpoints = [e for e in runs[0][impl]]
        for ep in endpoints:
            for metric, unit, better, fn in LOAD_METRICS:
                row(impl, f"{ep}/c{concurrency}/{metric}", unit, better,
                    [fn(r[impl][ep]) for r in runs])
            res = resources.get(impl, {}).get(ep, {})
            for metric, unit in RESOURCE_METRICS:
                if res.get(metric):
                    row(impl, f"{ep}/c{concurrency}/{metric}", unit, "lower", res[metric])
    return rows
