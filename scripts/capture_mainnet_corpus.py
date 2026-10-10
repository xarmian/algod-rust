#!/usr/bin/env python3
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
"""Capture one mainnet regression-corpus entry (issue #1675).

For ROUND this writes, under crates/core/algo-ledger/fixtures/mainnet_corpus/:

  <ROUND>.msgpack        the block exactly as served by
                         GET /v2/blocks/<ROUND>?format=msgpack
  <ROUND>.state.msgpack  {meta, prev_hdr, pre, post}
      pre   go-format ledger records (Accts / AppResources / AssetResources /
            KvMods) for every account, resource and box the block touches or
            reads, as they stood at the end of round ROUND-1
      post  the same record shapes taken verbatim from go's own state delta
            of ROUND (GET /v2/deltas/<ROUND>), the post-state oracle

The free public endpoints cannot rewind state, so the pre-state of each key
is reconstructed as "the record in the most recent state delta before ROUND
that carried the key": the indexer says in which rounds an account / asset /
application was involved, and /v2/deltas/<round> supplies the full record
that go wrote in that round.

Known limitations (see fixtures/mainnet_corpus/README.md):
  * a base record can change without a transaction (block proposer payouts,
    fee sink / rewards pool): the last PRESCAN deltas are scanned directly, but
    an older proposer-only write of a touched account would be missed (stale
    record); the replay test would then report the divergence;
  * read-only keys are approximated from the chain tip or left unresolved past
    a walk limit; both are recorded in `meta` and pinned by the test;
  * indexer failures abort the capture (nothing is silently treated as
    "no history").

Usage:  python3 scripts/capture_mainnet_corpus.py ROUND [ROUND ...]
Needs:  python3, `pip install msgpack requests`. Network responses are cached
in $CORPUS_CACHE (default: <tmpdir>/algod-corpus-cache).
"""
import base64
import hashlib
import os
import sys
import tempfile
import time

import msgpack
import requests

ALGOD = os.environ.get("CORPUS_ALGOD", "https://mainnet-api.algonode.cloud")
INDEXER = os.environ.get("CORPUS_INDEXER", "https://mainnet-idx.algonode.cloud")
OUT_DIR = os.environ.get("CORPUS_OUT") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "crates",
    "core",
    "algo-ledger",
    "fixtures",
    "mainnet_corpus",
)
CACHE = os.environ.get(
    "CORPUS_CACHE", os.path.join(tempfile.gettempdir(), "algod-corpus-cache")
)
os.makedirs(CACHE, exist_ok=True)
SESSION = requests.Session()


class M(list):
    pass


def _conv(x):
    if isinstance(x, M):
        try:
            return {
                (_conv(k) if not isinstance(k, (bytes, str, int)) else k): _conv(v)
                for k, v in x
            }
        except TypeError:  # map keys that are themselves maps
            return [(_conv(k), _conv(v)) for k, v in x]
    if isinstance(x, list):
        return [_conv(v) for v in x]
    return x


def unpack(b):
    # str values may hold arbitrary bytes (go `string` fields): keep them
    # lossless via surrogateescape so they repack identically.
    return _conv(
        msgpack.unpackb(
            b,
            raw=False,
            unicode_errors="surrogateescape",
            strict_map_key=False,
            object_pairs_hook=M,
        )
    )


def pack(x):
    return msgpack.packb(x, use_bin_type=True, unicode_errors="surrogateescape")


def http(url, params=None):
    forbidden_sleep = 0
    for attempt in range(6):
        try:
            r = SESSION.get(url, params=params, timeout=90)
            if r.status_code in (429, 502, 503, 504):
                time.sleep(1.5 * (attempt + 1))
                continue
            if r.status_code == 403 and "algonode.cloud" in url:
                # algonode's edge answers 403 when a burst trips its rate
                # limit (other hosts: a 403 is final, returned to the caller).
                # Bounded: at most 5 back-offs and 30 s of sleeping in total.
                if attempt >= 5 or forbidden_sleep >= 30:
                    return r
                pause = min(6 * (attempt + 1), 30 - forbidden_sleep)
                forbidden_sleep += pause
                print(
                    f"  403 from {url} (attempt {attempt + 1}/6), backing off {pause}s",
                    file=sys.stderr,
                )
                time.sleep(pause)
                continue
            return r
        except requests.RequestException:
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError("giving up on " + url)


def _atomic_write(path, data):
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def cached(name, fetch):
    p = os.path.join(CACHE, name)
    if os.path.exists(p):
        with open(p, "rb") as f:
            return f.read()
    b = fetch()
    _atomic_write(p, b)
    return b


def raw_block(r):
    def f():
        resp = http(f"{ALGOD}/v2/blocks/{r}", {"format": "msgpack"})
        resp.raise_for_status()
        return resp.content

    return cached(f"block-{r}.mp", f)


_delta_mem = {}
DELTA_404_RETRIES = 12


def delta(r):
    if r not in _delta_mem:

        def f():
            # algonode load-balances over backends of which some lack a given
            # round, so the same URL alternates 200 and 404 (issue #1769: a
            # 43-minute capture died on a transient 404). A real gap still
            # fails after DELTA_404_RETRIES attempts.
            for attempt in range(DELTA_404_RETRIES):
                resp = http(f"{ALGOD}/v2/deltas/{r}", {"format": "msgpack"})
                if resp.status_code != 404:
                    break
                time.sleep(0.5 * min(attempt + 1, 4))
            resp.raise_for_status()
            return resp.content

        _delta_mem[r] = unpack(cached(f"delta-{r}.mp", f))
    return _delta_mem[r]


def kvmods(d):
    """KvMods with raw-byte keys (go encodes them as msgpack str)."""
    out = {}
    for k, v in (d.get("KvMods") or {}).items():
        if isinstance(k, str):
            k = k.encode("utf-8", "surrogateescape")
        out[k] = v
    return out


class IndexerError(Exception):
    """The indexer could not answer a query. Never treated as 'no history'."""


def idx_json(path, params=None):
    import json

    ident = json.dumps([path, sorted((params or {}).items())], default=str)
    name = "idx-" + hashlib.sha256(ident.encode()).hexdigest()

    def f():
        resp = http(f"{INDEXER}/v2/{path}", params)
        if resp.status_code == 404:
            return b'{"_404":true}'
        if resp.status_code >= 500:
            raise IndexerError(f"{resp.status_code} for {path} {params}")
        resp.raise_for_status()
        return resp.content

    d = json.loads(cached(name, f))
    if d.get("message") and not d.get("_404"):
        # e.g. "rewinding account is no longer supported": an error body
        raise IndexerError(f"{d['message']} for {path} {params}")
    return d


def addr_b32(raw):
    import base64 as b64

    chk = hashlib.new("sha512_256", raw).digest()[-4:]
    return b64.b32encode(raw + chk).decode().rstrip("=")


def app_address(app_id):
    return hashlib.new("sha512_256", b"appID" + app_id.to_bytes(8, "big")).digest()


# ---------------------------------------------------------------------------
# Rounds in which something happened (indexer), newest first
# ---------------------------------------------------------------------------


def account_rounds(addr, before, **flt):
    """Distinct confirmed rounds < before of txns involving addr, newest first."""
    seen = []
    token = None
    while True:
        p = {"max-round": before - 1, "limit": 100}
        p.update(flt)
        if token:
            p["next"] = token
        d = idx_json(f"accounts/{addr_b32(addr)}/transactions", p)
        if d.get("_404"):
            return
        for t in d.get("transactions", []):
            r = t["confirmed-round"]
            if not seen or seen[-1] != r:
                seen.append(r)
                yield r
        token = d.get("next-token")
        if not token or not d.get("transactions"):
            return


def global_rounds(kind, ident, before, created_at, **flt):
    """Rounds < before with txns on application/asset ident, newest first.

    /v2/transactions is ascending-only, so walk doubling windows backwards."""
    hi = before - 1
    w = 2
    while hi >= created_at:
        lo = max(created_at, hi - w + 1)
        rounds = set()
        token = None
        while True:
            p = {kind: ident, "min-round": lo, "max-round": hi, "limit": 1000}
            p.update(flt)
            if token:
                p["next"] = token
            d = idx_json("transactions", p)
            for t in d.get("transactions", []):
                rounds.add(t["confirmed-round"])
            token = d.get("next-token")
            if not token or not d.get("transactions"):
                break
        for r in sorted(rounds, reverse=True):
            yield r
        hi = lo - 1
        w *= 2


# ---------------------------------------------------------------------------
# Pre-state finders
# ---------------------------------------------------------------------------


def resource_account_rounds(addr, before, **flt):
    """Account rounds filtered by asset/app id; when the indexer cannot serve
    the filtered query (it 500s on very hot assets), fall back to every round
    the account was involved in."""
    try:
        yield from account_rounds(addr, before, **flt)
    except IndexerError:
        yield from account_rounds(addr, before)


def merged_account_rounds(addr, before):
    """Every round < before in which addr took part in a transaction in any role
    (sender, receiver, close-to, freeze target, app-call account, inner
    transactions), newest first. The role-less query is a superset of the
    rounds in which the base record can change."""
    yield from account_rounds(addr, before)


RES_PRESCAN = {}
_prescan = {}
PRESCAN = 40
EXTRA_HDRS = 16  # headers R-2..R-17 for the `block` opcode


def prescan(before):
    """Latest record per key over the last PRESCAN deltas (covers keys that
    change every block without a transaction: fee sink, rewards pool, block
    proposers)."""
    accts = {}
    for rr in range(before - 1, before - 1 - PRESCAN, -1):
        d = delta(rr)
        for rec in d["Accts"]["Accts"]:
            accts.setdefault(rec["Addr"], rec)
        for listname, parts in (
            ("AppResources", (("Params", "Params"), ("State", "LocalState"))),
            ("AssetResources", (("Params", "Params"), ("Holding", "Holding"))),
        ):
            for rec in d["Accts"].get(listname) or []:
                for part, inner in parts:
                    p = rec[part]
                    if p.get("Deleted") or p.get(inner) is not None:
                        RES_PRESCAN.setdefault((before, listname, part, rec["Addr"], rec["Aidx"]), p)
    return accts


WALK_LIMIT = 150
APPROX = []  # accounts resolved from the chain tip instead of history


def tip_record(addr):
    """Go-style base record built from the *current* algod account state.

    Only used for accounts the block merely references (not in the round's
    state delta, so their record is unchanged by it) whose own history holds
    no record write in the last WALK_LIMIT candidate rounds."""
    resp = http(f"{ALGOD}/v2/accounts/{addr_b32(addr)}", {"exclude": "all"})
    if resp.status_code != 200:
        return None
    a = resp.json()
    if (
        a["amount-without-pending-rewards"] == 0
        and not a.get("total-assets-opted-in")
        and not a.get("total-apps-opted-in")
        and not a.get("total-created-apps")
        and not a.get("total-created-assets")
        and not a.get("total-boxes")
        and a["status"] == "Offline"
        and not a.get("auth-addr")
    ):
        return None  # algod reports a zero record for accounts that do not exist
    status = {"Offline": 0, "Online": 1, "NotParticipating": 2}[a["status"]]
    z32 = bytes(32)
    sch = a.get("apps-total-schema") or {}
    schema = {}
    if sch.get("num-uint"):
        schema["nui"] = sch["num-uint"]
    if sch.get("num-byte-slice"):
        schema["nbs"] = sch["num-byte-slice"]
    part = a.get("participation") or {}
    return {
        "Addr": addr,
        "AuthAddr": _decode_addr(a["auth-addr"]) if a.get("auth-addr") else z32,
        "IncentiveEligible": bool(a.get("incentive-eligible", False)),
        "LastHeartbeat": a.get("last-heartbeat", 0),
        "LastProposed": a.get("last-proposed", 0),
        "MicroAlgos": a["amount-without-pending-rewards"],
        "RewardedMicroAlgos": a.get("rewards", 0),
        "RewardsBase": a.get("reward-base", 0),
        "SelectionID": base64.b64decode(part["selection-participation-key"]) if part else z32,
        "StateProofID": base64.b64decode(part["state-proof-key"]) if part and "state-proof-key" in part else bytes(64),
        "Status": status,
        "TotalAppLocalStates": a.get("total-apps-opted-in", 0),
        "TotalAppParams": a.get("total-created-apps", 0),
        "TotalAppSchema": schema,
        "TotalAssetParams": a.get("total-created-assets", 0),
        "TotalAssets": a.get("total-assets-opted-in", 0),
        "TotalBoxBytes": a.get("total-box-bytes", 0),
        "TotalBoxes": a.get("total-boxes", 0),
        "TotalExtraAppPages": a.get("apps-total-extra-pages", 0),
        "VoteFirstValid": part.get("vote-first-valid", 0) if part else 0,
        "VoteID": base64.b64decode(part["vote-participation-key"]) if part else z32,
        "VoteKeyDilution": part.get("vote-key-dilution", 0) if part else 0,
        "VoteLastValid": part.get("vote-last-valid", 0) if part else 0,
    }


def find_account(addr, before, exact=True):
    if before not in _prescan:
        _prescan[before] = prescan(before)
    if addr in _prescan[before]:
        return _prescan[before][addr]
    steps = 0
    for r in merged_account_rounds(addr, before):
        if r >= before - PRESCAN:
            continue
        steps += 1
        if not exact and steps > WALK_LIMIT:
            rec = tip_record(addr)
            if rec is not None:
                APPROX.append(addr)
            return rec
        for rec in delta(r)["Accts"]["Accts"]:
            if rec["Addr"] == addr:
                return rec
    return None


def _res(delta_r, listname, addr, aidx):
    for rec in delta_r["Accts"].get(listname) or []:
        if rec["Addr"] == addr and rec["Aidx"] == aidx:
            return rec
    return None


def find_part(listname, part, inner, addr, aidx, before, rounds, exact=True, tip=None):
    """First (newest) record part (e.g. 'Holding') with a non-None payload or
    a Deleted flag, scanning `rounds` newest first. Returns the part dict.

    When not `exact` (the key is only read by the block, not written) and
    WALK_LIMIT candidate rounds hold no record, fall back to `tip()` -- the
    current chain-tip value -- and note it in APPROX_RES. If the key no
    longer exists at the tip (deleted since), keep walking back exactly."""
    if before not in _prescan:
        _prescan[before] = prescan(before)
    hit = RES_PRESCAN.get((before, listname, part, addr, aidx))
    if hit is not None:
        return hit
    steps = 0
    written = exact  # keys the block writes are always walked to the end
    for r, raddr, raidx in rounds:
        if r >= before - PRESCAN:
            continue
        steps += 1
        if not exact and steps > WALK_LIMIT:
            exact = True
            if tip is not None:
                v = tip()
                if v is not None:
                    APPROX_RES.append(f"{listname}/{part}")
                    return {"Deleted": False, inner: v}
        if not written and steps > (HARD_LIMIT if part == "Params" else 400):
            UNRESOLVED_RES.append(f"{listname}/{part}/{addr_b32(addr)[:8]}/{aidx}")
            return None
        rec = _res(delta(r), listname, raddr, raidx)
        if rec is None:
            continue
        p = rec[part]
        if p.get("Deleted") or p.get(inner) is not None:
            return p
    return None


APPROX_RES = []
UNRESOLVED_RES = []
HARD_LIMIT = 8000  # read-only keys deleted since: give up after this many rounds


def _teal(kvs):
    out = {}
    for e in kvs or []:
        v = e["value"]
        key = base64.b64decode(e["key"])
        if v["type"] == 1:
            d = {"tt": 1}
            if v.get("bytes"):
                d["tb"] = base64.b64decode(v["bytes"])
            out[key] = d
        else:
            d = {"tt": 2}
            if v.get("uint"):
                d["ui"] = v["uint"]
            out[key] = d
    return out


def _sch(x):
    d = {}
    if x and x.get("num-uint"):
        d["nui"] = x["num-uint"]
    if x and x.get("num-byte-slice"):
        d["nbs"] = x["num-byte-slice"]
    return d


def tip_app_params(aidx):
    resp = http(f"{ALGOD}/v2/applications/{aidx}")
    if resp.status_code != 200:
        return None
    p = resp.json()["params"]
    d = {
        "approv": base64.b64decode(p["approval-program"]),
        "clearp": base64.b64decode(p["clear-state-program"]),
        "gsch": _sch(p.get("global-state-schema")),
        "lsch": _sch(p.get("local-state-schema")),
    }
    if p.get("global-state"):
        d["gs"] = _teal(p["global-state"])
    if p.get("extra-program-pages"):
        d["epp"] = p["extra-program-pages"]
    if p.get("version"):
        d["v"] = p["version"]
    return d


def tip_local_state(addr, aidx):
    resp = http(f"{ALGOD}/v2/accounts/{addr_b32(addr)}/applications/{aidx}")
    if resp.status_code != 200:
        return None
    ls = resp.json().get("app-local-state")
    if not ls:
        return None
    d = {"hsch": _sch(ls.get("schema"))}
    if ls.get("key-value"):
        d["tkv"] = _teal(ls["key-value"])
    return d


def tip_box(appid, name):
    resp = http(
        f"{ALGOD}/v2/applications/{appid}/box",
        {"name": "b64:" + base64.b64encode(name).decode()},
    )
    if resp.status_code != 200:
        return None
    return base64.b64decode(resp.json()["value"])


def tip_holding(addr, aidx):
    resp = http(f"{ALGOD}/v2/accounts/{addr_b32(addr)}/assets/{aidx}")
    if resp.status_code != 200:
        return None
    h = resp.json().get("asset-holding")
    if not h:
        return None
    d = {}
    if h.get("amount"):
        d["a"] = h["amount"]
    if h.get("is-frozen"):
        d["f"] = True
    return d


def tip_asset_params(aidx):
    resp = http(f"{ALGOD}/v2/assets/{aidx}")
    if resp.status_code != 200:
        return None
    p = resp.json()["params"]
    d = {}

    def put(k, v):
        if v:
            d[k] = v

    put("t", p.get("total"))
    put("dc", p.get("decimals"))
    put("df", p.get("default-frozen"))
    for k, a, b in (("un", "unit-name", "unit-name-b64"), ("an", "name", "name-b64"), ("au", "url", "url-b64")):
        if p.get(b):
            put(k, base64.b64decode(p[b]))
        elif p.get(a):
            put(k, p[a].encode())
    if p.get("metadata-hash"):
        d["am"] = base64.b64decode(p["metadata-hash"])
    for k, a in (("m", "manager"), ("r", "reserve"), ("f", "freeze"), ("c", "clawback")):
        if p.get(a):
            d[k] = _decode_addr(p[a])
    return d


def creator_of(kind, ident):
    if kind == "app":
        d = idx_json(f"applications/{ident}", {"include-all": "true"})
        if d.get("_404") or "application" not in d:
            return None, None
        a = d["application"]
        return _decode_addr(a["params"]["creator"]), a.get("created-at-round", 0)
    d = idx_json(f"assets/{ident}", {"include-all": "true"})
    if d.get("_404") or "asset" not in d:
        return None, None
    a = d["asset"]
    return _decode_addr(a["params"]["creator"]), a.get("created-at-round", 0)


def _decode_addr(s):
    pad = "=" * (-len(s) % 8)
    return base64.b32decode(s + pad)[:32]


# ---------------------------------------------------------------------------
# Static reference extraction from the block
# ---------------------------------------------------------------------------

_ADDR_FIELDS = ("snd", "rcv", "close", "arcv", "asnd", "aclose", "fadd", "rekey")
_APAR_ADDRS = ("m", "r", "f", "c")  # asset manager / reserve / freeze / clawback


def walk_txn(t, accts, apps, assets):
    """Add every account / app / asset a transaction names."""
    for k in _ADDR_FIELDS:
        v = t.get(k)
        if isinstance(v, bytes) and len(v) == 32:
            accts.add(v)
    for a in t.get("apat", []) or []:
        if isinstance(a, bytes) and len(a) == 32:
            accts.add(a)
    for k in _APAR_ADDRS:
        v = (t.get("apar") or {}).get(k)
        if isinstance(v, bytes) and len(v) == 32:
            accts.add(v)
    apps.update(t.get("apfa", []) or [])
    assets.update(t.get("apas", []) or [])
    for k in ("xaid", "caid", "faid"):
        if t.get(k):
            assets.add(t[k])
    if t.get("apid"):
        apps.add(t["apid"])
    for al in t.get("al", []) or []:
        if isinstance(al, dict):
            for v in al.values():
                if isinstance(v, bytes) and len(v) == 32:
                    accts.add(v)


def collect_refs(block):
    """Reference sets per transaction GROUP.

    AVM resource sharing lets every app call in a group use the resources
    named by any other transaction of the group, so each group's accounts,
    apps, assets and boxes are unioned (inner transactions join the group of
    their top-level parent)."""
    groups = {}
    order = []

    def visit(stib, bucket):
        t = stib.get("txn", {})
        accts, apps, assets, boxes = bucket
        walk_txn(t, accts, apps, assets)
        for bx in t.get("apbx", []) or []:
            idx = bx.get("i", 0)
            fa = t.get("apfa") or []
            appid = fa[idx - 1] if idx and idx <= len(fa) else t.get("apid", 0)
            boxes.add((appid, bx.get("n", b"")))
        for inner in (stib.get("dt") or {}).get("itx", []) or []:
            visit(inner, bucket)

    for n, stib in enumerate(block["txns"]):
        key = stib.get("txn", {}).get("grp") or ("solo", n)
        if key not in groups:
            groups[key] = (set(), set(), set(), set())
            order.append(key)
        visit(stib, groups[key])
    return [groups[k] for k in order]


# ---------------------------------------------------------------------------


def strip_state_proof_bodies(buf):
    """Remove the `sp` key/value of every `stpf` txn from a block response,
    byte-exactly (no re-encoding). Returns (new_bytes, count)."""
    u = msgpack.Unpacker(raw=False, strict_map_key=False, max_buffer_size=len(buf) + 1)
    u.feed(buf)
    cuts = []  # (txn_map_header_pos, key_start, value_end)
    for _ in range(u.read_map_header()):
        if u.unpack() != "block":
            u.skip()
            continue
        for _ in range(u.read_map_header()):
            if u.unpack() != "txns":
                u.skip()
                continue
            for _ in range(u.read_array_header()):
                for _ in range(u.read_map_header()):  # SignedTxnInBlock
                    if u.unpack() != "txn":
                        u.skip()
                        continue
                    hdr = u.tell()
                    n = u.read_map_header()
                    found = None
                    is_stpf = False
                    for _ in range(n):
                        kstart = u.tell()
                        k = u.unpack()
                        if k == "sp":
                            u.skip()
                            found = (kstart, u.tell())
                        elif k == "type":
                            is_stpf = u.unpack() == "stpf"
                        else:
                            u.skip()
                    if is_stpf and not found:
                        raise SystemExit(
                            "stpf transaction without an `sp` key: refusing to "
                            "store an unstripped state proof body"
                        )
                    if is_stpf:
                        cuts.append((hdr, found[0], found[1], n))
    out = bytearray(buf)
    for hdr, ks, ve, n in sorted(cuts, reverse=True):
        del out[ks:ve]  # the entries follow the header, so hdr stays valid
        if 0x80 <= buf[hdr] <= 0x8F and n < 16:  # fixmap
            out[hdr] = 0x80 | (n - 1)
        elif buf[hdr] == 0xDE:  # map16: 2-byte big-endian count
            assert int.from_bytes(buf[hdr + 1 : hdr + 3], "big") == n
            out[hdr + 1 : hdr + 3] = (n - 1).to_bytes(2, "big")
        else:
            raise SystemExit(f"unexpected txn map header byte {buf[hdr]:#x}")
    return bytes(out), len(cuts)


def capture(r):
    _prescan.clear()
    RES_PRESCAN.clear()
    APPROX.clear()
    APPROX_RES.clear()
    UNRESOLVED_RES.clear()
    os.makedirs(OUT_DIR, exist_ok=True)
    blk_bytes = raw_block(r)
    # A mainnet state proof transaction carries a ~300 KB proof body (`sp`),
    # far above the per-file size limit of this corpus. Execute-mode replay
    # (no proof verification) never reads it: the replay needs only the
    # transaction's message (`spmsg`) and the header's StateProofTracking.
    # The bodies are cut out of the stored block at the byte level (every
    # other byte is as served; only the `sp` key/value and the owning txn
    # map's entry count change) and counted in
    # `meta.stripped_state_proof_bodies` (the test pins the count). The block's
    # payset commitments (`txn`/`txn256`) therefore no longer match the
    # stored payset; Execute-mode replay never recomputes them.
    blk_bytes, stripped_sp = strip_state_proof_bodies(blk_bytes)
    block = unpack(blk_bytes)["block"]
    dr = delta(r)
    d_prev = delta(r - 1)

    need_accts = set()
    need_asset = {}  # (addr, aidx) -> {"holding","params"}
    need_app = {}  # (addr, aidx) -> {"state","params"}
    need_box = set()

    written_accts = {rec["Addr"] for rec in dr["Accts"]["Accts"]}
    exact_app, exact_asset = set(), set()  # (addr, aidx, part) written at r
    # keys the go delta says were written
    for rec in dr["Accts"]["Accts"]:
        need_accts.add(rec["Addr"])
    for rec in dr["Accts"].get("AppResources") or []:
        e = need_app.setdefault((rec["Addr"], rec["Aidx"]), set())
        if rec["Params"].get("Deleted") or rec["Params"].get("Params") is not None:
            e.add("params")
            exact_app.add((rec["Addr"], rec["Aidx"], "params"))
        if rec["State"].get("Deleted") or rec["State"].get("LocalState") is not None:
            e.add("state")
            exact_app.add((rec["Addr"], rec["Aidx"], "state"))
    for rec in dr["Accts"].get("AssetResources") or []:
        e = need_asset.setdefault((rec["Addr"], rec["Aidx"]), set())
        if rec["Params"].get("Deleted") or rec["Params"].get("Params") is not None:
            e.add("params")
            exact_asset.add((rec["Addr"], rec["Aidx"], "params"))
        if rec["Holding"].get("Deleted") or rec["Holding"].get("Holding") is not None:
            e.add("holding")
            exact_asset.add((rec["Addr"], rec["Aidx"], "holding"))
    dkv = kvmods(dr)
    for k in dkv:
        need_box.add(k)

    # keys the block references (reads)
    app_creators, asset_creators = {}, {}
    for accts, apps, assets, boxes in collect_refs(block):
        need_accts.update(accts)
        for a in apps:
            need_accts.add(app_address(a))
        for a in apps:
            c, created = creator_of("app", a)
            if c is not None and created < r:
                app_creators[a] = (c, created)
                need_app.setdefault((c, a), set()).add("params")
                need_accts.add(c)
        for a in assets:
            c, created = creator_of("asset", a)
            if c is not None and created < r:
                asset_creators[a] = (c, created)
                need_asset.setdefault((c, a), set()).add("params")
                need_accts.add(c)
        # holdings / local states of every account the txn names
        for ac in accts:
            for a in assets:
                if a in asset_creators:
                    need_asset.setdefault((ac, a), set()).add("holding")
            for a in apps:
                if a in app_creators:
                    need_app.setdefault((ac, a), set()).add("state")
        for appid, name in boxes:
            need_box.add(b"bx:" + appid.to_bytes(8, "big") + name)

    # app/asset creators for every resource key (needed for params lookups)
    for (addr, aidx), parts in list(need_app.items()):
        if aidx not in app_creators:
            c, created = creator_of("app", aidx)
            if c is not None:
                app_creators[aidx] = (c, created)
    for (addr, aidx), parts in list(need_asset.items()):
        if aidx not in asset_creators:
            c, created = creator_of("asset", aidx)
            if c is not None:
                asset_creators[aidx] = (c, created)

    print(f"keys: accts {len(need_accts)} app {len(need_app)} asset {len(need_asset)} box {len(need_box)}", flush=True)
    pre_accts = []
    missing_accts = []
    for a in sorted(need_accts):
        rec = find_account(a, r, exact=a in written_accts)
        if rec is None:
            missing_accts.append(a)
        else:
            pre_accts.append(rec)

    pre_app, pre_asset = [], []
    for (addr, aidx), parts in sorted(need_app.items()):
        rec = {"Addr": addr, "Aidx": aidx,
               "Params": {"Deleted": False, "Params": None},
               "State": {"Deleted": False, "LocalState": None}}
        found = False
        if "params" in parts:
            c, created = app_creators.get(aidx, (addr, 0))
            rounds = ((rr, c, aidx) for rr in global_rounds("application-id", aidx, r, created, **{"tx-type": "appl"}))
            p = find_part("AppResources", "Params", "Params", addr, aidx, r, rounds,
                          exact=(addr, aidx, "params") in exact_app,
                          tip=lambda: tip_app_params(aidx))
            if p is not None and not p.get("Deleted"):
                rec["Params"] = p
                found = True
        if "state" in parts:
            rounds = ((rr, addr, aidx) for rr in resource_account_rounds(addr, r, **{"application-id": aidx}))
            p = find_part("AppResources", "State", "LocalState", addr, aidx, r, rounds,
                          exact=(addr, aidx, "state") in exact_app,
                          tip=lambda: tip_local_state(addr, aidx))
            if p is not None and not p.get("Deleted"):
                rec["State"] = p
                found = True
        if found:
            pre_app.append(rec)
    print("apps done", flush=True)
    for (addr, aidx), parts in sorted(need_asset.items()):
        rec = {"Addr": addr, "Aidx": aidx,
               "Params": {"Deleted": False, "Params": None},
               "Holding": {"Deleted": False, "Holding": None}}
        found = False
        if "params" in parts:
            c, created = asset_creators.get(aidx, (addr, 0))
            rounds = ((rr, c, aidx) for rr in global_rounds("asset-id", aidx, r, created, **{"tx-type": "acfg"}))
            p = find_part("AssetResources", "Params", "Params", addr, aidx, r, rounds,
                          exact=(addr, aidx, "params") in exact_asset,
                          tip=lambda: tip_asset_params(aidx))
            if p is not None and not p.get("Deleted"):
                rec["Params"] = p
                found = True
        if "holding" in parts:
            rounds = ((rr, addr, aidx) for rr in resource_account_rounds(addr, r, **{"asset-id": aidx}))
            p = find_part("AssetResources", "Holding", "Holding", addr, aidx, r, rounds,
                          exact=(addr, aidx, "holding") in exact_asset,
                          tip=lambda: tip_holding(addr, aidx))
            if p is not None and not p.get("Deleted"):
                rec["Holding"] = p
                found = True
        if found:
            pre_asset.append(rec)

    print("assets done", flush=True)
    pre_kv = {}
    for key in sorted(need_box):
        kv = dkv.get(key)
        if kv is not None:
            # go records the value before the first write of this round
            pre_kv[key] = {"Data": kv.get("OldData")}
            continue
        appid = int.from_bytes(key[3:11], "big")
        c, created = app_creators.get(appid) or creator_of("app", appid)
        if c is None:
            continue
        steps = 0
        for rr in global_rounds("application-id", appid, r, created, **{"tx-type": "appl"}):
            if rr >= r - PRESCAN:
                m = kvmods(delta(rr)).get(key)
            else:
                steps += 1
                if steps > WALK_LIMIT:
                    v = tip_box(appid, key[11:])
                    if v is not None:
                        pre_kv[key] = {"Data": v}
                        APPROX_RES.append("box")
                    break
                m = kvmods(delta(rr)).get(key)
            if m is not None:
                if m.get("Data") is not None:
                    pre_kv[key] = {"Data": m["Data"]}
                break

    post = {
        "Accts": dr["Accts"].get("Accts") or [],
        "AppResources": dr["Accts"].get("AppResources") or [],
        "AssetResources": dr["Accts"].get("AssetResources") or [],
        "KvMods": {
            k: {"Data": v.get("Data"), "OldData": v.get("OldData")}
            for k, v in dkv.items()
        },
    }
    state = {
        "meta": {
            "round": r,
            "block_url": f"{ALGOD}/v2/blocks/{r}?format=msgpack",
            "delta_url": f"{ALGOD}/v2/deltas/{r}?format=msgpack",
            "captured": time.strftime("%Y-%m-%d", time.gmtime()),
            "unresolved_accounts": [addr_b32(a) for a in missing_accts],
            "tip_approximated_accounts": [addr_b32(a) for a in APPROX],
            "tip_approximated_resource_parts": len(APPROX_RES),
            "unresolved_resource_parts": list(UNRESOLVED_RES),
            "stripped_state_proof_bodies": stripped_sp,
        },
        "prev_hdr": d_prev["Hdr"],
        "extra_hdrs": [delta(r - k)["Hdr"] for k in range(2, 2 + EXTRA_HDRS)],
        "pre": {
            "Accts": pre_accts,
            "AppResources": pre_app,
            "AssetResources": pre_asset,
            "KvMods": pre_kv,
        },
        "post": post,
    }
    with open(os.path.join(OUT_DIR, f"{r}.msgpack"), "wb") as f:
        f.write(blk_bytes)
    sb = pack(state)
    with open(os.path.join(OUT_DIR, f"{r}.state.msgpack"), "wb") as f:
        f.write(sb)
    print(
        f"round {r}: block {len(blk_bytes)} B, state {len(sb)} B, "
        f"pre accts {len(pre_accts)} (unresolved {len(missing_accts)}), "
        f"app {len(pre_app)}, asset {len(pre_asset)}, kv {len(pre_kv)}"
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for arg in sys.argv[1:]:
        capture(int(arg))
