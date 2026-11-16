#!/usr/bin/env python3
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.
"""Generate a synthetic, adversarial disassembly corpus (issue #2367, epic #2364).

The registry corpus only contains programs real compilers emitted. This tool
fills the rest of the input space with programs nobody would write, so the
go-vs-rust disassembly comparison also covers every opcode byte at every
version, every immediate byte value, and every way a real program can be cut
short:

    gen_synthetic.py OUT_DIR [--corpus CORPUS_DIR] [--seed N] [--random N]

writes `OUT_DIR/programs/<sha256>.bin` (the layout `scripts/teal-corpus/
run_drivers.sh` and the drivers read) with

* every (version 0..15, opcode byte, sub-opcode, immediate fill) combination,
* every value of each of the first three immediate bytes of every opcode, at
  the `--sweep-versions` (default 3, 8 and 14; field groups, curve ids, and plain numbers),
* when `--corpus` is given, every prefix (truncation) of a sample of its
  programs, and a few thousand random single-byte mutations of them,
* `--random` fully random byte strings (default 20000) from a fixed seed.

Deterministic for a given seed and corpus.
"""
import argparse
import hashlib
import os
import random
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--corpus")
    ap.add_argument("--seed", type=int, default=2367)
    ap.add_argument("--random", type=int, default=20000)
    ap.add_argument("--truncate-sample", type=int, default=60)
    ap.add_argument("--mutations", type=int, default=6000)
    ap.add_argument(
        "--sweep-versions",
        default="3,8,14",
        help="versions at which every immediate byte value is swept (comma separated)",
    )
    a = ap.parse_args()

    sweep_versions = {int(x) for x in a.sweep_versions.split(",") if x}
    pdir = os.path.join(a.out, "programs")
    os.makedirs(pdir, exist_ok=True)
    seen = set()

    def emit(p):
        sha = hashlib.sha256(p).hexdigest()
        if sha in seen:
            return
        seen.add(sha)
        with open(os.path.join(pdir, sha + ".bin"), "wb") as f:
            f.write(p)

    fills = [b"", b"\x00", b"\x01\x02", b"\x03\x00\x00\x00", b"\xff\xff\xff\xff\xff"]
    for v in range(0, 16):
        for b in range(256):
            for fill in fills:
                emit(bytes([v, b]) + fill)
            if b == 0xD4:
                for sub in range(0, 48):
                    emit(bytes([v, b, sub]))
                    emit(bytes([v, b, sub, 0x43]))
        # Immediate sweeps (at a few versions to bound the corpus size): every
        # value of the first, second and third immediate byte for every opcode
        # byte, with a valid-looking tail.
        for b in range(256) if v in sweep_versions else ():
            for val in range(256):
                emit(bytes([v, b, val, 0x43]))
                emit(bytes([v, b, 0x00, val, 0x43]))
                emit(bytes([v, b, 0x00, 0x00, val, 0x43]))

    rnd = random.Random(a.seed)
    if a.corpus:
        files = sorted(
            os.path.join(a.corpus, "programs", f)
            for f in os.listdir(os.path.join(a.corpus, "programs"))
            if f.endswith(".bin")
        )
        sample = rnd.sample(files, min(a.truncate_sample, len(files)))
        blobs = [open(f, "rb").read() for f in files]
        for f in sample:
            data = open(f, "rb").read()
            for cut in range(0, len(data)):
                emit(data[:cut])
        for _ in range(a.mutations):
            data = bytearray(rnd.choice(blobs))
            if not data:
                continue
            for _ in range(rnd.randint(1, 3)):
                data[rnd.randrange(len(data))] = rnd.randrange(256)
            emit(bytes(data))

    for _ in range(a.random):
        n = rnd.randint(1, 40)
        data = bytearray(rnd.randrange(256) for _ in range(n))
        data[0] = rnd.randint(0, 15)
        emit(bytes(data))
    print(f"{len(seen)} programs in {pdir}", file=sys.stderr)


if __name__ == "__main__":
    main()
