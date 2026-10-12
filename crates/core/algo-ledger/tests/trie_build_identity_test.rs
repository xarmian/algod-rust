// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Issue #1682: byte-identity matrix for the catchpoint-verify trie build.
//!
//! The chunked build (add in hash-sorted order, `commit` + `evict` every
//! chunk, lazy reload through the committer) must produce the exact same
//! root hash and the exact same stored `accounthashes` pages regardless of
//! how the trie internals are optimized. `GOLDEN` was captured from the
//! pre-optimization builder (the oracle); every case is re-run and compared
//! digest-for-digest. Set `TRIE_GOLDEN_PRINT=1` to print fresh digests.
//!
//! `trie_build_timing` (ignored) prints the per-chunk breakdown used in the
//! PR body: `cargo test --release -p algo-ledger --test trie_build_identity_test -- --ignored --nocapture`.

use algo_error::AlgoError;
use algo_ledger::merkle_cache::PageCommitter;
use algo_ledger::merkle_trie::MerkleTrie;
use sha2::{Digest, Sha256, Sha512_256};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct MapCommitter {
    pages: Arc<Mutex<BTreeMap<u64, Vec<u8>>>>,
    loads: Arc<std::sync::atomic::AtomicU64>,
}

impl PageCommitter for MapCommitter {
    fn load_page(&self, id: u64) -> Result<Option<Vec<u8>>, AlgoError> {
        self.loads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(self.pages.lock().unwrap().get(&id).cloned())
    }
    fn store_page(&self, id: u64, content: &[u8]) -> Result<(), AlgoError> {
        let mut p = self.pages.lock().unwrap();
        if content.is_empty() {
            p.remove(&id);
        } else {
            p.insert(id, content.to_vec());
        }
        Ok(())
    }
}

fn h(i: u64, salt: u8) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update([salt]);
    hasher.update(i.to_be_bytes());
    hasher.finalize().into()
}

/// Element families (all 36 bytes, returned sorted + deduplicated).
fn elements(kind: &str, n: u64) -> Vec<[u8; 36]> {
    let mut v: Vec<[u8; 36]> = (0..n)
        .map(|i| {
            let mut e = [0u8; 36];
            match kind {
                // Uniform random hashes.
                "random" => {
                    e[..32].copy_from_slice(&h(i, 1));
                    e[32..].copy_from_slice(&h(i, 2)[..4]);
                }
                // Real shape: clumped affinity+kind prefix, hash tail.
                "clumped" => {
                    e[0..4].copy_from_slice(&((i % 8) as u32).to_be_bytes());
                    e[4] = (i % 2) as u8;
                    e[5..36].copy_from_slice(&h(i, 3)[..31]);
                }
                // 30 identical leading bytes, only the tail differs.
                "same_prefix" => {
                    e[..30].fill(0xAB);
                    e[30..32].copy_from_slice(&((i & 0xffff) as u16).to_be_bytes());
                    e[32..].copy_from_slice(&h(i, 4)[..4]);
                }
                // Deep collisions: pairs sharing 35 bytes, differing in the last.
                "deep_pairs" => {
                    e[..32].copy_from_slice(&h(i / 2, 5));
                    e[32..35].copy_from_slice(&h(i / 2, 6)[..3]);
                    e[35] = (i % 2) as u8 * 0x80 + (i % 5) as u8;
                }
                // Dense counter (long shared prefix).
                "counter" => {
                    e[28..36].copy_from_slice(&i.to_be_bytes());
                }
                _ => unreachable!(),
            }
            e
        })
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

struct Outcome {
    root: [u8; 32],
    digest: String,
}

/// Chunked build mirroring `build_and_persist_trie_chunked`: add in the given
/// order, commit + evict every `chunk` elements, final commit; then digest the
/// root hash and every stored page (id order) byte-for-byte.
fn build(elems: &[[u8; 36]], chunk: usize, target: usize) -> Outcome {
    let committer = MapCommitter::default();
    let mut trie = MerkleTrie::with_cache_target(36, target);
    trie.set_lazy_loader(Box::new(committer.clone()));
    let mut since = 0usize;
    let mut stats_sum = 0usize;
    for e in elems {
        trie.add(e).unwrap();
        since += 1;
        if chunk != 0 && since >= chunk {
            let s = trie.commit(&committer).unwrap();
            stats_sum += s.new_page_count * 3 + s.updated_page_count * 5 + s.deleted_page_count * 7;
            trie.evict().unwrap();
            since = 0;
        }
    }
    let s = trie.commit(&committer).unwrap();
    stats_sum += s.new_page_count * 3 + s.updated_page_count * 5 + s.deleted_page_count * 7;
    let root = trie.root_hash().unwrap();
    let mut d = Sha256::new();
    d.update(root);
    d.update((stats_sum as u64).to_be_bytes());
    for (id, bytes) in committer.pages.lock().unwrap().iter() {
        d.update(id.to_be_bytes());
        d.update((bytes.len() as u64).to_be_bytes());
        d.update(bytes);
    }
    let digest: String = d.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Outcome { root, digest }
}

fn cases() -> Vec<(String, Vec<[u8; 36]>, usize, usize)> {
    let mut out = Vec::new();
    for kind in ["random", "clumped", "same_prefix", "deep_pairs", "counter"] {
        for &n in &[0u64, 1, 2, 3, 17, 99, 100, 101, 200, 201, 1000, 6000] {
            for &(chunk, target) in &[(0usize, 9000usize), (100, 200), (100, 9000), (1000, 500)] {
                out.push((
                    format!("{kind}/n{n}/chunk{chunk}/target{target}"),
                    elements(kind, n),
                    chunk,
                    target,
                ));
            }
        }
    }
    // Unsorted (reverse) insertion order exercises reload of arbitrary pages.
    for kind in ["random", "clumped"] {
        let mut e = elements(kind, 3000);
        e.reverse();
        out.push((
            format!("{kind}/reverse3000/chunk100/target200"),
            e,
            100,
            200,
        ));
    }
    out
}

#[test]
fn chunked_build_is_byte_identical_to_oracle() {
    let print = std::env::var_os("TRIE_GOLDEN_PRINT").is_some();
    let golden: BTreeMap<&str, &str> = GOLDEN.iter().copied().collect();
    let mut bad = Vec::new();
    for (name, elems, chunk, target) in cases() {
        let o = build(&elems, chunk, target);
        // Independent cross-check: chunking never changes the root.
        let single = build(&elems, 0, 9000);
        assert_eq!(
            o.root, single.root,
            "{name}: chunked root != single-pass root"
        );
        if print {
            println!("    (\"{name}\", \"{}\"),", o.digest);
        } else if golden.get(name.as_str()) != Some(&o.digest.as_str()) {
            bad.push(name);
        }
    }
    assert!(bad.is_empty(), "digest mismatch vs oracle: {bad:?}");
}

#[test]
#[ignore = "timing harness for the #1682 PR body"]
fn trie_build_timing() {
    use std::time::Instant;
    let n: u64 = std::env::var("TRIE_TIMING_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65536 * 6);
    let elems = elements("clumped", n);
    let committer = MapCommitter::default();
    let mut trie = MerkleTrie::new(36);
    trie.set_lazy_loader(Box::new(committer.clone()));
    let (mut t_add, mut t_commit, mut t_evict) = (0f64, 0f64, 0f64);
    let mut chunks = 0u32;
    let mut since = 0usize;
    let mut t = Instant::now();
    for e in &elems {
        trie.add(e).unwrap();
        since += 1;
        if since >= 65536 {
            t_add += t.elapsed().as_secs_f64();
            let t1 = Instant::now();
            trie.commit(&committer).unwrap();
            t_commit += t1.elapsed().as_secs_f64();
            let t2 = Instant::now();
            trie.evict().unwrap();
            t_evict += t2.elapsed().as_secs_f64();
            since = 0;
            chunks += 1;
            t = Instant::now();
        }
    }
    let c = chunks.max(1) as f64;
    println!(
        "chunks={chunks} lazy_page_loads={} per-chunk: add={:.3}s commit={:.3}s evict={:.3}s total={:.3}s",
        committer.loads.load(std::sync::atomic::Ordering::Relaxed),
        t_add / c,
        t_commit / c,
        t_evict / c,
        (t_add + t_commit + t_evict) / c
    );
}

const GOLDEN: &[(&str, &str)] = &[
    (
        "random/n0/chunk0/target9000",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "random/n0/chunk100/target200",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "random/n0/chunk100/target9000",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "random/n0/chunk1000/target500",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "random/n1/chunk0/target9000",
        "8d25e8587df93e9f0ffab18d106bcf8a2f9286c2bbedf97c6172bb609a1615cf",
    ),
    (
        "random/n1/chunk100/target200",
        "8d25e8587df93e9f0ffab18d106bcf8a2f9286c2bbedf97c6172bb609a1615cf",
    ),
    (
        "random/n1/chunk100/target9000",
        "8d25e8587df93e9f0ffab18d106bcf8a2f9286c2bbedf97c6172bb609a1615cf",
    ),
    (
        "random/n1/chunk1000/target500",
        "8d25e8587df93e9f0ffab18d106bcf8a2f9286c2bbedf97c6172bb609a1615cf",
    ),
    (
        "random/n2/chunk0/target9000",
        "cd01cb25e630f236cc766fdd2ced6336e812892243b13e80eaa5efa65d05598d",
    ),
    (
        "random/n2/chunk100/target200",
        "cd01cb25e630f236cc766fdd2ced6336e812892243b13e80eaa5efa65d05598d",
    ),
    (
        "random/n2/chunk100/target9000",
        "cd01cb25e630f236cc766fdd2ced6336e812892243b13e80eaa5efa65d05598d",
    ),
    (
        "random/n2/chunk1000/target500",
        "cd01cb25e630f236cc766fdd2ced6336e812892243b13e80eaa5efa65d05598d",
    ),
    (
        "random/n3/chunk0/target9000",
        "d9a15f4a43361863d76bf237a20753133e92858b9ab26ab23768c657dfbaf205",
    ),
    (
        "random/n3/chunk100/target200",
        "d9a15f4a43361863d76bf237a20753133e92858b9ab26ab23768c657dfbaf205",
    ),
    (
        "random/n3/chunk100/target9000",
        "d9a15f4a43361863d76bf237a20753133e92858b9ab26ab23768c657dfbaf205",
    ),
    (
        "random/n3/chunk1000/target500",
        "d9a15f4a43361863d76bf237a20753133e92858b9ab26ab23768c657dfbaf205",
    ),
    (
        "random/n17/chunk0/target9000",
        "31b74dc29e0c7f18fbefe7428b6b74fc3c10e70b2c7f307433320f43cedbb59d",
    ),
    (
        "random/n17/chunk100/target200",
        "31b74dc29e0c7f18fbefe7428b6b74fc3c10e70b2c7f307433320f43cedbb59d",
    ),
    (
        "random/n17/chunk100/target9000",
        "31b74dc29e0c7f18fbefe7428b6b74fc3c10e70b2c7f307433320f43cedbb59d",
    ),
    (
        "random/n17/chunk1000/target500",
        "31b74dc29e0c7f18fbefe7428b6b74fc3c10e70b2c7f307433320f43cedbb59d",
    ),
    (
        "random/n99/chunk0/target9000",
        "8a5729aec857728966291df1bf6e06a4fdbb951a0a6991a089dd3def89dbe980",
    ),
    (
        "random/n99/chunk100/target200",
        "8a5729aec857728966291df1bf6e06a4fdbb951a0a6991a089dd3def89dbe980",
    ),
    (
        "random/n99/chunk100/target9000",
        "8a5729aec857728966291df1bf6e06a4fdbb951a0a6991a089dd3def89dbe980",
    ),
    (
        "random/n99/chunk1000/target500",
        "8a5729aec857728966291df1bf6e06a4fdbb951a0a6991a089dd3def89dbe980",
    ),
    (
        "random/n100/chunk0/target9000",
        "16415102e8b4e2a0fe59f74776c0085c4bfb96679bf464ddf843333a9194225f",
    ),
    (
        "random/n100/chunk100/target200",
        "d36f1d7f97b9d26d87b8e47c0ef9b9b00b0c0dc93cf9312f55d1a8f44e2ebc24",
    ),
    (
        "random/n100/chunk100/target9000",
        "d36f1d7f97b9d26d87b8e47c0ef9b9b00b0c0dc93cf9312f55d1a8f44e2ebc24",
    ),
    (
        "random/n100/chunk1000/target500",
        "16415102e8b4e2a0fe59f74776c0085c4bfb96679bf464ddf843333a9194225f",
    ),
    (
        "random/n101/chunk0/target9000",
        "c48f8d6c9066c4dd7be1d6ae55072d0b85b2062798036665e4c6a74c7ae82221",
    ),
    (
        "random/n101/chunk100/target200",
        "0cedd40145d2bbd2cdbccfa732de4c9f5b513654390edb0ef46fb81442ccd7a5",
    ),
    (
        "random/n101/chunk100/target9000",
        "0cedd40145d2bbd2cdbccfa732de4c9f5b513654390edb0ef46fb81442ccd7a5",
    ),
    (
        "random/n101/chunk1000/target500",
        "c48f8d6c9066c4dd7be1d6ae55072d0b85b2062798036665e4c6a74c7ae82221",
    ),
    (
        "random/n200/chunk0/target9000",
        "2bf7d75a3998635b5eebdd0b581bbe3f6a58be7c4fef7fc2c096a6e2c2b5d971",
    ),
    (
        "random/n200/chunk100/target200",
        "f9950328626b80f7530557a81a908f1580f3d37baa90fd3c40551eacc409ebd2",
    ),
    (
        "random/n200/chunk100/target9000",
        "f9950328626b80f7530557a81a908f1580f3d37baa90fd3c40551eacc409ebd2",
    ),
    (
        "random/n200/chunk1000/target500",
        "2bf7d75a3998635b5eebdd0b581bbe3f6a58be7c4fef7fc2c096a6e2c2b5d971",
    ),
    (
        "random/n201/chunk0/target9000",
        "0e2e0c1628858d79b44c2367a0333122e130399c03725b8f0519338e938288e9",
    ),
    (
        "random/n201/chunk100/target200",
        "4ed94619b9816a7e7fa9d42c0dd859941a66c64438cbbb5d7788c228faff2e38",
    ),
    (
        "random/n201/chunk100/target9000",
        "4ed94619b9816a7e7fa9d42c0dd859941a66c64438cbbb5d7788c228faff2e38",
    ),
    (
        "random/n201/chunk1000/target500",
        "0e2e0c1628858d79b44c2367a0333122e130399c03725b8f0519338e938288e9",
    ),
    (
        "random/n1000/chunk0/target9000",
        "7e71cba440dd815a615413c04386ec08961fd9a53dd05521d4a29642f4e73bd2",
    ),
    (
        "random/n1000/chunk100/target200",
        "8e1d05d7e1fea6535adb9a0f005b87c4f584a37a0f341d35017749b98f274a6a",
    ),
    (
        "random/n1000/chunk100/target9000",
        "8e1d05d7e1fea6535adb9a0f005b87c4f584a37a0f341d35017749b98f274a6a",
    ),
    (
        "random/n1000/chunk1000/target500",
        "d9e21c4c3f07ccf94ebc966657706260a2ee15f0d4a342ae7db5dc278fcd0e93",
    ),
    (
        "random/n6000/chunk0/target9000",
        "2c959b078495eba25f4ea50c6959c0541c3bc57d584bf99915c546c0cc9c3053",
    ),
    (
        "random/n6000/chunk100/target200",
        "a60ef9f4de89bd79ff2ff2aeab25a019f2ac81ff92310e41219647f2d28f8021",
    ),
    (
        "random/n6000/chunk100/target9000",
        "a60ef9f4de89bd79ff2ff2aeab25a019f2ac81ff92310e41219647f2d28f8021",
    ),
    (
        "random/n6000/chunk1000/target500",
        "2c53819b6ef172697c7f421bbd04a364d0814f445da1c62180594b1a062c0931",
    ),
    (
        "clumped/n0/chunk0/target9000",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "clumped/n0/chunk100/target200",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "clumped/n0/chunk100/target9000",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "clumped/n0/chunk1000/target500",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "clumped/n1/chunk0/target9000",
        "77a8218785cdc6c94076bb718eb936e4103f845c0e217263f532b5cdbd52076e",
    ),
    (
        "clumped/n1/chunk100/target200",
        "77a8218785cdc6c94076bb718eb936e4103f845c0e217263f532b5cdbd52076e",
    ),
    (
        "clumped/n1/chunk100/target9000",
        "77a8218785cdc6c94076bb718eb936e4103f845c0e217263f532b5cdbd52076e",
    ),
    (
        "clumped/n1/chunk1000/target500",
        "77a8218785cdc6c94076bb718eb936e4103f845c0e217263f532b5cdbd52076e",
    ),
    (
        "clumped/n2/chunk0/target9000",
        "1e1efa0497f9e16001fb2ae7451248d76304e282ef65211afa138295825e5c50",
    ),
    (
        "clumped/n2/chunk100/target200",
        "1e1efa0497f9e16001fb2ae7451248d76304e282ef65211afa138295825e5c50",
    ),
    (
        "clumped/n2/chunk100/target9000",
        "1e1efa0497f9e16001fb2ae7451248d76304e282ef65211afa138295825e5c50",
    ),
    (
        "clumped/n2/chunk1000/target500",
        "1e1efa0497f9e16001fb2ae7451248d76304e282ef65211afa138295825e5c50",
    ),
    (
        "clumped/n3/chunk0/target9000",
        "5ad32b4e7790c944315f7cc44a7d0b9426d839269b65c9c93b09c4e36b11aaa2",
    ),
    (
        "clumped/n3/chunk100/target200",
        "5ad32b4e7790c944315f7cc44a7d0b9426d839269b65c9c93b09c4e36b11aaa2",
    ),
    (
        "clumped/n3/chunk100/target9000",
        "5ad32b4e7790c944315f7cc44a7d0b9426d839269b65c9c93b09c4e36b11aaa2",
    ),
    (
        "clumped/n3/chunk1000/target500",
        "5ad32b4e7790c944315f7cc44a7d0b9426d839269b65c9c93b09c4e36b11aaa2",
    ),
    (
        "clumped/n17/chunk0/target9000",
        "eca41a19dc04a2d66603cb23b8a11832ff630bf64680028f8730a8f0c4206a48",
    ),
    (
        "clumped/n17/chunk100/target200",
        "eca41a19dc04a2d66603cb23b8a11832ff630bf64680028f8730a8f0c4206a48",
    ),
    (
        "clumped/n17/chunk100/target9000",
        "eca41a19dc04a2d66603cb23b8a11832ff630bf64680028f8730a8f0c4206a48",
    ),
    (
        "clumped/n17/chunk1000/target500",
        "eca41a19dc04a2d66603cb23b8a11832ff630bf64680028f8730a8f0c4206a48",
    ),
    (
        "clumped/n99/chunk0/target9000",
        "6f359fe0c80eee602ba08aaed5d34888cca68e79b3f9e60f4e965f699f4e44e6",
    ),
    (
        "clumped/n99/chunk100/target200",
        "6f359fe0c80eee602ba08aaed5d34888cca68e79b3f9e60f4e965f699f4e44e6",
    ),
    (
        "clumped/n99/chunk100/target9000",
        "6f359fe0c80eee602ba08aaed5d34888cca68e79b3f9e60f4e965f699f4e44e6",
    ),
    (
        "clumped/n99/chunk1000/target500",
        "6f359fe0c80eee602ba08aaed5d34888cca68e79b3f9e60f4e965f699f4e44e6",
    ),
    (
        "clumped/n100/chunk0/target9000",
        "4c9b2bafd35d686ecdd74d925e1c842e50ab0b3aaee45318d56b9c276c3911a3",
    ),
    (
        "clumped/n100/chunk100/target200",
        "d264e8df237fe5bc06374c66fa7d865db932ec46655b1a57c5d1cda37c42b50c",
    ),
    (
        "clumped/n100/chunk100/target9000",
        "d264e8df237fe5bc06374c66fa7d865db932ec46655b1a57c5d1cda37c42b50c",
    ),
    (
        "clumped/n100/chunk1000/target500",
        "4c9b2bafd35d686ecdd74d925e1c842e50ab0b3aaee45318d56b9c276c3911a3",
    ),
    (
        "clumped/n101/chunk0/target9000",
        "8ddbf73d54e8e5c7141dee0fb84b6bdea4d1fce89eefe6eb4c7fc7d0dad40702",
    ),
    (
        "clumped/n101/chunk100/target200",
        "be9fa8a3a0667e6d5f5ef1b3ad29f3f7820d28b5323afa08afcc03d9dc6b9548",
    ),
    (
        "clumped/n101/chunk100/target9000",
        "be9fa8a3a0667e6d5f5ef1b3ad29f3f7820d28b5323afa08afcc03d9dc6b9548",
    ),
    (
        "clumped/n101/chunk1000/target500",
        "8ddbf73d54e8e5c7141dee0fb84b6bdea4d1fce89eefe6eb4c7fc7d0dad40702",
    ),
    (
        "clumped/n200/chunk0/target9000",
        "97600ef383fe27f6785acf8204789ae2a543e0c283c359416d3fe28d5e30da3c",
    ),
    (
        "clumped/n200/chunk100/target200",
        "ba8227d468450765d488f3e5668c485cdd973c720f883ff71b018675b55798ba",
    ),
    (
        "clumped/n200/chunk100/target9000",
        "ba8227d468450765d488f3e5668c485cdd973c720f883ff71b018675b55798ba",
    ),
    (
        "clumped/n200/chunk1000/target500",
        "97600ef383fe27f6785acf8204789ae2a543e0c283c359416d3fe28d5e30da3c",
    ),
    (
        "clumped/n201/chunk0/target9000",
        "ea1ca332bc8a8057dbe13bb1b2a84c907e5763ba2000312429ed2f0ca0a9c8cf",
    ),
    (
        "clumped/n201/chunk100/target200",
        "1ea7a8e62600c4bc8e4e98e35ffd6557a448269766d29472f0c3565bf786ce1b",
    ),
    (
        "clumped/n201/chunk100/target9000",
        "1ea7a8e62600c4bc8e4e98e35ffd6557a448269766d29472f0c3565bf786ce1b",
    ),
    (
        "clumped/n201/chunk1000/target500",
        "ea1ca332bc8a8057dbe13bb1b2a84c907e5763ba2000312429ed2f0ca0a9c8cf",
    ),
    (
        "clumped/n1000/chunk0/target9000",
        "55a76f39b8ee13c0e1dde26695271f1c2548ea89c5e17e2ace0d0f30e93ea81b",
    ),
    (
        "clumped/n1000/chunk100/target200",
        "d96eca33e712f3087b7884286d3c56e69148defacc72362b5fcdbba21e0f91a2",
    ),
    (
        "clumped/n1000/chunk100/target9000",
        "d96eca33e712f3087b7884286d3c56e69148defacc72362b5fcdbba21e0f91a2",
    ),
    (
        "clumped/n1000/chunk1000/target500",
        "21d8d095a518d2e2301b944f8bee91844d74aff5dbc6f4bc813407ef992429ec",
    ),
    (
        "clumped/n6000/chunk0/target9000",
        "aadee4b6616bde3c218e7fef3b7614f7a0d45682c19a67179e077ba409244a4a",
    ),
    (
        "clumped/n6000/chunk100/target200",
        "e32fbc4d5c4b6cfdadc920168efb8133fd012187061cc47e47450e5f577bb71d",
    ),
    (
        "clumped/n6000/chunk100/target9000",
        "e32fbc4d5c4b6cfdadc920168efb8133fd012187061cc47e47450e5f577bb71d",
    ),
    (
        "clumped/n6000/chunk1000/target500",
        "a7dfbf4ca176ed6177380d2f40d23344f2d2c52245462b58c47df52403cfe9b0",
    ),
    (
        "same_prefix/n0/chunk0/target9000",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "same_prefix/n0/chunk100/target200",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "same_prefix/n0/chunk100/target9000",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "same_prefix/n0/chunk1000/target500",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "same_prefix/n1/chunk0/target9000",
        "8f8f173ebef6c2c8f3eed01d0b9d1dde2e7ad7694ce7cea1de69f88270d1a264",
    ),
    (
        "same_prefix/n1/chunk100/target200",
        "8f8f173ebef6c2c8f3eed01d0b9d1dde2e7ad7694ce7cea1de69f88270d1a264",
    ),
    (
        "same_prefix/n1/chunk100/target9000",
        "8f8f173ebef6c2c8f3eed01d0b9d1dde2e7ad7694ce7cea1de69f88270d1a264",
    ),
    (
        "same_prefix/n1/chunk1000/target500",
        "8f8f173ebef6c2c8f3eed01d0b9d1dde2e7ad7694ce7cea1de69f88270d1a264",
    ),
    (
        "same_prefix/n2/chunk0/target9000",
        "fcd09b96f200de476c2c9917c0440ff5b00d203361b585ab9060ccf639dc9cac",
    ),
    (
        "same_prefix/n2/chunk100/target200",
        "fcd09b96f200de476c2c9917c0440ff5b00d203361b585ab9060ccf639dc9cac",
    ),
    (
        "same_prefix/n2/chunk100/target9000",
        "fcd09b96f200de476c2c9917c0440ff5b00d203361b585ab9060ccf639dc9cac",
    ),
    (
        "same_prefix/n2/chunk1000/target500",
        "fcd09b96f200de476c2c9917c0440ff5b00d203361b585ab9060ccf639dc9cac",
    ),
    (
        "same_prefix/n3/chunk0/target9000",
        "54683a1eae1e9a95f7695cac4f075bf9b89e7e4a86a887d2bbc315253cde0907",
    ),
    (
        "same_prefix/n3/chunk100/target200",
        "54683a1eae1e9a95f7695cac4f075bf9b89e7e4a86a887d2bbc315253cde0907",
    ),
    (
        "same_prefix/n3/chunk100/target9000",
        "54683a1eae1e9a95f7695cac4f075bf9b89e7e4a86a887d2bbc315253cde0907",
    ),
    (
        "same_prefix/n3/chunk1000/target500",
        "54683a1eae1e9a95f7695cac4f075bf9b89e7e4a86a887d2bbc315253cde0907",
    ),
    (
        "same_prefix/n17/chunk0/target9000",
        "d317a0fe4d27aa8b7a92ce6d7ef834289f65728f5f517f2e34d073c6225d6675",
    ),
    (
        "same_prefix/n17/chunk100/target200",
        "d317a0fe4d27aa8b7a92ce6d7ef834289f65728f5f517f2e34d073c6225d6675",
    ),
    (
        "same_prefix/n17/chunk100/target9000",
        "d317a0fe4d27aa8b7a92ce6d7ef834289f65728f5f517f2e34d073c6225d6675",
    ),
    (
        "same_prefix/n17/chunk1000/target500",
        "d317a0fe4d27aa8b7a92ce6d7ef834289f65728f5f517f2e34d073c6225d6675",
    ),
    (
        "same_prefix/n99/chunk0/target9000",
        "e2f257e0cd0ae91c792d18db6643cff061eaf706476e9a0cce28e0bd4cf5dbf2",
    ),
    (
        "same_prefix/n99/chunk100/target200",
        "e2f257e0cd0ae91c792d18db6643cff061eaf706476e9a0cce28e0bd4cf5dbf2",
    ),
    (
        "same_prefix/n99/chunk100/target9000",
        "e2f257e0cd0ae91c792d18db6643cff061eaf706476e9a0cce28e0bd4cf5dbf2",
    ),
    (
        "same_prefix/n99/chunk1000/target500",
        "e2f257e0cd0ae91c792d18db6643cff061eaf706476e9a0cce28e0bd4cf5dbf2",
    ),
    (
        "same_prefix/n100/chunk0/target9000",
        "e6d32b4f6bb3a8b999a1a093d14a6721423efe92b8a595c99519a2c0d8598370",
    ),
    (
        "same_prefix/n100/chunk100/target200",
        "c6fbefe914b6f0d25d05871940a9e009902d8279f08806478d8bb10f0944184b",
    ),
    (
        "same_prefix/n100/chunk100/target9000",
        "c6fbefe914b6f0d25d05871940a9e009902d8279f08806478d8bb10f0944184b",
    ),
    (
        "same_prefix/n100/chunk1000/target500",
        "e6d32b4f6bb3a8b999a1a093d14a6721423efe92b8a595c99519a2c0d8598370",
    ),
    (
        "same_prefix/n101/chunk0/target9000",
        "c3f0465ca989175c3e1b3bb0606eae07eb9dce5f82ecd6464404a0a94228f699",
    ),
    (
        "same_prefix/n101/chunk100/target200",
        "a7a1b75390a2bab45fcfeebd24b8a0234b4db3ad571fa835123f87b6bbc62de5",
    ),
    (
        "same_prefix/n101/chunk100/target9000",
        "a7a1b75390a2bab45fcfeebd24b8a0234b4db3ad571fa835123f87b6bbc62de5",
    ),
    (
        "same_prefix/n101/chunk1000/target500",
        "c3f0465ca989175c3e1b3bb0606eae07eb9dce5f82ecd6464404a0a94228f699",
    ),
    (
        "same_prefix/n200/chunk0/target9000",
        "8915ddb6e053172860c917718d08fa8f9e3155977bf035f3647903fc7f39cc72",
    ),
    (
        "same_prefix/n200/chunk100/target200",
        "e485a0ed3592b56f8c92e246423dc1de5e0ee73835d168f78ee089278375136f",
    ),
    (
        "same_prefix/n200/chunk100/target9000",
        "e485a0ed3592b56f8c92e246423dc1de5e0ee73835d168f78ee089278375136f",
    ),
    (
        "same_prefix/n200/chunk1000/target500",
        "8915ddb6e053172860c917718d08fa8f9e3155977bf035f3647903fc7f39cc72",
    ),
    (
        "same_prefix/n201/chunk0/target9000",
        "3b430f84171a1dafd9e8cf2f0382b671c952bf9497ca235dbe1f76525d70a79f",
    ),
    (
        "same_prefix/n201/chunk100/target200",
        "8291882b4827878c2e92c2b4c7d1a401f799f2e12dbcda98aa35faaa945249ad",
    ),
    (
        "same_prefix/n201/chunk100/target9000",
        "8291882b4827878c2e92c2b4c7d1a401f799f2e12dbcda98aa35faaa945249ad",
    ),
    (
        "same_prefix/n201/chunk1000/target500",
        "3b430f84171a1dafd9e8cf2f0382b671c952bf9497ca235dbe1f76525d70a79f",
    ),
    (
        "same_prefix/n1000/chunk0/target9000",
        "80b3a2d5c7dd7d583f299039c6fa7aee36582710a627dfc8b39a5bc88f91b09a",
    ),
    (
        "same_prefix/n1000/chunk100/target200",
        "295312249991dbe5188dce5524c1200ace27fb0ef3bfb82b97b4bca08620db4a",
    ),
    (
        "same_prefix/n1000/chunk100/target9000",
        "295312249991dbe5188dce5524c1200ace27fb0ef3bfb82b97b4bca08620db4a",
    ),
    (
        "same_prefix/n1000/chunk1000/target500",
        "917aa1f7d3ed8f8345683967d87acbad15a99a3bbe18a6cadb2e6d6a092e54a2",
    ),
    (
        "same_prefix/n6000/chunk0/target9000",
        "fd695fc14cca803e1961317113f60035403e09ac9dd0b775876b3f7447f1b607",
    ),
    (
        "same_prefix/n6000/chunk100/target200",
        "a2d18e8159f09d5281c31c8ccb83206738020c3813b69b361a3725c8e8ba66f1",
    ),
    (
        "same_prefix/n6000/chunk100/target9000",
        "a2d18e8159f09d5281c31c8ccb83206738020c3813b69b361a3725c8e8ba66f1",
    ),
    (
        "same_prefix/n6000/chunk1000/target500",
        "1880d8d14c1e746198bcd1a3907900fe6f243b2d07d9debacf7176209d8e8c32",
    ),
    (
        "deep_pairs/n0/chunk0/target9000",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "deep_pairs/n0/chunk100/target200",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "deep_pairs/n0/chunk100/target9000",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "deep_pairs/n0/chunk1000/target500",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "deep_pairs/n1/chunk0/target9000",
        "a9064195c0d4acdb03e9f99ff6bd819b163ba07db36252a0851d735759cef91e",
    ),
    (
        "deep_pairs/n1/chunk100/target200",
        "a9064195c0d4acdb03e9f99ff6bd819b163ba07db36252a0851d735759cef91e",
    ),
    (
        "deep_pairs/n1/chunk100/target9000",
        "a9064195c0d4acdb03e9f99ff6bd819b163ba07db36252a0851d735759cef91e",
    ),
    (
        "deep_pairs/n1/chunk1000/target500",
        "a9064195c0d4acdb03e9f99ff6bd819b163ba07db36252a0851d735759cef91e",
    ),
    (
        "deep_pairs/n2/chunk0/target9000",
        "c87ca2c22fbcc071a05d32391b15f55dc05eed11263128c5e1d59f30bfc01a21",
    ),
    (
        "deep_pairs/n2/chunk100/target200",
        "c87ca2c22fbcc071a05d32391b15f55dc05eed11263128c5e1d59f30bfc01a21",
    ),
    (
        "deep_pairs/n2/chunk100/target9000",
        "c87ca2c22fbcc071a05d32391b15f55dc05eed11263128c5e1d59f30bfc01a21",
    ),
    (
        "deep_pairs/n2/chunk1000/target500",
        "c87ca2c22fbcc071a05d32391b15f55dc05eed11263128c5e1d59f30bfc01a21",
    ),
    (
        "deep_pairs/n3/chunk0/target9000",
        "401a8821957351cf7db9d9932667fb47ed89226bb2d469f8c66771fcd643d92f",
    ),
    (
        "deep_pairs/n3/chunk100/target200",
        "401a8821957351cf7db9d9932667fb47ed89226bb2d469f8c66771fcd643d92f",
    ),
    (
        "deep_pairs/n3/chunk100/target9000",
        "401a8821957351cf7db9d9932667fb47ed89226bb2d469f8c66771fcd643d92f",
    ),
    (
        "deep_pairs/n3/chunk1000/target500",
        "401a8821957351cf7db9d9932667fb47ed89226bb2d469f8c66771fcd643d92f",
    ),
    (
        "deep_pairs/n17/chunk0/target9000",
        "49cf92e5ca611bcca11ba151b1309b009c6f288ec5436f372bad3f97331d2516",
    ),
    (
        "deep_pairs/n17/chunk100/target200",
        "49cf92e5ca611bcca11ba151b1309b009c6f288ec5436f372bad3f97331d2516",
    ),
    (
        "deep_pairs/n17/chunk100/target9000",
        "49cf92e5ca611bcca11ba151b1309b009c6f288ec5436f372bad3f97331d2516",
    ),
    (
        "deep_pairs/n17/chunk1000/target500",
        "49cf92e5ca611bcca11ba151b1309b009c6f288ec5436f372bad3f97331d2516",
    ),
    (
        "deep_pairs/n99/chunk0/target9000",
        "bd15e2f5967fcdb9ae8d09efa41b8c20348afb453d77df830581fe9ad22f35c8",
    ),
    (
        "deep_pairs/n99/chunk100/target200",
        "bd15e2f5967fcdb9ae8d09efa41b8c20348afb453d77df830581fe9ad22f35c8",
    ),
    (
        "deep_pairs/n99/chunk100/target9000",
        "bd15e2f5967fcdb9ae8d09efa41b8c20348afb453d77df830581fe9ad22f35c8",
    ),
    (
        "deep_pairs/n99/chunk1000/target500",
        "bd15e2f5967fcdb9ae8d09efa41b8c20348afb453d77df830581fe9ad22f35c8",
    ),
    (
        "deep_pairs/n100/chunk0/target9000",
        "c25be53ce82154b8d15f0a50e77db9c85870e72f27417abef1c2e35e213d4774",
    ),
    (
        "deep_pairs/n100/chunk100/target200",
        "d4e54f58d78de93dc732072c020c9370fa21b6c6b8bfc76c4af1d93439074a52",
    ),
    (
        "deep_pairs/n100/chunk100/target9000",
        "d4e54f58d78de93dc732072c020c9370fa21b6c6b8bfc76c4af1d93439074a52",
    ),
    (
        "deep_pairs/n100/chunk1000/target500",
        "c25be53ce82154b8d15f0a50e77db9c85870e72f27417abef1c2e35e213d4774",
    ),
    (
        "deep_pairs/n101/chunk0/target9000",
        "569087c5d5f446df3c38c3aa3c8446d510e25eed3ae51c697b4bba304b3a56ed",
    ),
    (
        "deep_pairs/n101/chunk100/target200",
        "2b085fbfff2c0a4a9ab9b94a46936149a6cf065d6e6fd74f4f761fe2fb24030c",
    ),
    (
        "deep_pairs/n101/chunk100/target9000",
        "2b085fbfff2c0a4a9ab9b94a46936149a6cf065d6e6fd74f4f761fe2fb24030c",
    ),
    (
        "deep_pairs/n101/chunk1000/target500",
        "569087c5d5f446df3c38c3aa3c8446d510e25eed3ae51c697b4bba304b3a56ed",
    ),
    (
        "deep_pairs/n200/chunk0/target9000",
        "749bb051c7f336a7a998e04f544b003f50c99e042e873f6ead3e23538d6ae6f4",
    ),
    (
        "deep_pairs/n200/chunk100/target200",
        "35d4fda998a9e12195a7af193528edd323d2cfadabbff48ec74fbc68687b9bf7",
    ),
    (
        "deep_pairs/n200/chunk100/target9000",
        "35d4fda998a9e12195a7af193528edd323d2cfadabbff48ec74fbc68687b9bf7",
    ),
    (
        "deep_pairs/n200/chunk1000/target500",
        "749bb051c7f336a7a998e04f544b003f50c99e042e873f6ead3e23538d6ae6f4",
    ),
    (
        "deep_pairs/n201/chunk0/target9000",
        "1e6cb59d9056f6b498e63d71f2556e4aab720f4cd6a4cf6fbec959ba64230b59",
    ),
    (
        "deep_pairs/n201/chunk100/target200",
        "69b46c96898fa2d2120dc112cf25933a01f4e811408b3fe4b296da2443c1ce5d",
    ),
    (
        "deep_pairs/n201/chunk100/target9000",
        "69b46c96898fa2d2120dc112cf25933a01f4e811408b3fe4b296da2443c1ce5d",
    ),
    (
        "deep_pairs/n201/chunk1000/target500",
        "1e6cb59d9056f6b498e63d71f2556e4aab720f4cd6a4cf6fbec959ba64230b59",
    ),
    (
        "deep_pairs/n1000/chunk0/target9000",
        "76ddfe87cfc42e540606615bd43b723a288001ddb8366817a85a9a732a403fee",
    ),
    (
        "deep_pairs/n1000/chunk100/target200",
        "f938c96862a5cb142a9bf59a6fb3354254626a2b3b038c5e59d5557d473b1fbf",
    ),
    (
        "deep_pairs/n1000/chunk100/target9000",
        "f938c96862a5cb142a9bf59a6fb3354254626a2b3b038c5e59d5557d473b1fbf",
    ),
    (
        "deep_pairs/n1000/chunk1000/target500",
        "716b4babd15b8566271eca73d37d88faec272fa6ab7d597823e633babee3aa6b",
    ),
    (
        "deep_pairs/n6000/chunk0/target9000",
        "d45278dc9e6f8fb2165ab295648319d1c1e26d3eb657b3d85a0dcb057dfb87d5",
    ),
    (
        "deep_pairs/n6000/chunk100/target200",
        "ee36456b0bfd05919e3c0da99cabf53c33397987c91560491cbf24b0b07da171",
    ),
    (
        "deep_pairs/n6000/chunk100/target9000",
        "ee36456b0bfd05919e3c0da99cabf53c33397987c91560491cbf24b0b07da171",
    ),
    (
        "deep_pairs/n6000/chunk1000/target500",
        "a421db49686c67c91a7ddd7e37be89599d2ad1fa1bd5be68454daa53bb859352",
    ),
    (
        "counter/n0/chunk0/target9000",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "counter/n0/chunk100/target200",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "counter/n0/chunk100/target9000",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "counter/n0/chunk1000/target500",
        "eb023ab0839378db93c7c6e545075dd67fbd075102d6465c39add431e6b63ab4",
    ),
    (
        "counter/n1/chunk0/target9000",
        "fae51c5d0c3e0ebd5d36acf4057735e59ae05daca8d3f3ec8c90f474f89fa1dd",
    ),
    (
        "counter/n1/chunk100/target200",
        "fae51c5d0c3e0ebd5d36acf4057735e59ae05daca8d3f3ec8c90f474f89fa1dd",
    ),
    (
        "counter/n1/chunk100/target9000",
        "fae51c5d0c3e0ebd5d36acf4057735e59ae05daca8d3f3ec8c90f474f89fa1dd",
    ),
    (
        "counter/n1/chunk1000/target500",
        "fae51c5d0c3e0ebd5d36acf4057735e59ae05daca8d3f3ec8c90f474f89fa1dd",
    ),
    (
        "counter/n2/chunk0/target9000",
        "59627c7739bcf1c9a5adc57fc3971afdbe7f88dfe90fd79eaa6f6cb6aeea951b",
    ),
    (
        "counter/n2/chunk100/target200",
        "59627c7739bcf1c9a5adc57fc3971afdbe7f88dfe90fd79eaa6f6cb6aeea951b",
    ),
    (
        "counter/n2/chunk100/target9000",
        "59627c7739bcf1c9a5adc57fc3971afdbe7f88dfe90fd79eaa6f6cb6aeea951b",
    ),
    (
        "counter/n2/chunk1000/target500",
        "59627c7739bcf1c9a5adc57fc3971afdbe7f88dfe90fd79eaa6f6cb6aeea951b",
    ),
    (
        "counter/n3/chunk0/target9000",
        "383b6c9f77d5efae6d40b0798acbf5bdfa0128fcd67bb84aecc715b0649e1612",
    ),
    (
        "counter/n3/chunk100/target200",
        "383b6c9f77d5efae6d40b0798acbf5bdfa0128fcd67bb84aecc715b0649e1612",
    ),
    (
        "counter/n3/chunk100/target9000",
        "383b6c9f77d5efae6d40b0798acbf5bdfa0128fcd67bb84aecc715b0649e1612",
    ),
    (
        "counter/n3/chunk1000/target500",
        "383b6c9f77d5efae6d40b0798acbf5bdfa0128fcd67bb84aecc715b0649e1612",
    ),
    (
        "counter/n17/chunk0/target9000",
        "1d6f8ef6aa718105f22ac3246780b148bdc6993362ef615bb8165b80250f4507",
    ),
    (
        "counter/n17/chunk100/target200",
        "1d6f8ef6aa718105f22ac3246780b148bdc6993362ef615bb8165b80250f4507",
    ),
    (
        "counter/n17/chunk100/target9000",
        "1d6f8ef6aa718105f22ac3246780b148bdc6993362ef615bb8165b80250f4507",
    ),
    (
        "counter/n17/chunk1000/target500",
        "1d6f8ef6aa718105f22ac3246780b148bdc6993362ef615bb8165b80250f4507",
    ),
    (
        "counter/n99/chunk0/target9000",
        "51502ad4866f078d2b31054a19335adca8ee57609585cc96e6586883427b11f2",
    ),
    (
        "counter/n99/chunk100/target200",
        "51502ad4866f078d2b31054a19335adca8ee57609585cc96e6586883427b11f2",
    ),
    (
        "counter/n99/chunk100/target9000",
        "51502ad4866f078d2b31054a19335adca8ee57609585cc96e6586883427b11f2",
    ),
    (
        "counter/n99/chunk1000/target500",
        "51502ad4866f078d2b31054a19335adca8ee57609585cc96e6586883427b11f2",
    ),
    (
        "counter/n100/chunk0/target9000",
        "482fe87883b371dc0dafd17638fd375b81abbc1536206be0e6726e1afab39dcf",
    ),
    (
        "counter/n100/chunk100/target200",
        "3c509b4d3ae474aacee568f36628fab3ede6fb9ac1bfc76354529519bc5899c8",
    ),
    (
        "counter/n100/chunk100/target9000",
        "3c509b4d3ae474aacee568f36628fab3ede6fb9ac1bfc76354529519bc5899c8",
    ),
    (
        "counter/n100/chunk1000/target500",
        "482fe87883b371dc0dafd17638fd375b81abbc1536206be0e6726e1afab39dcf",
    ),
    (
        "counter/n101/chunk0/target9000",
        "0a558af34763bc322afb92f339c2bf6c19116f9c962baed77788c3f5bd9b0236",
    ),
    (
        "counter/n101/chunk100/target200",
        "75c37df0174581d8a16995cb166e1506427b108d382828dcd1e453bcffaa6f8f",
    ),
    (
        "counter/n101/chunk100/target9000",
        "75c37df0174581d8a16995cb166e1506427b108d382828dcd1e453bcffaa6f8f",
    ),
    (
        "counter/n101/chunk1000/target500",
        "0a558af34763bc322afb92f339c2bf6c19116f9c962baed77788c3f5bd9b0236",
    ),
    (
        "counter/n200/chunk0/target9000",
        "6c892cc10b6ed65d37194cbc0a768e5d8593d27ea88ec93c65d70b5db8ac9b77",
    ),
    (
        "counter/n200/chunk100/target200",
        "66da627584170d2a940c6d175a4767364eda6fc0cf39ec04217a9f4490ab68de",
    ),
    (
        "counter/n200/chunk100/target9000",
        "66da627584170d2a940c6d175a4767364eda6fc0cf39ec04217a9f4490ab68de",
    ),
    (
        "counter/n200/chunk1000/target500",
        "6c892cc10b6ed65d37194cbc0a768e5d8593d27ea88ec93c65d70b5db8ac9b77",
    ),
    (
        "counter/n201/chunk0/target9000",
        "d257ed2c5e1ae4bdbe6d70585900bc70dcc73dc6032843c5b7467e0220cd02e7",
    ),
    (
        "counter/n201/chunk100/target200",
        "cf6f4912f61ac9ebe05c1773fb6e548d716248188b6a6235595252e11b6837db",
    ),
    (
        "counter/n201/chunk100/target9000",
        "cf6f4912f61ac9ebe05c1773fb6e548d716248188b6a6235595252e11b6837db",
    ),
    (
        "counter/n201/chunk1000/target500",
        "d257ed2c5e1ae4bdbe6d70585900bc70dcc73dc6032843c5b7467e0220cd02e7",
    ),
    (
        "counter/n1000/chunk0/target9000",
        "a4305fa9564a5c35aab87d6ff67da0d59909848dcf9fe8eadaffe29c995c9aa3",
    ),
    (
        "counter/n1000/chunk100/target200",
        "de22da3ffce7b39c81b2c5c5ddedda6f9779e992ae781c98026fc3f8f3cc83d2",
    ),
    (
        "counter/n1000/chunk100/target9000",
        "de22da3ffce7b39c81b2c5c5ddedda6f9779e992ae781c98026fc3f8f3cc83d2",
    ),
    (
        "counter/n1000/chunk1000/target500",
        "82e10f4e25a412ce84962004066f1ca5dda735066a0a2468c0e0b863fe2bf433",
    ),
    (
        "counter/n6000/chunk0/target9000",
        "17464cb8d7d4d1cf23446310806d888091a89b7e89c34b026efdb6fe13b21a5f",
    ),
    (
        "counter/n6000/chunk100/target200",
        "78ae8ce9d8d12c177487faa693c6761e323512ec80b1bbaf3160e884ca6e354b",
    ),
    (
        "counter/n6000/chunk100/target9000",
        "78ae8ce9d8d12c177487faa693c6761e323512ec80b1bbaf3160e884ca6e354b",
    ),
    (
        "counter/n6000/chunk1000/target500",
        "de71dbddf6cace12a14637c2ffa5d7ea822f8b2924f2f46ec7a2e3f22ea68dda",
    ),
    (
        "random/reverse3000/chunk100/target200",
        "23ae21ec488c0685f19d12d05b61fbb82f4cd81aa499a9888d2793075d4d27bf",
    ),
    (
        "clumped/reverse3000/chunk100/target200",
        "bbdde99cffce746bc3fe6cd8ce9cfb488b2933a9e03a48bfd338a3f32c621f80",
    ),
];
