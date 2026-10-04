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

//! External sort of 36-byte trie elements for the catchpoint verify rebuild.
//!
//! Workers append elements to a [`RunBuffer`]; when it is full the buffer is
//! sorted and spilled to a run file. [`SortedRunMerger`] then k-way merges all
//! run files into one globally sorted stream. The merged order is a pure
//! function of the multiset of elements (equal elements are byte-identical,
//! so ties are unobservable), hence independent of how many threads produced
//! the runs.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use super::types::CatchpointError;
use crate::trie_hash::ELEMENT_SIZE;

/// One trie element.
pub(crate) type Element = [u8; ELEMENT_SIZE];

fn io_err(what: &str, e: std::io::Error) -> CatchpointError {
    CatchpointError::ImportError(format!("trie rebuild element sort: {what}: {e}"))
}

/// Temp directory holding the run files, removed on drop (success or error).
pub(crate) struct ElementSortDir {
    path: PathBuf,
}

impl ElementSortDir {
    /// Create a unique directory next to the database file, so the spill
    /// lands on the same volume as the ledger.
    pub(crate) fn create(db_path: &str) -> Result<Self, CatchpointError> {
        let parent = Path::new(db_path)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = parent.join(format!(
            ".catchpoint-verify-sort-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).map_err(|e| io_err("create temp dir", e))?;
        Ok(Self { path })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ElementSortDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Accumulates elements, spilling sorted runs of at most `capacity` elements.
pub(crate) struct RunBuffer<'a> {
    dir: &'a Path,
    tag: usize,
    capacity: usize,
    buf: Vec<Element>,
    runs: Vec<PathBuf>,
    total: u64,
}

impl<'a> RunBuffer<'a> {
    pub(crate) fn new(dir: &'a Path, tag: usize, capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            dir,
            tag,
            capacity,
            buf: Vec::with_capacity(capacity.min(1 << 20)),
            runs: Vec::new(),
            total: 0,
        }
    }

    pub(crate) fn push(&mut self, elem: Element) -> Result<(), CatchpointError> {
        self.buf.push(elem);
        self.total += 1;
        if self.buf.len() >= self.capacity {
            self.spill()?;
        }
        Ok(())
    }

    fn spill(&mut self) -> Result<(), CatchpointError> {
        if self.buf.is_empty() {
            return Ok(());
        }
        self.buf.sort_unstable();
        let path = self
            .dir
            .join(format!("run-{}-{}.bin", self.tag, self.runs.len()));
        let file = File::create(&path).map_err(|e| io_err("create run file", e))?;
        let mut w = BufWriter::with_capacity(1 << 20, file);
        for e in &self.buf {
            w.write_all(e).map_err(|e| io_err("write run", e))?;
        }
        w.flush().map_err(|e| io_err("flush run", e))?;
        self.runs.push(path);
        self.buf.clear();
        Ok(())
    }

    /// Spill the remainder; returns `(run files, total elements pushed)`.
    pub(crate) fn finish(mut self) -> Result<(Vec<PathBuf>, u64), CatchpointError> {
        self.spill()?;
        Ok((self.runs, self.total))
    }
}

/// k-way merge over sorted run files.
pub(crate) struct SortedRunMerger {
    readers: Vec<BufReader<File>>,
    heap: BinaryHeap<Reverse<(Element, usize)>>,
}

impl SortedRunMerger {
    pub(crate) fn open(runs: &[PathBuf]) -> Result<Self, CatchpointError> {
        let mut readers = Vec::with_capacity(runs.len());
        let mut heap = BinaryHeap::with_capacity(runs.len());
        for (i, p) in runs.iter().enumerate() {
            let mut r = BufReader::with_capacity(
                256 * 1024,
                File::open(p).map_err(|e| io_err("open run file", e))?,
            );
            if let Some(e) = read_element(&mut r)? {
                heap.push(Reverse((e, i)));
            }
            readers.push(r);
        }
        Ok(Self { readers, heap })
    }

    /// Next element in global sorted order.
    pub(crate) fn next_element(&mut self) -> Result<Option<Element>, CatchpointError> {
        let Some(Reverse((elem, idx))) = self.heap.pop() else {
            return Ok(None);
        };
        if let Some(next) = read_element(&mut self.readers[idx])? {
            self.heap.push(Reverse((next, idx)));
        }
        Ok(Some(elem))
    }
}

fn read_element<R: Read>(r: &mut R) -> Result<Option<Element>, CatchpointError> {
    let mut e = [0u8; ELEMENT_SIZE];
    let mut filled = 0;
    while filled < ELEMENT_SIZE {
        let n = r
            .read(&mut e[filled..])
            .map_err(|e| io_err("read run", e))?;
        if n == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(CatchpointError::ImportError(
                    "trie rebuild element sort: truncated run file".to_string(),
                ))
            };
        }
        filled += n;
    }
    Ok(Some(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudo(i: u64) -> Element {
        let mut e = [0u8; ELEMENT_SIZE];
        let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(7);
        for chunk in e.chunks_mut(8) {
            x ^= x >> 33;
            x = x.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
            let b = x.to_le_bytes();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
        e
    }

    #[test]
    fn merged_stream_is_globally_sorted_for_any_split() {
        let all: Vec<Element> = (0..1000u64).map(|i| pseudo(i % 900)).collect(); // has duplicates
        let mut expected = all.clone();
        expected.sort_unstable();

        for &(parts, cap) in &[(1usize, 10_000usize), (3, 64), (7, 1)] {
            let dir =
                ElementSortDir::create(std::env::temp_dir().join("x.sqlite").to_str().unwrap())
                    .unwrap();
            let mut runs = Vec::new();
            let mut total = 0;
            for p in 0..parts {
                let mut rb = RunBuffer::new(dir.path(), p, cap);
                for (i, e) in all.iter().enumerate() {
                    if i % parts == p {
                        rb.push(*e).unwrap();
                    }
                }
                let (r, t) = rb.finish().unwrap();
                runs.extend(r);
                total += t;
            }
            assert_eq!(total, all.len() as u64);
            let mut m = SortedRunMerger::open(&runs).unwrap();
            let mut got = Vec::new();
            while let Some(e) = m.next_element().unwrap() {
                got.push(e);
            }
            assert_eq!(got, expected, "parts={parts} cap={cap}");
            let p = dir.path().to_path_buf();
            drop(dir);
            assert!(!p.exists(), "temp dir removed on drop");
        }
    }
}
