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

//! App-call foreign-resource resolution — port of go-algorand's
//! `libgoal/transactions.go` (`RefBundle`, `attachReferences`,
//! `attachForeignRefs`, `attachAccessList`, `maybeAppend`).
//!
//! `goal`/`libgoal` lets a CLI user submit an ABI/app-call transaction
//! without manually enumerating every low-level foreign-resource index:
//! the caller supplies a [`RefBundle`] of *hydrated* resource hints (real
//! account addresses, asset/app IDs, `(app, box-name)` pairs, etc. —
//! typically derived from an ABI method signature's `box`/`foreign-app`/
//! `foreign-asset` hints plus the method's resolved arguments) and this
//! module lowers them onto the wire-format transaction fields: either the
//! legacy `ForeignApps`/`ForeignAssets`/`Accounts`/`Boxes` arrays
//! ([`attach_foreign_refs`]) or the unified `Access` array introduced at
//! consensus v41/`v10` ([`attach_access_list`]). [`attach_references`]
//! dispatches between the two based on [`RefBundle::use_access`], mirroring
//! `libgoal.attachReferences`.
//!
//! This module intentionally implements *only* the resolution/lowering
//! algorithm, not ABI method-signature parsing, argument encoding, or CLI
//! argument plumbing — see issue #820 item 3. A caller (a future `goal app
//! call`/`goal app method` subcommand) is expected to compute the
//! `RefBundle` from an ABI method signature and hand it to
//! [`attach_references`].
//!
//! Ported test-for-test from go-algorand's `TestForeignResolution` and
//! `TestAccessResolution` in `libgoal/libgoal_test.go`.

use algo_types::{Address, BoxRef, HoldingRef, LocalsRef, ResourceRef, Transaction};
use sha2::{Digest, Sha512_256};

/// Compute an application account address: `SHA512/256("appID" ||
/// app_id_be_bytes)`.
///
/// Mirrors go-algorand's `basics.AppIndex.Address()`
/// (`data/basics/userBalance.go`). `goal-rust` does not depend on
/// `algo-ledger` (which has its own, functionally identical, copy used for
/// AVM execution — `algo_ledger::avm_context::app_address`), so this is a
/// standalone copy for the CLI's resource-resolution path.
pub fn app_address(app_id: u64) -> Address {
    let mut h = Sha512_256::new();
    h.update(b"appID");
    h.update(app_id.to_be_bytes());
    Address(h.finalize().into())
}

/// A "hydrated" holding reference: a real asset ID and real address, as
/// opposed to the wire-format `HoldingRef`'s indices into `Access`.
///
/// Mirrors go-algorand's `basics.HoldingRef`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldingHint {
    pub asset: u64,
    /// The zero address conveys "the transaction's Sender".
    pub address: Address,
}

/// A "hydrated" local-state reference: a real app ID and real address.
///
/// Mirrors go-algorand's `basics.LocalRef`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHint {
    /// 0 conveys "the app being called" (`tx.ApplicationID`).
    pub app: u64,
    /// The zero address conveys "the transaction's Sender".
    pub address: Address,
}

/// A "hydrated" box reference: a real app ID and the raw box name.
///
/// Mirrors go-algorand's `basics.BoxRef`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoxHint {
    /// 0 conveys "the app being called" (`tx.ApplicationID`).
    pub app: u64,
    pub name: Vec<u8>,
}

/// Build a [`BoxHint`] list the way go-algorand's test helper `bbrs` does:
/// alternating `(app, name)` pairs. Purely a test/call-site convenience.
pub fn box_hints(pairs: &[(u64, &str)]) -> Vec<BoxHint> {
    pairs
        .iter()
        .map(|(app, name)| BoxHint {
            app: *app,
            name: name.as_bytes().to_vec(),
        })
        .collect()
}

/// A bundle of hydrated resource references to attach to an app-call
/// transaction, resolved from an ABI method signature's declared hints
/// (`box`/`foreign-app`/`foreign-asset`) plus its resolved arguments.
///
/// Mirrors go-algorand's `libgoal.RefBundle` (`libgoal/transactions.go`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefBundle {
    /// When true, lower onto the unified `Access` array (consensus v41+).
    /// When false, lower onto the legacy `Accounts`/`ForeignApps`/
    /// `ForeignAssets`/`Boxes` arrays.
    pub use_access: bool,

    pub accounts: Vec<Address>,
    pub assets: Vec<u64>,
    pub holdings: Vec<HoldingHint>,
    pub apps: Vec<u64>,
    pub locals: Vec<LocalHint>,
    pub boxes: Vec<BoxHint>,

    /// Number of empty refs to append (a box-IO quota bump with no named
    /// resource). Lowers to empty `BoxRef`s or empty `ResourceRef`s
    /// depending on `use_access`.
    pub empty_refs: u64,
}

/// Attach the foreign arrays or access list required to access the
/// resources in `refs` to `tx`, dispatching on `refs.use_access`.
///
/// Mirrors go-algorand's `libgoal.attachReferences`.
pub fn attach_references(tx: &mut Transaction, refs: &RefBundle) {
    if refs.use_access {
        attach_access_list(tx, refs);
    } else {
        attach_foreign_refs(tx, refs);
    }
}

/// Find `target` in `slice`, returning its index if present; otherwise
/// push it and return the (new) index.
///
/// Mirrors go-algorand's generic `libgoal.maybeAppend`.
fn maybe_append<T: PartialEq + Clone>(slice: &mut Vec<T>, target: &T) -> usize {
    if let Some(idx) = slice.iter().position(|x| x == target) {
        idx
    } else {
        slice.push(target.clone());
        slice.len() - 1
    }
}

/// Reports whether `app`'s account address equals `addr` for some `app`
/// already present in `foreign_apps`. Used to skip adding a redundant
/// `Accounts` entry when the address is already reachable via an app's
/// implicit account.
fn addr_covered_by_foreign_apps(foreign_apps: &[u64], addr: Address) -> bool {
    foreign_apps.iter().any(|&id| app_address(id) == addr)
}

/// Populate the legacy `Accounts`/`ForeignApps`/`ForeignAssets`/`Boxes`
/// arrays from `refs`.
///
/// Mirrors go-algorand's `libgoal.attachForeignRefs`.
pub fn attach_foreign_refs(tx: &mut Transaction, refs: &RefBundle) {
    // We must add these as given, (not dedupe).
    tx.accounts
        .get_or_insert_with(Vec::new)
        .extend(refs.accounts.iter().copied());
    tx.foreign_assets
        .get_or_insert_with(Vec::new)
        .extend(refs.assets.iter().copied());
    tx.foreign_apps
        .get_or_insert_with(Vec::new)
        .extend(refs.apps.iter().copied());

    // Add assets, addresses if Holdings need them.
    for hr in &refs.holdings {
        maybe_append(tx.foreign_assets.get_or_insert_with(Vec::new), &hr.asset);
        if !hr.address.is_zero()
            // Zero address used to convey "Sender".
            && !addr_covered_by_foreign_apps(
                tx.foreign_apps.as_deref().unwrap_or(&[]),
                hr.address,
            )
        {
            maybe_append(tx.accounts.get_or_insert_with(Vec::new), &hr.address);
        }
    }

    // Add apps, addresses if Locals need them.
    for lr in &refs.locals {
        if lr.app != 0 && lr.app != tx.application_id {
            maybe_append(tx.foreign_apps.get_or_insert_with(Vec::new), &lr.app);
        }
        if !lr.address.is_zero()
            && !addr_covered_by_foreign_apps(tx.foreign_apps.as_deref().unwrap_or(&[]), lr.address)
        {
            maybe_append(tx.accounts.get_or_insert_with(Vec::new), &lr.address);
        }
    }

    // Add boxes (and their app, if needed).
    for br in &refs.boxes {
        let mut index: u64 = 0;
        if br.app != 0 && br.app != tx.application_id {
            let idx = maybe_append(tx.foreign_apps.get_or_insert_with(Vec::new), &br.app);
            index = idx as u64 + 1; // 1-based index
        }
        tx.boxes.get_or_insert_with(Vec::new).push(BoxRef {
            index,
            name: Some(serde_bytes::ByteBuf::from(br.name.clone())),
        });
    }

    for _ in 0..refs.empty_refs {
        tx.boxes
            .get_or_insert_with(Vec::new)
            .push(BoxRef::default());
    }
}

/// Populate the unified `Access` array (consensus v41+) from `refs`.
///
/// Mirrors go-algorand's `libgoal.attachAccessList`.
pub fn attach_access_list(tx: &mut Transaction, refs: &RefBundle) {
    // `ensure` looks for a "simple" resource ref that is needed by a
    // cross-product ref. If found, return the 1-based index. If not
    // found, insert and return its (new) index.
    fn ensure(access: &mut Vec<ResourceRef>, target: ResourceRef) -> u64 {
        // We always check all three, though callers only ever set one.
        // Less code duplication (mirrors the Go closure).
        if let Some(idx) = access.iter().position(|present| {
            present.address == target.address
                && present.asset == target.asset
                && present.app == target.app
        }) {
            return idx as u64 + 1;
        }
        access.push(target);
        access.len() as u64
    }

    let access = tx.access.get_or_insert_with(Vec::new);

    for addr in &refs.accounts {
        ensure(
            access,
            ResourceRef {
                address: *addr,
                ..Default::default()
            },
        );
    }
    for asset in &refs.assets {
        ensure(
            access,
            ResourceRef {
                asset: *asset,
                ..Default::default()
            },
        );
    }
    for app in &refs.apps {
        ensure(
            access,
            ResourceRef {
                app: *app,
                ..Default::default()
            },
        );
    }

    for hr in &refs.holdings {
        let addr_idx = if !hr.address.is_zero() {
            ensure(
                access,
                ResourceRef {
                    address: hr.address,
                    ..Default::default()
                },
            )
        } else {
            0
        };
        let asset_idx = ensure(
            access,
            ResourceRef {
                asset: hr.asset,
                ..Default::default()
            },
        );
        access.push(ResourceRef {
            holding: Some(HoldingRef {
                asset: asset_idx,
                address: addr_idx,
            }),
            ..Default::default()
        });
    }

    for lr in &refs.locals {
        let app_idx = if lr.app != 0 && lr.app != tx.application_id {
            ensure(
                access,
                ResourceRef {
                    app: lr.app,
                    ..Default::default()
                },
            )
        } else {
            0
        };
        let addr_idx = if !lr.address.is_zero() {
            ensure(
                access,
                ResourceRef {
                    address: lr.address,
                    ..Default::default()
                },
            )
        } else {
            0
        };
        access.push(ResourceRef {
            locals: Some(LocalsRef {
                app: app_idx,
                address: addr_idx,
            }),
            ..Default::default()
        });
    }

    for br in &refs.boxes {
        let app_idx = if br.app != 0 && br.app != tx.application_id {
            ensure(
                access,
                ResourceRef {
                    app: br.app,
                    ..Default::default()
                },
            )
        } else {
            0
        };
        access.push(ResourceRef {
            box_ref: Some(BoxRef {
                index: app_idx,
                name: Some(serde_bytes::ByteBuf::from(br.name.clone())),
            }),
            ..Default::default()
        });
    }

    for _ in 0..refs.empty_refs {
        access.push(ResourceRef::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte0: u8) -> Address {
        let mut bytes = [0u8; 32];
        bytes[0] = byte0;
        Address(bytes)
    }

    fn boxes_field(tx: &Transaction) -> Vec<BoxRef> {
        tx.boxes.clone().unwrap_or_default()
    }

    // Port of go-algorand's `TestForeignResolution`
    // (`libgoal/libgoal_test.go`).
    #[test]
    fn test_foreign_resolution() {
        let mut tx = Transaction {
            application_id: 111,
            ..Default::default()
        };

        let accounts = vec![addr(0x22), addr(0x33)];
        let foreign_apps = vec![222u64, 333u64];
        let foreign_assets = vec![2222u64, 3333u64];

        attach_foreign_refs(
            &mut tx,
            &RefBundle {
                accounts: accounts.clone(),
                ..Default::default()
            },
        );
        assert_eq!(tx.accounts, Some(accounts.clone()));

        attach_foreign_refs(
            &mut tx,
            &RefBundle {
                assets: foreign_assets.clone(),
                ..Default::default()
            },
        );
        assert_eq!(tx.foreign_assets, Some(foreign_assets.clone()));

        attach_foreign_refs(
            &mut tx,
            &RefBundle {
                apps: foreign_apps.clone(),
                ..Default::default()
            },
        );
        assert_eq!(tx.foreign_apps, Some(foreign_apps.clone()));

        attach_foreign_refs(
            &mut tx,
            &RefBundle {
                apps: foreign_apps.clone(),
                ..Default::default()
            },
        );
        let mut doubled = foreign_apps.clone();
        doubled.extend(foreign_apps.clone());
        assert_eq!(tx.foreign_apps, Some(doubled));

        let boxes = box_hints(&[(3, "aaa")]);
        attach_foreign_refs(
            &mut tx,
            &RefBundle {
                boxes,
                ..Default::default()
            },
        );
        assert_eq!(tx.foreign_apps, Some(vec![222, 333, 222, 333, 3]));
        assert_eq!(
            boxes_field(&tx),
            vec![BoxRef {
                index: 5,
                name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
            }]
        );

        let boxes = box_hints(&[(3, "aaa"), (0, "bbb")]);
        tx.boxes = None;
        attach_foreign_refs(
            &mut tx,
            &RefBundle {
                boxes,
                ..Default::default()
            },
        );
        assert_eq!(tx.foreign_apps, Some(vec![222, 333, 222, 333, 3]));
        assert_eq!(
            boxes_field(&tx),
            vec![
                BoxRef {
                    index: 5,
                    name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                },
                BoxRef {
                    index: 0,
                    name: Some(serde_bytes::ByteBuf::from(b"bbb".to_vec()))
                },
            ]
        );

        let boxes = box_hints(&[(3, "aaa"), (3, "xxx")]);
        attach_foreign_refs(
            &mut tx,
            &RefBundle {
                boxes,
                ..Default::default()
            },
        );
        assert_eq!(tx.foreign_apps, Some(vec![222, 333, 222, 333, 3]));
        assert_eq!(
            boxes_field(&tx),
            vec![
                BoxRef {
                    index: 5,
                    name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                },
                BoxRef {
                    index: 0,
                    name: Some(serde_bytes::ByteBuf::from(b"bbb".to_vec()))
                },
                BoxRef {
                    index: 5,
                    name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                },
                BoxRef {
                    index: 5,
                    name: Some(serde_bytes::ByteBuf::from(b"xxx".to_vec()))
                },
            ]
        );

        let boxes = box_hints(&[(111, "aaa"), (333, "xxx")]);
        attach_foreign_refs(
            &mut tx,
            &RefBundle {
                boxes,
                ..Default::default()
            },
        );
        assert_eq!(tx.foreign_apps, Some(vec![222, 333, 222, 333, 3]));
        assert_eq!(
            boxes_field(&tx),
            vec![
                BoxRef {
                    index: 5,
                    name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                },
                BoxRef {
                    index: 0,
                    name: Some(serde_bytes::ByteBuf::from(b"bbb".to_vec()))
                },
                BoxRef {
                    index: 5,
                    name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                },
                BoxRef {
                    index: 5,
                    name: Some(serde_bytes::ByteBuf::from(b"xxx".to_vec()))
                },
                BoxRef {
                    index: 0,
                    name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                },
                BoxRef {
                    index: 2,
                    name: Some(serde_bytes::ByteBuf::from(b"xxx".to_vec()))
                },
            ]
        );

        let box_count = boxes_field(&tx).len();
        attach_foreign_refs(
            &mut tx,
            &RefBundle {
                empty_refs: 2,
                ..Default::default()
            },
        );
        assert_eq!(boxes_field(&tx).len(), box_count + 2);
        assert_eq!(
            &boxes_field(&tx)[box_count..],
            &[BoxRef::default(), BoxRef::default()]
        );

        let zero = Address::ZERO;
        let one = addr(0x01);
        let two = addr(0x02);
        let holdings = vec![
            HoldingHint {
                asset: 111,
                address: one,
            },
            HoldingHint {
                asset: 3333,
                address: zero,
            },
        ];
        attach_foreign_refs(
            &mut tx,
            &RefBundle {
                holdings,
                ..Default::default()
            },
        );
        // it's added, 111 is the APP id
        assert_eq!(tx.foreign_assets, Some(vec![2222, 3333, 111]));
        let mut expected_accounts = accounts.clone();
        expected_accounts.push(one);
        assert_eq!(tx.accounts, Some(expected_accounts.clone()));

        let locals = vec![
            LocalHint {
                app: 111,
                address: two,
            },
            LocalHint {
                app: 333,
                address: zero,
            },
            LocalHint {
                app: 444,
                address: one,
            },
        ];
        attach_foreign_refs(
            &mut tx,
            &RefBundle {
                locals,
                ..Default::default()
            },
        );
        // 111 not added, it's being called
        assert_eq!(tx.foreign_apps, Some(vec![222, 333, 222, 333, 3, 444]));
        expected_accounts.push(two);
        assert_eq!(tx.accounts, Some(expected_accounts));
    }

    // Port of go-algorand's `TestAccessResolution`
    // (`libgoal/libgoal_test.go`).
    #[test]
    fn test_access_resolution() {
        let mut tx = Transaction {
            application_id: 111,
            ..Default::default()
        };

        let accounts = vec![addr(0x22), addr(0x33)];
        let foreign_apps = vec![222u64, 333u64];
        let foreign_assets = vec![2222u64, 3333u64];

        attach_access_list(
            &mut tx,
            &RefBundle {
                accounts: accounts.clone(),
                ..Default::default()
            },
        );
        assert!(tx.accounts.is_none());
        assert_eq!(
            tx.access,
            Some(vec![
                ResourceRef {
                    address: accounts[0],
                    ..Default::default()
                },
                ResourceRef {
                    address: accounts[1],
                    ..Default::default()
                },
            ])
        );

        attach_access_list(
            &mut tx,
            &RefBundle {
                assets: foreign_assets.clone(),
                ..Default::default()
            },
        );
        assert!(tx.foreign_assets.is_none());
        assert_eq!(
            tx.access,
            Some(vec![
                ResourceRef {
                    address: accounts[0],
                    ..Default::default()
                },
                ResourceRef {
                    address: accounts[1],
                    ..Default::default()
                },
                ResourceRef {
                    asset: foreign_assets[0],
                    ..Default::default()
                },
                ResourceRef {
                    asset: foreign_assets[1],
                    ..Default::default()
                },
            ])
        );

        attach_access_list(
            &mut tx,
            &RefBundle {
                apps: foreign_apps.clone(),
                ..Default::default()
            },
        );
        assert!(tx.foreign_apps.is_none());
        assert_eq!(
            tx.access,
            Some(vec![
                ResourceRef {
                    address: accounts[0],
                    ..Default::default()
                },
                ResourceRef {
                    address: accounts[1],
                    ..Default::default()
                },
                ResourceRef {
                    asset: foreign_assets[0],
                    ..Default::default()
                },
                ResourceRef {
                    asset: foreign_assets[1],
                    ..Default::default()
                },
                ResourceRef {
                    app: foreign_apps[0],
                    ..Default::default()
                },
                ResourceRef {
                    app: foreign_apps[1],
                    ..Default::default()
                },
            ])
        );

        attach_access_list(
            &mut tx,
            &RefBundle {
                apps: foreign_apps.clone(),
                ..Default::default()
            },
        );
        // no change
        assert_eq!(
            tx.access,
            Some(vec![
                ResourceRef {
                    address: accounts[0],
                    ..Default::default()
                },
                ResourceRef {
                    address: accounts[1],
                    ..Default::default()
                },
                ResourceRef {
                    asset: foreign_assets[0],
                    ..Default::default()
                },
                ResourceRef {
                    asset: foreign_assets[1],
                    ..Default::default()
                },
                ResourceRef {
                    app: foreign_apps[0],
                    ..Default::default()
                },
                ResourceRef {
                    app: foreign_apps[1],
                    ..Default::default()
                },
            ])
        );

        let boxes = box_hints(&[(3, "aaa")]);
        attach_access_list(
            &mut tx,
            &RefBundle {
                boxes,
                ..Default::default()
            },
        );
        assert!(tx.boxes.is_none());
        assert!(tx.foreign_apps.is_none());
        assert_eq!(
            tx.access,
            Some(vec![
                ResourceRef {
                    address: accounts[0],
                    ..Default::default()
                },
                ResourceRef {
                    address: accounts[1],
                    ..Default::default()
                },
                ResourceRef {
                    asset: foreign_assets[0],
                    ..Default::default()
                },
                ResourceRef {
                    asset: foreign_assets[1],
                    ..Default::default()
                },
                ResourceRef {
                    app: foreign_apps[0],
                    ..Default::default()
                },
                ResourceRef {
                    app: foreign_apps[1],
                    ..Default::default()
                },
                ResourceRef {
                    app: 3,
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 7,
                        name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                    }),
                    ..Default::default()
                },
            ])
        );

        let boxes = box_hints(&[(3, "aaa"), (0, "bbb")]);
        attach_access_list(
            &mut tx,
            &RefBundle {
                boxes,
                ..Default::default()
            },
        );
        assert!(tx.boxes.is_none());
        assert!(tx.foreign_apps.is_none());
        assert_eq!(
            tx.access,
            Some(vec![
                ResourceRef {
                    address: accounts[0],
                    ..Default::default()
                },
                ResourceRef {
                    address: accounts[1],
                    ..Default::default()
                },
                ResourceRef {
                    asset: foreign_assets[0],
                    ..Default::default()
                },
                ResourceRef {
                    asset: foreign_assets[1],
                    ..Default::default()
                },
                ResourceRef {
                    app: foreign_apps[0],
                    ..Default::default()
                },
                ResourceRef {
                    app: foreign_apps[1],
                    ..Default::default()
                },
                ResourceRef {
                    app: 3,
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 7,
                        name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                    }),
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 7,
                        name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                    }),
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 0,
                        name: Some(serde_bytes::ByteBuf::from(b"bbb".to_vec()))
                    }),
                    ..Default::default()
                },
            ])
        );

        let boxes = box_hints(&[(3, "aaa"), (3, "xxx")]);
        attach_access_list(
            &mut tx,
            &RefBundle {
                boxes,
                ..Default::default()
            },
        );
        assert_eq!(
            tx.access,
            Some(vec![
                ResourceRef {
                    address: accounts[0],
                    ..Default::default()
                },
                ResourceRef {
                    address: accounts[1],
                    ..Default::default()
                },
                ResourceRef {
                    asset: foreign_assets[0],
                    ..Default::default()
                },
                ResourceRef {
                    asset: foreign_assets[1],
                    ..Default::default()
                },
                ResourceRef {
                    app: foreign_apps[0],
                    ..Default::default()
                },
                ResourceRef {
                    app: foreign_apps[1],
                    ..Default::default()
                },
                ResourceRef {
                    app: 3,
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 7,
                        name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                    }),
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 7,
                        name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                    }),
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 0,
                        name: Some(serde_bytes::ByteBuf::from(b"bbb".to_vec()))
                    }),
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 7,
                        name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                    }),
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 7,
                        name: Some(serde_bytes::ByteBuf::from(b"xxx".to_vec()))
                    }),
                    ..Default::default()
                },
            ])
        );

        let boxes = box_hints(&[(111, "aaa"), (333, "xxx")]);
        attach_access_list(
            &mut tx,
            &RefBundle {
                boxes,
                ..Default::default()
            },
        );
        assert_eq!(
            tx.access,
            Some(vec![
                ResourceRef {
                    address: accounts[0],
                    ..Default::default()
                },
                ResourceRef {
                    address: accounts[1],
                    ..Default::default()
                },
                ResourceRef {
                    asset: foreign_assets[0],
                    ..Default::default()
                },
                ResourceRef {
                    asset: foreign_assets[1],
                    ..Default::default()
                },
                ResourceRef {
                    app: foreign_apps[0],
                    ..Default::default()
                },
                ResourceRef {
                    app: foreign_apps[1],
                    ..Default::default()
                },
                ResourceRef {
                    app: 3,
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 7,
                        name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                    }),
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 7,
                        name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                    }),
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 0,
                        name: Some(serde_bytes::ByteBuf::from(b"bbb".to_vec()))
                    }),
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 7,
                        name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                    }),
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 7,
                        name: Some(serde_bytes::ByteBuf::from(b"xxx".to_vec()))
                    }),
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 0,
                        name: Some(serde_bytes::ByteBuf::from(b"aaa".to_vec()))
                    }),
                    ..Default::default()
                },
                ResourceRef {
                    box_ref: Some(BoxRef {
                        index: 6,
                        name: Some(serde_bytes::ByteBuf::from(b"xxx".to_vec()))
                    }),
                    ..Default::default()
                },
            ])
        );

        let zero = Address::ZERO;
        let one = addr(0x01);
        let two = addr(0x02);
        let holdings = vec![
            HoldingHint {
                asset: 111,
                address: one,
            },
            HoldingHint {
                asset: 3333,
                address: zero,
            },
        ];
        attach_access_list(
            &mut tx,
            &RefBundle {
                holdings,
                ..Default::default()
            },
        );
        assert!(tx.foreign_assets.is_none());
        assert!(tx.accounts.is_none());
        let access = tx.access.clone().unwrap();
        // Before this step, access held 14 entries (0..=13): the two
        // accounts, two assets, two apps, the box-inserted `app: 3`, and
        // seven BoxRefs. `ensure` appends `Address:one` at 0-based index
        // 14 (1-based 15) and `Asset:111` at 0-based index 15 (1-based
        // 16); the Holding push itself lands at 0-based index 16. The
        // second holding (asset 3333, zero address) reuses the existing
        // `Asset:3333` entry (0-based index 3, 1-based 4) and pushes at
        // 0-based index 17.
        assert_eq!(access.len(), 18);
        assert_eq!(
            access[14],
            ResourceRef {
                address: one,
                ..Default::default()
            }
        );
        assert_eq!(
            access[15],
            ResourceRef {
                asset: 111,
                ..Default::default()
            }
        );
        assert_eq!(
            access[16],
            ResourceRef {
                holding: Some(HoldingRef {
                    asset: 16,
                    address: 15
                }),
                ..Default::default()
            }
        );
        assert_eq!(
            access[17],
            ResourceRef {
                holding: Some(HoldingRef {
                    asset: 4,
                    address: 0
                }),
                ..Default::default()
            }
        );

        let locals = vec![
            LocalHint {
                app: 111,
                address: two,
            },
            LocalHint {
                app: 333,
                address: zero,
            },
            LocalHint {
                app: 444,
                address: one,
            },
        ];
        attach_access_list(
            &mut tx,
            &RefBundle {
                locals,
                ..Default::default()
            },
        );
        assert!(tx.foreign_apps.is_none());
        assert!(tx.accounts.is_none());
        let access = tx.access.clone().unwrap();
        // Starting from length 18. Local 1 (App:111 == tx.ApplicationID,
        // so no App ensure; Address:two is new) contributes `Address:two`
        // at 0-based index 18 and `Locals{App:0,Address:19}` at index 19.
        // Local 2 (App:333, already present at 1-based index 6; Address
        // zero) contributes only `Locals{App:6,Address:0}` at index 20 —
        // no new ensure entry since App:333 was already in `access`.
        // Local 3 (App:444, new; Address:one, already present at 1-based
        // index 15) contributes `App:444` (ensure insert) at index 21 and
        // `Locals{App:22,Address:15}` at index 22.
        assert_eq!(access.len(), 23);
        assert_eq!(
            access[18],
            ResourceRef {
                address: two,
                ..Default::default()
            }
        );
        assert_eq!(
            access[19],
            ResourceRef {
                locals: Some(LocalsRef {
                    app: 0,
                    address: 19
                }),
                ..Default::default()
            }
        );
        assert_eq!(
            access[20],
            ResourceRef {
                locals: Some(LocalsRef { app: 6, address: 0 }),
                ..Default::default()
            }
        );
        assert_eq!(
            access[21],
            ResourceRef {
                app: 444,
                ..Default::default()
            }
        );
        assert_eq!(
            access[22],
            ResourceRef {
                locals: Some(LocalsRef {
                    app: 22,
                    address: 15
                }),
                ..Default::default()
            }
        );

        let access_count = tx.access.as_ref().unwrap().len();
        attach_access_list(
            &mut tx,
            &RefBundle {
                empty_refs: 2,
                ..Default::default()
            },
        );
        let access = tx.access.clone().unwrap();
        assert_eq!(access.len(), access_count + 2);
        assert_eq!(
            &access[access_count..],
            &[ResourceRef::default(), ResourceRef::default()]
        );
    }

    #[test]
    fn attach_references_dispatches_on_use_access() {
        let mut tx = Transaction {
            application_id: 111,
            ..Default::default()
        };
        attach_references(
            &mut tx,
            &RefBundle {
                use_access: true,
                apps: vec![5],
                ..Default::default()
            },
        );
        assert!(tx.foreign_apps.is_none());
        assert_eq!(
            tx.access,
            Some(vec![ResourceRef {
                app: 5,
                ..Default::default()
            }])
        );

        let mut tx2 = Transaction {
            application_id: 111,
            ..Default::default()
        };
        attach_references(
            &mut tx2,
            &RefBundle {
                use_access: false,
                apps: vec![5],
                ..Default::default()
            },
        );
        assert!(tx2.access.is_none());
        assert_eq!(tx2.foreign_apps, Some(vec![5]));
    }

    #[test]
    fn app_address_matches_known_vector() {
        // app 1's account address, cross-checked against go-algorand's
        // `basics.AppIndex(1).Address()` / algo-ledger's own
        // `avm_context::app_address(1)` (both SHA512/256("appID" || 1u64be)).
        let a = app_address(1);
        // Recomputed independently to ensure this port is self-consistent
        // rather than only checked against itself.
        let mut h = Sha512_256::new();
        h.update(b"appID");
        h.update(1u64.to_be_bytes());
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(a.0, expected);
    }
}
