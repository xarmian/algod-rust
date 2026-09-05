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

//! FD-pressure connection-limit rebalancing.
//!
//! go-algorand raises its process's file-descriptor soft limit at startup to
//! cover its configured connection limits, and — if the OS won't grant that
//! much headroom (the *hard* limit is lower than what's needed) — shrinks
//! the configured limits back down to fit instead of failing to start. This
//! module ports both halves:
//!
//! - **Live FD accounting**: [`get_fd_limits`]/[`raise_fd_soft_limit`] port
//!   go's `util.GetFdLimits`/`util.RaiseFdSoftLimit`
//!   (`util/util.go`/`util/util_windows.go`) — `getrlimit`(2)/`setrlimit`(2)
//!   on Unix, and go's own hard-coded "unlimited" on Windows (go's
//!   `util_windows.go` build tag never calls a Windows API for this at all,
//!   so this module doesn't either).
//! - **Rebalancing**: [`rebalance_connection_limits`] ports the relevant
//!   slice of `daemon/algod/server.go`'s `Initialize()` (`server.go:125-200`)
//!   — the call site that computes how many FDs the node's current
//!   configuration requires, compares that against the process's actual FD
//!   hard limit, and calls into [`algo_config::Local::adjust_connection_limits`]
//!   (go: `Local.AdjustConnectionLimits`, `config/localTemplate.go:1012`) when
//!   the two don't fit.
//!
//! `daemon/algod/server.go`'s own `fdRequired` accounting additionally folds
//! in `StorageEngine == "pebbledb"` (+1000, explicitly a `TODO` in go itself
//! to fold into `ReservedFDs` once pebble is official) and P2P's flat +512
//! guess ("TODO: Decide if this is too much, or not enough."); both are
//! go-side estimation fudge factors on knobs algod-rust doesn't yet surface
//! identically, so [`required_fds`] sticks to the well-defined portion:
//! `ReservedFDs` + `RestConnectionsHardLimit` +
//! [`crate::listener::RESERVED_HEALTH_SERVICE_CONNECTIONS`] +
//! `IncomingConnectionsLimit` (if listening) +
//! `P2PHybridIncomingConnectionsLimit` (if a hybrid server).

use algo_config::Local;

use crate::listener::RESERVED_HEALTH_SERVICE_CONNECTIONS;

/// A process's current file-descriptor soft/hard limits.
///
/// Go: the `(soft, hard uint64)` return of `util.GetFdLimits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdLimits {
    pub soft: u64,
    pub hard: u64,
}

/// Go: `util.GetFdLimits` (`util/util.go:29`, Unix) /
/// (`util/util_windows.go:30`, Windows).
#[cfg(unix)]
pub fn get_fd_limits() -> std::io::Result<FdLimits> {
    // SAFETY: `rlimit` is a plain-old-data struct; `getrlimit` only writes
    // through the pointer we give it, and we check its return value below.
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(FdLimits {
        soft: rl.rlim_cur as u64,
        hard: rl.rlim_max as u64,
    })
}

/// Go: `util.GetFdLimits` (`util/util_windows.go:30`) — Windows has no
/// `RLIMIT_NOFILE` equivalent go-algorand models, so go hard-codes
/// `(math.MaxUint64, math.MaxUint64)` ("no limit") rather than calling any
/// Windows API. algod-rust mirrors that exactly: FD-pressure rebalancing is
/// a no-op on Windows in both implementations.
#[cfg(not(unix))]
pub fn get_fd_limits() -> std::io::Result<FdLimits> {
    Ok(FdLimits {
        soft: u64::MAX,
        hard: u64::MAX,
    })
}

/// Go: `util.SetFdSoftLimit` (`util/util.go:57`, Unix) — sets a new FD soft
/// limit outright (the hard limit is left untouched).
#[cfg(unix)]
pub fn set_fd_soft_limit(new_limit: u64) -> std::io::Result<()> {
    // SAFETY: same as `get_fd_limits` — `getrlimit`/`setrlimit` only touch
    // the `rlimit` we hand them, and both return values are checked.
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    rl.rlim_cur = new_limit as libc::rlim_t;
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Go: `util.SetFdSoftLimit` (`util/util_windows.go:39`) — a no-op on
/// Windows, matching [`get_fd_limits`]'s "no limit" story there.
#[cfg(not(unix))]
pub fn set_fd_soft_limit(_new_limit: u64) -> std::io::Result<()> {
    Ok(())
}

/// Go: `util.RaiseFdSoftLimit` (`util/util.go:40`) — raises the FD soft
/// limit to `new_limit`, clamped to the hard limit, or leaves it unchanged
/// if it's already sufficient.
pub fn raise_fd_soft_limit(new_limit: u64) -> std::io::Result<()> {
    let limits = get_fd_limits()?;
    if new_limit <= limits.soft {
        return Ok(());
    }
    let new_limit = new_limit.min(limits.hard);
    set_fd_soft_limit(new_limit)
}

/// The number of file descriptors `cfg`'s current connection-limit fields
/// require, given which listen mode(s) `net_address`/`p2p_net_address`
/// indicate are active. See the module docs for how this compares to go's
/// fuller `fdRequired` accounting in `daemon/algod/server.go:125-171`.
pub fn required_fds(cfg: &Local, net_address: Option<&str>, p2p_net_address: Option<&str>) -> u64 {
    let mut required = cfg.reserved_fds
        + cfg.rest_connections_hard_limit
        + u64::from(RESERVED_HEALTH_SERVICE_CONNECTIONS);
    if cfg.is_listen_server(net_address, p2p_net_address) {
        required += cfg.incoming_connections_limit.max(0) as u64;
    }
    if cfg.is_hybrid_server(net_address, p2p_net_address) {
        required += cfg.p2p_hybrid_incoming_connections_limit.max(0) as u64;
    }
    required
}

/// Outcome of [`rebalance_connection_limits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RebalanceOutcome {
    /// The process's actual FD limits observed via [`get_fd_limits`].
    pub fd_limits: FdLimits,
    /// FDs `cfg` required before any rebalancing.
    pub required_fds: u64,
    /// Whether `cfg`'s connection-limit fields were adjusted downward.
    pub adjusted: bool,
}

/// Go: the relevant slice of `daemon/algod/server.go`'s `Initialize()`
/// (`server.go:172-200`) — reads the process's actual FD hard limit, and if
/// `cfg`'s configured connection limits would need more FDs than that,
/// shrinks them via [`Local::adjust_connection_limits`] so the node can
/// still start (rather than failing outright or silently over-subscribing
/// the OS's actual FD budget). Then attempts to raise the process's FD soft
/// limit to cover whatever `cfg` now requires.
///
/// Mutates `cfg` in place; returns what happened for the caller to log
/// (mirroring go's own `s.log.Warnf("Updated connection limits: ...")`).
pub fn rebalance_connection_limits(
    cfg: &mut Local,
    net_address: Option<&str>,
    p2p_net_address: Option<&str>,
) -> std::io::Result<RebalanceOutcome> {
    let fd_limits = get_fd_limits()?;
    let mut required = required_fds(cfg, net_address, p2p_net_address);

    let adjusted = if required > fd_limits.hard {
        cfg.adjust_connection_limits(required, fd_limits.hard, net_address, p2p_net_address)
    } else {
        false
    };
    if adjusted {
        // Recompute post-adjustment: `adjust_connection_limits` shrank the
        // fields `required_fds` reads, so the node now needs (at most) the
        // hard limit's worth of FDs — go relies on the same invariant
        // (`server.go:177`'s `maxFDs = hard`).
        required = required_fds(cfg, net_address, p2p_net_address).min(fd_limits.hard);
    }

    // Best-effort like go's own call site: log-worthy but not fatal if the
    // OS refuses (go: `s.log.Errorf(...)` without returning an error).
    let _ = raise_fd_soft_limit(required);

    Ok(RebalanceOutcome {
        fd_limits,
        required_fds: required,
        adjusted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(
        reserved_fds: u64,
        rest_hard: u64,
        incoming: i64,
        p2p_incoming: i64,
    ) -> Local {
        Local {
            reserved_fds,
            rest_connections_soft_limit: rest_hard,
            rest_connections_hard_limit: rest_hard,
            incoming_connections_limit: incoming,
            p2p_hybrid_incoming_connections_limit: p2p_incoming,
            enable_p2p_hybrid_mode: p2p_incoming > 0,
            ..Local::default()
        }
    }

    #[test]
    fn get_fd_limits_returns_plausible_values() {
        // On every supported platform this call must succeed and report a
        // soft limit no greater than the hard limit (Unix: real
        // `getrlimit`; Windows: go's own hard-coded "unlimited").
        let limits = get_fd_limits().expect("get_fd_limits should succeed");
        assert!(limits.soft <= limits.hard);
    }

    #[test]
    fn required_fds_counts_only_active_listen_modes() {
        let cfg = cfg_with(256, 2048, 2400, 0);
        // WS-only: net_address set, no P2P — P2PHybridIncomingConnectionsLimit
        // (0 here anyway) must not be counted, matching go's `IsHybridServer()`
        // gate at `server.go:166`.
        let required = required_fds(&cfg, Some(":4160"), None);
        assert_eq!(required, 256 + 2048 + 10 + 2400);

        // No listen address at all: IncomingConnectionsLimit isn't counted
        // either (go's `IsListenServer()` gate at `server.go:160`).
        let required_no_listen = required_fds(&cfg, None, None);
        assert_eq!(required_no_listen, 256 + 2048 + 10);
    }

    #[test]
    fn required_fds_counts_p2p_hybrid_limit_only_when_hybrid() {
        let cfg = cfg_with(256, 2048, 2400, 1200);
        let required = required_fds(&cfg, Some(":4160"), Some(":4190"));
        assert_eq!(required, 256 + 2048 + 10 + 2400 + 1200);
    }

    #[test]
    fn rebalance_is_a_no_op_when_fds_are_not_actually_constrained() {
        // A real, generous config against the real process FD limits should
        // never need adjusting on any CI/dev machine.
        let mut cfg = cfg_with(256, 2048, 2400, 0);
        let outcome = rebalance_connection_limits(&mut cfg, Some(":4160"), None)
            .expect("rebalance should succeed");
        assert!(!outcome.adjusted);
        assert_eq!(cfg.incoming_connections_limit, 2_400);
    }

    // --- Simulated FD-pressure rebalancing (issue #949's own acceptance
    // criterion: "demonstrated with a test that lowers limits when the
    // simulated/actual FD budget is constrained") ---------------------------

    #[test]
    fn adjust_connection_limits_triggers_under_simulated_fd_pressure() {
        // Simulate a tiny FD budget (as if `getrlimit` returned a low hard
        // limit) without touching the real process limit, by driving
        // `Local::adjust_connection_limits` directly with a `max_fds` far
        // below `required_fds`. This is the same pure function
        // `rebalance_connection_limits` calls once it reads the real
        // `get_fd_limits()` value.
        let mut cfg = cfg_with(10, 40, 50, 0);
        let required = required_fds(&cfg, Some(":4160"), None); // 10+40+10+50=110
        assert_eq!(required, 110);

        let simulated_max_fds = 60; // far below `required`
        let adjusted = cfg.adjust_connection_limits(
            required,
            simulated_max_fds,
            Some(":4160"),
            None,
        );
        assert!(adjusted, "must rebalance when FD budget is constrained");
        // The node's limits must have moved strictly downward from their
        // configured values.
        assert!(cfg.rest_connections_hard_limit < 40);
        assert!(cfg.incoming_connections_limit < 50);
        // And the node must now fit within the simulated FD budget.
        assert!(required_fds(&cfg, Some(":4160"), None) <= simulated_max_fds);
    }

    #[cfg(unix)]
    #[test]
    fn rebalance_lowers_limits_under_a_real_lowered_rlimit() {
        // Exercise the live FD-accounting path for real: lower this test
        // process's own soft *and* observe against the (unchanged) hard
        // limit is not something a test should touch — hard limits usually
        // require privilege to raise back up. Instead, drive
        // `rebalance_connection_limits` with a config whose required FDs
        // exceed the process's *actual* current hard limit, which is
        // always finite and discoverable on Unix CI/dev machines.
        let real_hard = get_fd_limits().expect("real getrlimit must succeed").hard;

        // A config engineered to need far more FDs than any real machine's
        // hard limit will ever be, so this test doesn't depend on the CI
        // runner's specific ulimit -Hn value.
        let huge = real_hard.saturating_add(1_000_000);
        let mut cfg = cfg_with(10, huge / 2, (huge / 2) as i64, 0);

        let outcome = rebalance_connection_limits(&mut cfg, Some(":4160"), None)
            .expect("rebalance should succeed");

        assert!(outcome.adjusted, "must rebalance against the real rlimit hard cap");
        assert!(outcome.required_fds <= real_hard);
        assert!(required_fds(&cfg, Some(":4160"), None) <= real_hard);
    }
}
