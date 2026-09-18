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

//! A thin [`NetworkBehaviour`] wrapper — used to wrap [`identify::Behaviour`]
//! in [`crate::host::P2pHost`] — that applies
//! [`crate::conn_limits::address_filter`] to the address set the wrapped
//! behaviour advertises to peers. The missing wiring closed by issue #1444.
//!
//! Go's `network/p2p/p2p.go` `MakeHost` passes `addressFilter` straight to
//! `go-libp2p`'s `libp2p.New` as a `libp2p.AddrsFactory`: a host-wide hook
//! `go-libp2p` calls on *every* address the host is about to hand out
//! (identify responses, but also any other protocol that asks the host for
//! "my addresses"). `rust-libp2p` 0.54 has no equivalent host-level hook —
//! there is no `AddrsFactory`, and the `identify::Behaviour` that actually
//! reports this host's addresses to peers derives its advertised set
//! (`identify::Behaviour::all_addresses`, private) from two swarm-tracked
//! components it feeds via [`NetworkBehaviour::on_swarm_event`]:
//! `ListenAddresses` (populated from `FromSwarm::NewListenAddr`/
//! `ExpiredListenAddr`) and `ExternalAddresses` (populated from
//! `FromSwarm::ExternalAddrConfirmed`/`ExternalAddrExpired`). Both are
//! private fields with no override/callback — the only place left to filter
//! is upstream of `identify` itself, by intercepting the `FromSwarm` events
//! that feed those two components before they ever reach the wrapped
//! behaviour.
//!
//! [`AddressFilteringBehaviour`] does exactly that: it is a drop-in,
//! transparent `NetworkBehaviour<ConnectionHandler = B::ConnectionHandler,
//! ToSwarm = B::ToSwarm>` wrapper (generic so this module's filtering logic
//! is unit-testable against a lightweight recording double, without needing
//! access to `identify::Behaviour`'s own private internals — see this
//! module's tests) that, when its filter is enabled, drops any
//! `NewListenAddr`/`ExpiredListenAddr`/`ExternalAddrConfirmed`/
//! `ExternalAddrExpired` event whose address [`address_filter`] would
//! discard before forwarding it to the wrapped behaviour — every other
//! `FromSwarm` variant (and every other trait method) passes straight
//! through unmodified. Wrapping [`identify::Behaviour`] this way in
//! `crate::host::P2pHost::new` (`P2pBehaviour::identify`'s field type) means
//! a filtered-out `NewListenAddr` never enters `identify`'s
//! `ListenAddresses` set, so it never appears in its advertised address set
//! and is never sent to a peer — while the underlying transport still binds
//! and listens on it exactly as before (only the advertisement is
//! suppressed, matching go's `addressFilter`: the socket is still opened on
//! every interface, only the *set of addresses handed out to peers* is
//! narrowed).
//!
//! The filter is enabled per go's own `needAddressFilter` condition (see
//! [`crate::conn_limits::needs_address_filter`]'s doc comment): only when
//! this host is listening on an "all interfaces" address (`0.0.0.0`/`::`),
//! never for a caller-configured specific bind address.

use std::task::{Context, Poll};

use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
    THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};

use crate::conn_limits::address_filter;

/// Whether `addr` survives [`address_filter`] — i.e. would still be present
/// in its output if it were advertised.
fn passes_filter(addr: &Multiaddr) -> bool {
    !address_filter(std::slice::from_ref(addr)).is_empty()
}

/// See this module's doc comment.
pub struct AddressFilteringBehaviour<B> {
    inner: B,
    filter_enabled: bool,
}

impl<B> AddressFilteringBehaviour<B> {
    /// Wrap `inner`, applying [`address_filter`] to any
    /// `NewListenAddr`/`ExpiredListenAddr`/`ExternalAddrConfirmed`/
    /// `ExternalAddrExpired` event reaching it via [`on_swarm_event`]
    /// whenever `filter_enabled` is `true`.
    ///
    /// [`on_swarm_event`]: NetworkBehaviour::on_swarm_event
    pub fn new(inner: B, filter_enabled: bool) -> Self {
        Self {
            inner,
            filter_enabled,
        }
    }
}

impl<B> NetworkBehaviour for AddressFilteringBehaviour<B>
where
    B: NetworkBehaviour,
{
    type ConnectionHandler = B::ConnectionHandler;
    type ToSwarm = B::ToSwarm;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.inner.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        if self.filter_enabled {
            let suppressed = match event {
                FromSwarm::NewListenAddr(e) => !passes_filter(e.addr),
                FromSwarm::ExpiredListenAddr(e) => !passes_filter(e.addr),
                FromSwarm::ExternalAddrConfirmed(e) => !passes_filter(e.addr),
                FromSwarm::ExternalAddrExpired(e) => !passes_filter(e.addr),
                _ => false,
            };
            if suppressed {
                // Never forwarded to `inner`: a filtered listen/external
                // address never enters its `ListenAddresses`/
                // `ExternalAddresses` bookkeeping, so it never appears in
                // what it advertises to peers.
                return;
            }
        }
        self.inner.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner
            .on_connection_handler_event(peer_id, connection_id, event)
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.inner.poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::core::transport::ListenerId;
    use libp2p::swarm::behaviour::{ExpiredListenAddr, ExternalAddrConfirmed, NewListenAddr};
    use libp2p::swarm::dummy;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A minimal recording [`NetworkBehaviour`] test double: every
    /// `FromSwarm` event it actually receives (i.e. that
    /// [`AddressFilteringBehaviour`] chose to forward) is appended to a
    /// shared log, keyed by a short tag plus the address involved — letting
    /// these tests assert on *what got through the filter* without needing
    /// access to `identify::Behaviour`'s own private internals.
    struct Recording {
        log: Rc<RefCell<Vec<(&'static str, Multiaddr)>>>,
    }

    impl NetworkBehaviour for Recording {
        type ConnectionHandler = dummy::ConnectionHandler;
        type ToSwarm = void::Void;

        fn handle_established_inbound_connection(
            &mut self,
            _: ConnectionId,
            _: PeerId,
            _: &Multiaddr,
            _: &Multiaddr,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            Ok(dummy::ConnectionHandler)
        }

        fn handle_established_outbound_connection(
            &mut self,
            _: ConnectionId,
            _: PeerId,
            _: &Multiaddr,
            _: Endpoint,
            _: PortUse,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            Ok(dummy::ConnectionHandler)
        }

        fn on_swarm_event(&mut self, event: FromSwarm) {
            let entry = match event {
                FromSwarm::NewListenAddr(NewListenAddr { addr, .. }) => {
                    Some(("new_listen", addr.clone()))
                }
                FromSwarm::ExpiredListenAddr(ExpiredListenAddr { addr, .. }) => {
                    Some(("expired_listen", addr.clone()))
                }
                FromSwarm::ExternalAddrConfirmed(ExternalAddrConfirmed { addr }) => {
                    Some(("external_confirmed", addr.clone()))
                }
                _ => None,
            };
            if let Some(entry) = entry {
                self.log.borrow_mut().push(entry);
            }
        }

        fn on_connection_handler_event(
            &mut self,
            _: PeerId,
            _: ConnectionId,
            event: THandlerOutEvent<Self>,
        ) {
            void::unreachable(event)
        }

        fn poll(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
            Poll::Pending
        }
    }

    /// The [`Recording`] test double's shared event log.
    type RecordingLog = Rc<RefCell<Vec<(&'static str, Multiaddr)>>>;

    fn wrapped(filter_enabled: bool) -> (AddressFilteringBehaviour<Recording>, RecordingLog) {
        let log = Rc::new(RefCell::new(Vec::new()));
        let recording = Recording { log: log.clone() };
        (
            AddressFilteringBehaviour::new(recording, filter_enabled),
            log,
        )
    }

    // --- passes_filter ----------------------------------------------------

    #[test]
    fn passes_filter_rejects_private_ipv4() {
        let addr: Multiaddr = "/ip4/10.0.0.5/tcp/4160".parse().unwrap();
        assert!(!passes_filter(&addr));
    }

    #[test]
    fn passes_filter_accepts_public_ipv4() {
        let addr: Multiaddr = "/ip4/8.8.8.8/tcp/4160".parse().unwrap();
        assert!(passes_filter(&addr));
    }

    // --- on_swarm_event suppression (go: addressFilter applied at the
    // AddrsFactory hook point) ---------------------------------------------

    #[test]
    fn filter_disabled_forwards_private_listen_addr() {
        let (mut filtered, log) = wrapped(false);
        let private: Multiaddr = "/ip4/192.168.1.5/tcp/4160".parse().unwrap();
        let listener_id = ListenerId::next();
        filtered.on_swarm_event(FromSwarm::NewListenAddr(NewListenAddr {
            listener_id,
            addr: &private,
        }));
        assert_eq!(
            log.borrow().as_slice(),
            &[("new_listen", private)],
            "filter disabled must forward every listen address unmodified, mirroring go's \
             needAddressFilter == false (a caller-configured specific bind address)"
        );
    }

    #[test]
    fn filter_enabled_suppresses_private_listen_addr() {
        let (mut filtered, log) = wrapped(true);
        let private: Multiaddr = "/ip4/192.168.1.5/tcp/4160".parse().unwrap();
        let listener_id = ListenerId::next();
        filtered.on_swarm_event(FromSwarm::NewListenAddr(NewListenAddr {
            listener_id,
            addr: &private,
        }));
        assert!(
            log.borrow().is_empty(),
            "a private listen address must never reach the wrapped behaviour (and so never \
             identify's advertised set) when the filter is enabled"
        );
    }

    #[test]
    fn filter_enabled_still_forwards_public_listen_addr() {
        let (mut filtered, log) = wrapped(true);
        let public: Multiaddr = "/ip4/8.8.8.8/tcp/4160".parse().unwrap();
        let listener_id = ListenerId::next();
        filtered.on_swarm_event(FromSwarm::NewListenAddr(NewListenAddr {
            listener_id,
            addr: &public,
        }));
        assert_eq!(
            log.borrow().as_slice(),
            &[("new_listen", public)],
            "a publicly routable listen address must still be advertised even with the filter \
             enabled"
        );
    }

    #[test]
    fn filter_enabled_suppresses_expired_private_listen_addr() {
        let (mut filtered, log) = wrapped(true);
        let private: Multiaddr = "/ip4/192.168.1.5/tcp/4160".parse().unwrap();
        let listener_id = ListenerId::next();
        filtered.on_swarm_event(FromSwarm::ExpiredListenAddr(ExpiredListenAddr {
            listener_id,
            addr: &private,
        }));
        assert!(log.borrow().is_empty());
    }

    #[test]
    fn filter_enabled_suppresses_private_external_addr_confirmed() {
        let (mut filtered, log) = wrapped(true);
        let private: Multiaddr = "/ip4/172.16.0.9/tcp/4160".parse().unwrap();
        filtered.on_swarm_event(FromSwarm::ExternalAddrConfirmed(ExternalAddrConfirmed {
            addr: &private,
        }));
        assert!(
            log.borrow().is_empty(),
            "a confirmed-external event for a private address must also be suppressed, since \
             ExternalAddresses feeds the same advertised set as ListenAddresses"
        );
    }

    #[test]
    fn filter_enabled_passes_non_address_events_through_unconditionally() {
        let (mut filtered, log) = wrapped(true);
        filtered.on_swarm_event(FromSwarm::NewListener(
            libp2p::swarm::behaviour::NewListener {
                listener_id: ListenerId::next(),
            },
        ));
        assert!(
            log.borrow().is_empty(),
            "NewListener carries no address, so the recording double logs nothing either way — \
             this only proves on_swarm_event doesn't panic/misroute a non-address variant"
        );
    }
}
