// Null network implementation for the agreement simulation driver.
//
// Mirrors go-algorand/agreement/agreementtest/simulate.go `blackhole` type.
//
// `BlackholeNetwork` consumes every outgoing message without routing it
// anywhere and never delivers incoming messages. It is the counterpart to
// `InstantClock`: together they strip the agreement service of any wall-
// clock timing or network I/O, leaving round progression under the explicit
// control of the driver thread.
//
// The `messages(tag)` returned receivers are kept alive (we never drop the
// senders) — that keeps the demux's `crossbeam_channel::Select` arms sane
// instead of surfacing disconnected channels every iteration.

use std::collections::HashMap;
use std::sync::Mutex;

use crossbeam_channel::{unbounded, Receiver, Sender};

use algo_agreement::{
    AgreementError, AgreementNetwork, Message, MessageHandle, Tag, AGREEMENT_VOTE_TAG,
    PROPOSAL_PAYLOAD_TAG, VOTE_BUNDLE_TAG,
};

/// Sender/receiver pair held per protocol tag.
type TagChannel = (Sender<Message>, Receiver<Message>);

/// Null-routing network — accepts every outbound message and discards it;
/// never emits inbound messages. Mirrors Go's `blackhole` in simulate.go:120.
pub struct BlackholeNetwork {
    /// Per-tag outgoing channels. We keep the senders alive for the
    /// lifetime of the network so the `messages()` receivers never go
    /// Disconnected — the service's demux selects on them every iteration
    /// and a disconnected arm would surface spuriously.
    outbound: Mutex<HashMap<String, TagChannel>>,
}

impl BlackholeNetwork {
    /// Construct a fresh blackhole with empty per-tag channels.
    pub fn new() -> Self {
        let mut outbound = HashMap::new();
        // Pre-create receivers for the three agreement tags so the first
        // `messages()` call on each returns an open receiver. This mirrors
        // the production `WebsocketNetwork` behavior where tag receivers
        // exist as long as the service is running.
        for tag in [AGREEMENT_VOTE_TAG, PROPOSAL_PAYLOAD_TAG, VOTE_BUNDLE_TAG] {
            outbound.insert(tag.to_string(), unbounded::<Message>());
        }
        Self {
            outbound: Mutex::new(outbound),
        }
    }
}

impl Default for BlackholeNetwork {
    fn default() -> Self {
        Self::new()
    }
}

impl AgreementNetwork for BlackholeNetwork {
    fn messages(&self, tag: &Tag) -> Receiver<Message> {
        let mut outbound = self
            .outbound
            .lock()
            .expect("BlackholeNetwork outbound mutex poisoned");
        let entry = outbound
            .entry(tag.0.to_string())
            .or_insert_with(unbounded::<Message>);
        entry.1.clone()
    }

    fn broadcast(&self, _tag: &Tag, _data: &[u8]) -> Result<(), AgreementError> {
        // No-op — the blackhole never routes outgoing messages. Mirrors
        // Go's embedded `mocks.MockNetwork` which discards broadcasts.
        Ok(())
    }

    fn relay(
        &self,
        _handle: &MessageHandle,
        _tag: &Tag,
        _data: &[u8],
    ) -> Result<(), AgreementError> {
        Ok(())
    }

    fn disconnect(&self, _handle: &MessageHandle) {
        // No peers → nothing to disconnect.
    }

    fn start(&self) {
        // No startup work. Mirrors Go's `MockNetwork.Start()` no-op.
    }
}
