// Filter trait + decision enum.
//
// Mirrors go-algorand/agreement/fuzzer/filter_test.go's
// `DownstreamFilter` / `UpstreamFilter` / `NetworkFilter` interfaces,
// collapsed into a single Rust trait. Each filter inspects every
// outgoing AND incoming message at its node and returns a
// `FilterDecision` describing what the [`network_facade::NetworkFacade`]
// should do with it.
//
// Determinism: filters MUST NOT use RNG. They may keep counters /
// hash-set state to track per-message decisions; that's exactly what
// `dropMessageFilter_test.go` (modulo counter) and Go's other base
// filters do. A given filter configuration applied to the same
// message sequence MUST produce the same decision sequence.

use super::AlgoMessage;

/// Disposition for a single filter inspecting a single message.
///
/// The semantics deliberately match the four cases the task acceptance
/// criteria call out (drop / keep / duplicate / delay). The
/// [`network_facade::NetworkFacade`] interprets each decision before
/// passing the message to the next filter in the chain — so a chain
/// of `[Drop, Duplicate]` means: Drop sees the original first; if it
/// returns `Keep` then Duplicate runs, and any extra copies it asks for
/// also flow through any *subsequent* filters (here: none).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterDecision {
    /// Pass the original message through to the next filter / final
    /// delivery. Default behavior of every trait method.
    Keep,
    /// Drop the message — do not deliver it, do not forward to the next
    /// filter in the chain.
    Drop,
    /// Deliver the original message PLUS `extra_copies` additional
    /// copies. Each copy is forwarded through the remaining filters in
    /// the chain so that downstream filters can also act on them. Mirrors
    /// the multi-delivery semantics of Go's `MessageDuplicationFilter`.
    Duplicate { extra_copies: u32 },
    /// Hold the message and re-fire `delay_ticks` ticks from the
    /// current scheduler clock. Recognized for completeness but not
    /// emitted by the drop / duplicate filters that ship in TASK-84;
    /// reserved for future delay / reorder filters (TASK-85).
    Delay { delay_ticks: u64 },
}

/// A single filter in the per-node chain. Each filter sees both
/// directions of traffic for its owning node.
///
/// Default implementations pass everything through — concrete filters
/// override only the methods they care about. This matches Go's pattern
/// where `DropMessageFilter` overrides `SendMessage` / `ReceiveMessage`
/// but defers `Tick` to the upstream filter unchanged.
pub trait Filter: Send {
    /// A short, stable identifier for the filter — used in panic /
    /// debug messages emitted by the harness. Defaults to the Rust
    /// type name; overrides are encouraged when multiple filters of
    /// the same type are chained with different parameters.
    fn name(&self) -> &str {
        std::any::type_name::<Self>()
    }

    /// Inspect a message *leaving* this node (before it reaches the
    /// router / target nodes). The decision is applied immediately —
    /// `Drop` discards the message, `Keep` forwards it to the next
    /// filter in the outgoing chain, `Duplicate { extra_copies: N }`
    /// forwards `1 + N` copies, `Delay { delay_ticks: D }` enqueues
    /// the message in the facade's outgoing-delay heap.
    fn filter_outgoing(&mut self, _msg: &AlgoMessage) -> FilterDecision {
        FilterDecision::Keep
    }

    /// Inspect a message *arriving* at this node (after the router has
    /// delivered it). Same semantics as `filter_outgoing` but applied
    /// to the incoming-delay heap.
    fn filter_incoming(&mut self, _msg: &AlgoMessage) -> FilterDecision {
        FilterDecision::Keep
    }

    /// Advance this filter's internal clock to `new_clock_time` and
    /// return any messages it wishes to *spontaneously emit* this
    /// tick (for example, a future regossip filter would re-emit
    /// previously-seen messages here). The drop / duplicate filters
    /// shipping in TASK-84 never emit anything from `tick`.
    ///
    /// Direction of returned messages: the caller treats them as
    /// outgoing (sent from this node), matching Go's `Tick(...)`
    /// pattern where reflected/regossiped messages re-enter the
    /// downstream chain.
    fn tick(&mut self, _new_clock_time: u64) -> Vec<AlgoMessage> {
        Vec::new()
    }
}
