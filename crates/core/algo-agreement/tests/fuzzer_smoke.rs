// Integration smoke for the agreement fuzzer harness (TASK-84).
//
// Exercises the full message-pump pipeline: per-node outgoing chain →
// router → per-node incoming chain → received log. The two filters
// shipping under TASK-84 (`drop_message`, `duplicate_message`) are
// counter-driven, so every assertion below is a deterministic
// expected-count match — no probabilistic tolerances, no RNG.
//
// Live multi-Service consensus through the harness is deliberately
// out of scope here (CONVE-14: keep task scope to one PR); that
// integration arrives in TASK-85 alongside reorder + nodeCrash.
// What this smoke proves is that the harness itself routes / filters
// / ticks correctly and is ready for that follow-up.

#![deny(unsafe_code)]

mod fuzzer;

use fuzzer::filter::{Filter, FilterDecision};
use fuzzer::filters::drop_message::DropMessageFilterBuilder;
use fuzzer::filters::duplicate_message::DuplicateMessageFilterBuilder;
use fuzzer::network_facade::NetworkFacade;
use fuzzer::router::Router;
use fuzzer::scheduler::Scheduler;
use fuzzer::AlgoMessage;

const TAG: &str = "AV"; // arbitrary tag for fixture messages — the
                        // harness is tag-agnostic.

// ---------------------------------------------------------------------------
// Filter unit tests
// ---------------------------------------------------------------------------

#[test]
fn drop_filter_drops_every_nth_outgoing() {
    let mut f = DropMessageFilterBuilder::new()
        .outgoing_rate(Some(3))
        .build();
    let mut decisions = Vec::new();
    for i in 0..9 {
        let msg = AlgoMessage::broadcast(0, TAG, vec![i as u8]);
        decisions.push(f.filter_outgoing(&msg));
    }
    // Counter sequence 1..=9; drops at 3, 6, 9.
    assert_eq!(
        decisions,
        vec![
            FilterDecision::Keep,
            FilterDecision::Keep,
            FilterDecision::Drop,
            FilterDecision::Keep,
            FilterDecision::Keep,
            FilterDecision::Drop,
            FilterDecision::Keep,
            FilterDecision::Keep,
            FilterDecision::Drop,
        ],
    );
    assert_eq!(f.outgoing_seen(), 9);
}

#[test]
fn drop_filter_rate_zero_is_noop() {
    // Matches Go's `dropMessageFilter_test.go:48-52` short-circuit:
    // `rate == 0` makes the `||` always-true so the forward branch
    // runs every time. Effective behavior: rate-zero is a no-op
    // (forwards everything). To drop EVERY message, configure
    // `rate == 1` (every counter % 1 == 0).
    let mut f = DropMessageFilterBuilder::new()
        .outgoing_rate(Some(0))
        .build();
    for i in 0..5 {
        let msg = AlgoMessage::broadcast(0, TAG, vec![i as u8]);
        assert_eq!(f.filter_outgoing(&msg), FilterDecision::Keep);
    }
    assert_eq!(f.outgoing_seen(), 5);
}

#[test]
fn drop_filter_rate_one_drops_every_message() {
    let mut f = DropMessageFilterBuilder::new()
        .outgoing_rate(Some(1))
        .build();
    for i in 0..4 {
        let msg = AlgoMessage::broadcast(0, TAG, vec![i as u8]);
        assert_eq!(f.filter_outgoing(&msg), FilterDecision::Drop);
    }
}

#[test]
fn drop_filter_none_keeps_everything_in_other_direction() {
    let mut f = DropMessageFilterBuilder::new()
        .outgoing_rate(Some(2))
        .incoming_rate(None)
        .build();
    // Outgoing: drops at 2, 4 — incoming chain should still pass everything.
    for i in 0..4 {
        let _ = f.filter_outgoing(&AlgoMessage::broadcast(0, TAG, vec![i]));
    }
    for i in 0..4 {
        assert_eq!(
            f.filter_incoming(&AlgoMessage::unicast(1, 0, TAG, vec![i])),
            FilterDecision::Keep,
        );
    }
}

#[test]
fn duplicate_filter_emits_extra_copies_on_every_nth_outgoing() {
    let mut f = DuplicateMessageFilterBuilder::new()
        .outgoing(Some(2), 3) // every 2nd msg → 1 + 3 copies
        .build();
    let decisions: Vec<_> = (0..6)
        .map(|i| f.filter_outgoing(&AlgoMessage::broadcast(0, TAG, vec![i])))
        .collect();
    assert_eq!(
        decisions,
        vec![
            FilterDecision::Keep,
            FilterDecision::Duplicate { extra_copies: 3 },
            FilterDecision::Keep,
            FilterDecision::Duplicate { extra_copies: 3 },
            FilterDecision::Keep,
            FilterDecision::Duplicate { extra_copies: 3 },
        ],
    );
}

#[test]
fn duplicate_filter_zero_extra_copies_is_noop() {
    // Even with rate Some(1), extra_copies==0 must produce no
    // duplications — the harness short-circuits to Keep.
    let mut f = DuplicateMessageFilterBuilder::new()
        .outgoing(Some(1), 0)
        .build();
    for i in 0..4 {
        assert_eq!(
            f.filter_outgoing(&AlgoMessage::broadcast(0, TAG, vec![i])),
            FilterDecision::Keep,
        );
    }
}

// ---------------------------------------------------------------------------
// NetworkFacade chain integration
// ---------------------------------------------------------------------------

#[test]
fn facade_outgoing_chain_duplicate_then_drop_propagates_copies() {
    // Coverage for the "Duplicate's extra copies flow through
    // remaining filters too" guarantee in run_chain_from. With
    // [Duplicate(rate=1, extra=2), Drop(rate=2)]:
    //   * Duplicate fires on EVERY message (rate=1) and emits 1+2 = 3
    //     copies per call.
    //   * Each of those 3 copies feeds into Drop, whose internal
    //     counter advances 1, 2, 3 across them — Drop's modulo=2
    //     fires on copies 2 and 6 (etc.).
    //
    // For 2 input messages:
    //   In 1 → 3 copies → Drop counter 1, 2, 3 → drops at #2 → 2 survive.
    //   In 2 → 3 copies → Drop counter 4, 5, 6 → drops at #4, #6 → 1 survives.
    //   Total survivors: 3.
    //
    // If `Duplicate` somehow short-circuited the rest of the chain,
    // we'd see all 6 copies survive — the assertion below catches
    // that regression.
    let dup = DuplicateMessageFilterBuilder::new()
        .outgoing(Some(1), 2)
        .build();
    let drop = DropMessageFilterBuilder::new()
        .outgoing_rate(Some(2))
        .build();
    let mut facade = NetworkFacade::new(0, vec![Box::new(dup), Box::new(drop)], Vec::new());

    let mut emitted = 0usize;
    for i in 1u8..=2 {
        let survivors = facade.process_outgoing(AlgoMessage::unicast(0, 1, TAG, vec![i]));
        emitted += survivors.len();
    }
    assert_eq!(
        emitted, 3,
        "expected 3 survivors after [Duplicate(1, extra=2), Drop(2)] on 2 msgs; \
         each duplicate copy must flow through Drop",
    );
}

#[test]
fn facade_outgoing_chain_drop_then_duplicate_runs_in_order() {
    // [Drop(rate=3), Duplicate(rate=2, extra=2)] applied to messages
    // 1..=6: Drop sees them all; survivors (1, 2, 4, 5 — i.e. NOT 3 or
    // 6) feed into Duplicate which counts them 1, 2, 3, 4 and so
    // duplicates positions 2 and 4 (the 2nd and 4th SURVIVOR).
    //
    // Survivor sequence after Drop: m1, m2, m4, m5.
    // Duplicate's counter post-each: 1, 2, 3, 4 → duplicates at 2, 4.
    // Final emissions:
    //   m1 (Keep)
    //   m2 (Duplicate ⇒ 3 copies)
    //   m4 (Keep)
    //   m5 (Duplicate ⇒ 3 copies)
    // Total: 1 + 3 + 1 + 3 = 8 messages.
    let drop = DropMessageFilterBuilder::new()
        .outgoing_rate(Some(3))
        .build();
    let dup = DuplicateMessageFilterBuilder::new()
        .outgoing(Some(2), 2)
        .build();
    let mut facade = NetworkFacade::new(0, vec![Box::new(drop), Box::new(dup)], Vec::new());

    let mut emitted = 0usize;
    for i in 1u8..=6 {
        let msg = AlgoMessage::unicast(0, 1, TAG, vec![i]);
        let survivors = facade.process_outgoing(msg);
        emitted += survivors.len();
    }
    assert_eq!(
        emitted, 8,
        "expected 8 outgoing survivors after [Drop(3), Duplicate(2,extra=2)] on 6 messages",
    );
}

// ---------------------------------------------------------------------------
// Scheduler integration: 3-node cluster with chained filters
// ---------------------------------------------------------------------------

/// Build a 3-node cluster where node 0 has a Drop filter (rate=4)
/// and a Duplicate filter (rate=3, extra=1) on its OUTGOING chain;
/// nodes 1 and 2 have empty chains. Returns the scheduler.
fn make_three_node_cluster() -> Scheduler {
    let n = 3;
    let router = Router::new(n);
    let mut facades = Vec::with_capacity(n);
    facades.push(NetworkFacade::new(
        0,
        vec![
            Box::new(
                DropMessageFilterBuilder::new()
                    .outgoing_rate(Some(4))
                    .build(),
            ),
            Box::new(
                DuplicateMessageFilterBuilder::new()
                    .outgoing(Some(3), 1)
                    .build(),
            ),
        ],
        Vec::new(),
    ));
    facades.push(NetworkFacade::new(1, Vec::new(), Vec::new()));
    facades.push(NetworkFacade::new(2, Vec::new(), Vec::new()));
    Scheduler::new(router, facades)
}

#[test]
fn scheduler_three_node_broadcast_with_drop_and_duplicate() {
    let mut sched = make_three_node_cluster();

    // Send 12 broadcasts from node 0. Walk through what each of node
    // 0's filters does to the per-message stream:
    //
    //   Drop(rate=4): drops messages 4, 8, 12 → 9 survivors
    //                 (1,2,3,5,6,7,9,10,11)
    //   Duplicate(rate=3, extra=1) on those 9 survivors counted 1..9:
    //     emits one extra copy at survivor counter 3, 6, 9 — i.e. for
    //     the survivors at counter positions 3, 6, 9. That means the
    //     3rd survivor (m3), the 6th survivor (m7), and the 9th
    //     survivor (m11) each get 1 extra copy.
    //   Final outgoing message count: 9 + 3 = 12.
    //
    // Each survivor is broadcast → fanout to nodes {1, 2}, so each of
    // those receives 12 messages.
    for i in 1u8..=12 {
        sched.enqueue_send(AlgoMessage::broadcast(0, TAG, vec![i]));
    }

    let recv1 = sched.drain_received(1);
    let recv2 = sched.drain_received(2);
    assert_eq!(
        recv1.len(),
        12,
        "node 1 should have received 12 messages (9 unique + 3 dup), got {} ({:?})",
        recv1.len(),
        recv1.iter().map(|m| m.data[0]).collect::<Vec<_>>(),
    );
    assert_eq!(
        recv2.len(),
        12,
        "node 2 should have received 12 messages (9 unique + 3 dup), got {} ({:?})",
        recv2.len(),
        recv2.iter().map(|m| m.data[0]).collect::<Vec<_>>(),
    );
    // Source node never receives its own broadcast.
    assert!(sched.drain_received(0).is_empty());

    // Per-message verification: messages 4, 8, 12 must be ABSENT, and
    // messages 3, 7, 11 must appear TWICE.
    let bytes_at_node1: Vec<u8> = recv1.iter().map(|m| m.data[0]).collect();
    for absent in [4u8, 8, 12] {
        assert!(
            !bytes_at_node1.contains(&absent),
            "node 1 received dropped message {} ({:?})",
            absent,
            bytes_at_node1,
        );
    }
    for duped in [3u8, 7, 11] {
        let count = bytes_at_node1.iter().filter(|&&b| b == duped).count();
        assert_eq!(
            count, 2,
            "node 1 should have 2 copies of message {} (saw {}); full bytes: {:?}",
            duped, count, bytes_at_node1,
        );
    }
}

#[test]
fn scheduler_is_deterministic_across_reruns() {
    // Two fresh clusters, identical send sequence, must yield byte-
    // identical received logs at every node. This is the deterministic-
    // replay guarantee called out in TASK-84's acceptance criteria.
    let send_sequence: Vec<AlgoMessage> = (1u8..=20)
        .map(|i| AlgoMessage::broadcast(0, TAG, vec![i]))
        .collect();

    let mut sched_a = make_three_node_cluster();
    for m in &send_sequence {
        sched_a.enqueue_send(m.clone());
    }
    let recv_a_1 = sched_a.drain_received(1);
    let recv_a_2 = sched_a.drain_received(2);

    let mut sched_b = make_three_node_cluster();
    for m in &send_sequence {
        sched_b.enqueue_send(m.clone());
    }
    let recv_b_1 = sched_b.drain_received(1);
    let recv_b_2 = sched_b.drain_received(2);

    assert_eq!(
        recv_a_1, recv_b_1,
        "node 1 receive log must be deterministic"
    );
    assert_eq!(
        recv_a_2, recv_b_2,
        "node 2 receive log must be deterministic"
    );
}

#[test]
fn scheduler_unicast_routing() {
    // Drive a unicast (target_node=Some(2)) from node 0 with NO
    // filters configured at any node. Only node 2 should receive.
    let n = 3;
    let router = Router::new(n);
    let facades = (0..n)
        .map(|i| NetworkFacade::new(i, Vec::new(), Vec::new()))
        .collect();
    let mut sched = Scheduler::new(router, facades);

    sched.enqueue_send(AlgoMessage::unicast(0, 2, TAG, vec![42]));

    assert!(sched.drain_received(0).is_empty());
    assert!(sched.drain_received(1).is_empty());
    let recv2 = sched.drain_received(2);
    assert_eq!(recv2.len(), 1);
    assert_eq!(recv2[0].data, vec![42]);
}

#[test]
fn scheduler_loopback_unicast_is_dropped() {
    // A unicast to the source node is silently dropped by the router
    // (loopback isn't meaningful for the agreement protocol).
    let n = 2;
    let router = Router::new(n);
    let facades = (0..n)
        .map(|i| NetworkFacade::new(i, Vec::new(), Vec::new()))
        .collect();
    let mut sched = Scheduler::new(router, facades);

    sched.enqueue_send(AlgoMessage::unicast(0, 0, TAG, vec![1]));
    assert!(sched.drain_received(0).is_empty());
    assert!(sched.drain_received(1).is_empty());
}

#[test]
fn scheduler_tick_releases_delayed_messages_in_release_tick_order() {
    // Coverage for DelayedMessage::Ord — items inserted out-of-order
    // by release tick must surface in ascending release_tick order.
    //
    // Filter that delays the 1st message by 10 ticks, the 2nd by 3,
    // the 3rd by 7. Expected drain order at tick 10: [#2 (tick 3),
    // #3 (tick 7), #1 (tick 10)].
    use crate::fuzzer::filter::Filter;

    struct ScheduleByDataFilter;
    impl Filter for ScheduleByDataFilter {
        fn filter_outgoing(&mut self, msg: &AlgoMessage) -> FilterDecision {
            // Encode the delay in the message payload byte for clarity.
            FilterDecision::Delay {
                delay_ticks: msg.data[0] as u64,
            }
        }
    }

    let n = 2;
    let router = Router::new(n);
    let mut facades = Vec::with_capacity(n);
    facades.push(NetworkFacade::new(
        0,
        vec![Box::new(ScheduleByDataFilter)],
        Vec::new(),
    ));
    facades.push(NetworkFacade::new(1, Vec::new(), Vec::new()));
    let mut sched = Scheduler::new(router, facades);

    // Insertion order: [10, 3, 7].
    sched.enqueue_send(AlgoMessage::broadcast(0, TAG, vec![10]));
    sched.enqueue_send(AlgoMessage::broadcast(0, TAG, vec![3]));
    sched.enqueue_send(AlgoMessage::broadcast(0, TAG, vec![7]));

    sched.tick_to(10);
    let recv: Vec<u8> = sched.drain_received(1).iter().map(|m| m.data[0]).collect();
    assert_eq!(
        recv,
        vec![3, 7, 10],
        "delayed messages must surface in ascending release_tick order",
    );
}

#[test]
fn scheduler_tick_release_same_tick_preserves_insertion_order() {
    // Coverage for the `sequence` tie-breaker in DelayedMessage::Ord.
    // Three messages all delayed to the same tick must surface in the
    // order they were enqueued.
    use crate::fuzzer::filter::Filter;

    struct DelayAllFiveFilter;
    impl Filter for DelayAllFiveFilter {
        fn filter_outgoing(&mut self, _msg: &AlgoMessage) -> FilterDecision {
            FilterDecision::Delay { delay_ticks: 5 }
        }
    }

    let n = 2;
    let router = Router::new(n);
    let mut facades = Vec::with_capacity(n);
    facades.push(NetworkFacade::new(
        0,
        vec![Box::new(DelayAllFiveFilter)],
        Vec::new(),
    ));
    facades.push(NetworkFacade::new(1, Vec::new(), Vec::new()));
    let mut sched = Scheduler::new(router, facades);

    for i in 1u8..=5 {
        sched.enqueue_send(AlgoMessage::broadcast(0, TAG, vec![i]));
    }
    sched.tick_to(5);
    let recv: Vec<u8> = sched.drain_received(1).iter().map(|m| m.data[0]).collect();
    assert_eq!(
        recv,
        vec![1, 2, 3, 4, 5],
        "same-tick delayed messages must drain in insertion order",
    );
}

#[test]
fn scheduler_tick_releases_delayed_outgoing_messages() {
    // A pass-through filter that delays every message by 5 ticks the
    // first time it sees them; subsequent calls keep. We assert that
    // the message surfaces only after `tick_to(5)` (or later) — proving
    // the delay heap honors release ticks.
    use crate::fuzzer::filter::Filter;

    struct DelayOnceFilter {
        triggered: bool,
    }
    impl Filter for DelayOnceFilter {
        fn filter_outgoing(&mut self, _msg: &AlgoMessage) -> FilterDecision {
            if self.triggered {
                FilterDecision::Keep
            } else {
                self.triggered = true;
                FilterDecision::Delay { delay_ticks: 5 }
            }
        }
    }

    let n = 2;
    let router = Router::new(n);
    let mut facades = Vec::with_capacity(n);
    facades.push(NetworkFacade::new(
        0,
        vec![Box::new(DelayOnceFilter { triggered: false })],
        Vec::new(),
    ));
    facades.push(NetworkFacade::new(1, Vec::new(), Vec::new()));
    let mut sched = Scheduler::new(router, facades);

    sched.enqueue_send(AlgoMessage::broadcast(0, TAG, vec![99]));
    // No delivery yet — the message is in the delay heap.
    assert!(sched.drain_received(1).is_empty());

    // Tick to 4 — still parked.
    sched.tick_to(4);
    assert!(sched.drain_received(1).is_empty());

    // Tick to 5 — release fires this tick.
    sched.tick_to(5);
    let recv = sched.drain_received(1);
    assert_eq!(recv.len(), 1);
    assert_eq!(recv[0].data, vec![99]);
}
