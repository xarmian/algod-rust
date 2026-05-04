// Integration smoke for the agreement fuzzer harness (TASK-84 + TASK-85).
//
// Exercises the full message-pump pipeline: per-node outgoing chain →
// router → per-node incoming chain → received log. Four filters now
// ship as part of PLAN-32's "base 4" set — `drop_message`,
// `duplicate_message` (TASK-84, counter-driven, no RNG); plus
// `message_reordering` (TASK-85, seeded `ChaCha8Rng` per direction —
// chosen over `StdRng` for cross-version replay stability) and
// `node_crash` (TASK-85, tick-range based suppression). All assertions
// are deterministic — RNG-using filters are seeded explicitly so the
// emission sequence is fixed across runs.
//
// Live multi-Service consensus through the harness is still out of
// scope (CONVE-14); the message-pump shape stays the same, the
// follow-up just bridges the `Scheduler` to N real `Service`s over a
// custom `AgreementNetwork` impl.

#![deny(unsafe_code)]

mod fuzzer;

use fuzzer::filter::{Filter, FilterDecision};
use fuzzer::filters::drop_message::DropMessageFilterBuilder;
use fuzzer::filters::duplicate_message::DuplicateMessageFilterBuilder;
use fuzzer::filters::message_reordering::MessageReorderingFilterBuilder;
use fuzzer::filters::node_crash::NodeCrashFilterBuilder;
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

// ---------------------------------------------------------------------------
// Reorder filter (TASK-85) — seeded-RNG shuffle pool
// ---------------------------------------------------------------------------

#[test]
fn reorder_filter_size_zero_is_noop() {
    let mut f = MessageReorderingFilterBuilder::new()
        .outgoing(0, 0xa5_5a)
        .build();
    for i in 0..5 {
        assert_eq!(
            f.filter_outgoing(&AlgoMessage::broadcast(0, TAG, vec![i as u8])),
            FilterDecision::Keep,
        );
    }
}

#[test]
fn reorder_filter_holds_first_n_then_emits_displaced() {
    // shuffle_size=2 → first 2 messages are buffered (Drop); the 3rd
    // pushes the pool to 3 > 2 and triggers a random-index emission.
    let mut f = MessageReorderingFilterBuilder::new()
        .outgoing(2, 0x1234)
        .build();
    let m1 = AlgoMessage::broadcast(0, TAG, vec![1]);
    let m2 = AlgoMessage::broadcast(0, TAG, vec![2]);
    let m3 = AlgoMessage::broadcast(0, TAG, vec![3]);

    assert_eq!(f.filter_outgoing(&m1), FilterDecision::Drop);
    assert_eq!(f.outgoing_pool_size(), 1);
    assert_eq!(f.filter_outgoing(&m2), FilterDecision::Drop);
    assert_eq!(f.outgoing_pool_size(), 2);

    let dec3 = f.filter_outgoing(&m3);
    match dec3 {
        FilterDecision::Substitute { with } => {
            assert_eq!(with.len(), 1);
            // The displaced message must be one of the three we pushed.
            let payload = with[0].data[0];
            assert!(
                payload == 1 || payload == 2 || payload == 3,
                "displaced message payload {} is not one of [1,2,3]",
                payload,
            );
        }
        other => panic!("expected Substitute on overflow, got {:?}", other),
    }
    assert_eq!(f.outgoing_pool_size(), 2);
}

#[test]
fn reorder_filter_seed_is_deterministic() {
    // Two filters with the same seed should produce identical
    // displacement choices for the same input sequence.
    fn collect_displacements(seed: u64) -> Vec<u8> {
        let mut f = MessageReorderingFilterBuilder::new()
            .outgoing(2, seed)
            .build();
        let mut out = Vec::new();
        for i in 1u8..=10 {
            let dec = f.filter_outgoing(&AlgoMessage::broadcast(0, TAG, vec![i]));
            if let FilterDecision::Substitute { with } = dec {
                out.push(with[0].data[0]);
            }
        }
        out
    }
    let a = collect_displacements(0xc0fe);
    let b = collect_displacements(0xc0fe);
    assert_eq!(
        a, b,
        "same seed must produce identical displacement sequence"
    );
    // Sanity: different seed gives a (probably) different sequence.
    let c = collect_displacements(0xdead_beef);
    assert_ne!(
        a, c,
        "different seeds should differ on a 10-message sequence (probability of collision ~0)",
    );
}

#[test]
fn reorder_filter_tick_retention_flushes_expired_outgoing() {
    // Configure max_retention=4: messages older than 4 ticks are
    // auto-flushed via `tick`. Mirrors Go's MaxRetension at
    // messageReorderingFilter_test.go:32-34.
    let mut f = MessageReorderingFilterBuilder::new()
        .outgoing(8, 0xfeed) // shuffle_size large enough that
        // the 3 messages below stay parked
        // by displacement alone.
        .max_retention_ticks(4)
        .build();

    // Park three messages at tick 0 (the filter's initial current_tick).
    for i in 1u8..=3 {
        let _ = f.filter_outgoing(&AlgoMessage::broadcast(0, TAG, vec![i]));
    }
    assert_eq!(f.outgoing_pool_size(), 3);

    // Tick to 4 — arrival_tick=0 is NOT yet older than tick(4) - 4 = 0
    // (the cutoff is INCLUSIVE: `arrival_tick <= cutoff`), so they
    // expire exactly at tick 4.
    let flushed_at_4 = f.tick(4);
    assert_eq!(
        flushed_at_4.len(),
        3,
        "all 3 messages should flush at tick 4"
    );
    assert_eq!(f.outgoing_pool_size(), 0);

    // A subsequent tick with no new arrivals returns nothing.
    let flushed_at_5 = f.tick(5);
    assert!(flushed_at_5.is_empty());
}

#[test]
fn reorder_filter_drain_returns_remaining_pool() {
    let mut f = MessageReorderingFilterBuilder::new()
        .outgoing(3, 0x33)
        .build();
    for i in 1u8..=2 {
        let _ = f.filter_outgoing(&AlgoMessage::broadcast(0, TAG, vec![i]));
    }
    assert_eq!(f.outgoing_pool_size(), 2);
    let (out_drained, in_drained) = f.drain_pending();
    assert_eq!(out_drained.len(), 2);
    assert!(in_drained.is_empty());
    assert_eq!(f.outgoing_pool_size(), 0);
}

// ---------------------------------------------------------------------------
// NodeCrash filter (TASK-85) — tick-range based suppression
// ---------------------------------------------------------------------------

#[test]
fn node_crash_filter_default_is_passthrough() {
    // Default builder = crash window [0, 0) which means never crashed.
    let mut f = NodeCrashFilterBuilder::new().build();
    for i in 0..3 {
        assert_eq!(
            f.filter_outgoing(&AlgoMessage::broadcast(0, TAG, vec![i])),
            FilterDecision::Keep,
        );
        assert_eq!(
            f.filter_incoming(&AlgoMessage::unicast(1, 0, TAG, vec![i])),
            FilterDecision::Keep,
        );
    }
    assert_eq!(f.crashed_messages_seen(), 0);
}

#[test]
fn node_crash_filter_drops_inside_window_in_both_directions() {
    let mut f = NodeCrashFilterBuilder::new()
        .crash_window(2, 5) // crashed at ticks 2, 3, 4
        .build();

    // Tick 0: not crashed → Keep.
    assert_eq!(
        f.filter_outgoing(&AlgoMessage::broadcast(0, TAG, vec![0])),
        FilterDecision::Keep,
    );

    // Advance to tick 2: now crashed.
    let _ = f.tick(2);
    assert_eq!(
        f.filter_outgoing(&AlgoMessage::broadcast(0, TAG, vec![1])),
        FilterDecision::Drop,
    );
    assert_eq!(
        f.filter_incoming(&AlgoMessage::unicast(1, 0, TAG, vec![1])),
        FilterDecision::Drop,
    );

    // Still crashed at tick 4 (last tick of the [2, 5) window).
    let _ = f.tick(4);
    assert_eq!(
        f.filter_outgoing(&AlgoMessage::broadcast(0, TAG, vec![2])),
        FilterDecision::Drop,
    );

    // Tick 5: window over, node is back online.
    let _ = f.tick(5);
    assert_eq!(
        f.filter_outgoing(&AlgoMessage::broadcast(0, TAG, vec![3])),
        FilterDecision::Keep,
    );
    assert_eq!(f.crashed_messages_seen(), 3);
}

#[test]
#[should_panic(expected = "crash window start")]
fn node_crash_filter_rejects_inverted_window() {
    let _ = NodeCrashFilterBuilder::new().crash_window(10, 5).build();
}

#[test]
fn node_crash_filter_documents_delay_release_bypass_known_limitation() {
    // Locks down the documented limitation (see node_crash.rs module
    // header): messages parked in the NetworkFacade's delay heap
    // BEFORE the crash window starts are still released during the
    // window — the scheduler's tick_to releases them straight to the
    // router without re-entering the source's outgoing chain. If a
    // future PR plumbs an `is_crashed()` veto through the scheduler,
    // this test should be inverted; until then it captures current
    // behavior so the gap doesn't silently regress.
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

    // Chain: [NodeCrash(window 3..10), DelayOnce(5 ticks)]. The
    // outgoing message hits NodeCrash first (current_tick=0, not
    // crashed → Keep), then DelayOnce parks it for release at tick 5.
    // We then advance past the crash start (tick 3) and into the
    // window. At tick 5 the delayed message is released — the
    // documented limitation predicts it surfaces despite the node
    // being "crashed".
    let n = 2;
    let router = Router::new(n);
    let mut facades = Vec::with_capacity(n);
    facades.push(NetworkFacade::new(
        0,
        vec![
            Box::new(NodeCrashFilterBuilder::new().crash_window(3, 10).build()),
            Box::new(DelayOnceFilter { triggered: false }),
        ],
        Vec::new(),
    ));
    facades.push(NetworkFacade::new(1, Vec::new(), Vec::new()));
    let mut sched = Scheduler::new(router, facades);

    sched.enqueue_send(AlgoMessage::broadcast(0, TAG, vec![42]));
    sched.tick_to(5); // crosses crash_start (3) and reaches release (5)

    let recv = sched.drain_received(1);
    assert_eq!(
        recv.len(),
        1,
        "documented limitation: delayed messages bypass NodeCrash on release; \
         see node_crash.rs module header for the follow-up plan",
    );
    assert_eq!(recv[0].data, vec![42]);
}

// ---------------------------------------------------------------------------
// 4-filter scheduler integration (TASK-85 acceptance criterion)
// ---------------------------------------------------------------------------

/// Build a 4-node cluster with all four filters configured at node 0:
/// drop (rate=4), duplicate (rate=3, extra=1), reorder (size=2,
/// seeded), and node_crash (window 3..6 — i.e. ticks 3, 4, 5 are
/// crashed). Nodes 1, 2, 3 have empty chains. Returns the scheduler.
fn make_four_node_cluster_with_all_filters() -> Scheduler {
    let n = 4;
    let router = Router::new(n);
    let mut facades = Vec::with_capacity(n);
    facades.push(NetworkFacade::new(
        0,
        vec![
            Box::new(NodeCrashFilterBuilder::new().crash_window(3, 6).build()),
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
            Box::new(
                MessageReorderingFilterBuilder::new()
                    .outgoing(2, 0xc0de_cafe)
                    .build(),
            ),
        ],
        Vec::new(),
    ));
    facades.push(NetworkFacade::new(1, Vec::new(), Vec::new()));
    facades.push(NetworkFacade::new(2, Vec::new(), Vec::new()));
    facades.push(NetworkFacade::new(3, Vec::new(), Vec::new()));
    Scheduler::new(router, facades)
}

#[test]
fn scheduler_four_node_with_all_four_filters_is_deterministic() {
    // Drive 12 messages, advance the clock through the crash window,
    // then drive 12 more after the window. Two fresh runs must
    // produce byte-identical received logs at every receiver. This is
    // the deterministic-replay guarantee from the TASK-85 acceptance
    // criteria — proves all four filters compose without introducing
    // hidden non-determinism (e.g. random ordering, time-based
    // tiebreaks).
    fn run() -> [Vec<Vec<u8>>; 3] {
        let mut sched = make_four_node_cluster_with_all_filters();
        for i in 1u8..=12 {
            sched.enqueue_send(AlgoMessage::broadcast(0, TAG, vec![i]));
        }
        // Walk the clock through the crash window (3..6).
        sched.tick_to(7);
        for i in 13u8..=24 {
            sched.enqueue_send(AlgoMessage::broadcast(0, TAG, vec![i]));
        }
        sched.tick_to(20);
        [
            sched
                .drain_received(1)
                .iter()
                .map(|m| m.data.clone())
                .collect(),
            sched
                .drain_received(2)
                .iter()
                .map(|m| m.data.clone())
                .collect(),
            sched
                .drain_received(3)
                .iter()
                .map(|m| m.data.clone())
                .collect(),
        ]
    }

    let a = run();
    let b = run();
    for (i, (recv_a, recv_b)) in a.iter().zip(b.iter()).enumerate() {
        assert_eq!(
            recv_a,
            recv_b,
            "node {} receive log diverged across reruns — not deterministic",
            i + 1,
        );
    }

    // Each receiver should have gotten the SAME number of messages
    // (the cluster is a uniform broadcast topology with all filters
    // at the source node only).
    assert_eq!(a[0].len(), a[1].len());
    assert_eq!(a[1].len(), a[2].len());

    // And the count must be > 0 (filters drop / hold a lot but don't
    // suppress everything outside the crash window).
    assert!(
        !a[0].is_empty(),
        "expected at least some messages to survive the 4-filter chain",
    );
}
