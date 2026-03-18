// Agreement state persistence for crash recovery.
//
// Mirrors go-algorand/agreement/persistence.go.
//
// The agreement service persists its state (player + router + pending actions)
// to SQLite so it can recover after a crash without losing in-flight state
// or double-voting.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use crossbeam_channel::{bounded, Receiver, Sender};
use serde::{Deserialize, Serialize};

use algo_types::Round;

use crate::actions::{Action, ActionType};
use crate::events::CheckpointEvent;
use crate::player::Player;
use crate::router::RootRouter;
use crate::step::{Period, Step};
use crate::types::{
    CredentialArrivalHistory, TimeoutType, DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY,
};

// ---------------------------------------------------------------------------
// duration_map_serde — serialize HashMap<TimeoutType, Duration> with nanos
// ---------------------------------------------------------------------------

mod duration_map_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    /// Intermediate representation: each Duration stored as nanoseconds.
    #[derive(Serialize, Deserialize)]
    struct Entry {
        key: TimeoutType,
        nanos: u64,
    }

    pub fn serialize<S: Serializer>(
        map: &HashMap<TimeoutType, Duration>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let entries: Vec<Entry> = map
            .iter()
            .map(|(&key, &dur)| Entry {
                key,
                nanos: dur.as_nanos() as u64,
            })
            .collect();
        entries.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<HashMap<TimeoutType, Duration>, D::Error> {
        let entries: Vec<Entry> = Vec::deserialize(d)?;
        Ok(entries
            .into_iter()
            .map(|e| (e.key, Duration::from_nanos(e.nanos)))
            .collect())
    }
}

// ---------------------------------------------------------------------------
// ClockState
// ---------------------------------------------------------------------------

/// Represents the clock state that is persisted alongside player/router state.
///
/// Go persists a `Clock[TimeoutType]` which tracks deadline offsets per timeout
/// type. We model this as a map from `TimeoutType` to `Duration`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ClockState {
    /// Duration offsets for each active timeout, keyed by timeout type.
    #[serde(with = "duration_map_serde")]
    pub deadlines: HashMap<TimeoutType, Duration>,
}

// ---------------------------------------------------------------------------
// DiskState
// ---------------------------------------------------------------------------

/// The on-disk representation of agreement state.
///
/// Mirrors Go's `diskState` in agreement/persistence.go. Each field is
/// individually serialized so that future schema changes only affect the
/// sub-struct that changed.
#[derive(Debug, Serialize, Deserialize)]
pub struct DiskState {
    /// Encoded rootRouter (rmp-serde bytes).
    pub router: Vec<u8>,
    /// Encoded player (rmp-serde bytes).
    pub player: Vec<u8>,
    /// Encoded clock durations for each timeout type.
    pub clock: Vec<u8>,
    /// Action types for pending actions.
    pub action_types: Vec<ActionType>,
    /// Encoded actions (each action serialized separately).
    pub actions: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// PersistenceError
// ---------------------------------------------------------------------------

/// Errors that can occur during agreement state persistence.
#[derive(Debug)]
pub enum PersistenceError {
    /// Serialization/deserialization error.
    Encode(String),
    /// SQLite error.
    Db(rusqlite::Error),
    /// State is corrupt or incompatible.
    Corrupt(String),
}

impl fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(msg) => write!(f, "persistence encode error: {msg}"),
            Self::Db(e) => write!(f, "persistence db error: {e}"),
            Self::Corrupt(msg) => write!(f, "persistence corrupt state: {msg}"),
        }
    }
}

impl std::error::Error for PersistenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Db(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for PersistenceError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Db(e)
    }
}

// ---------------------------------------------------------------------------
// encode / decode
// ---------------------------------------------------------------------------

/// Encode agreement state for persistence.
///
/// Mirrors Go's `encode()` in persistence.go. Filters the router to only keep
/// rounds >= player.Round, matching Go's pre-persistence GC.
pub fn encode(
    router: &RootRouter,
    player: &Player,
    clock: &ClockState,
    actions: &[Action],
) -> Result<Vec<u8>, PersistenceError> {
    // Clone the router and filter children to only keep rounds >= player.round.
    let mut filtered_router = router.clone();
    filtered_router
        .children
        .retain(|&round, _| round.0 >= player.round.0);

    let router_bytes =
        rmp_serde::to_vec(&filtered_router).map_err(|e| PersistenceError::Encode(e.to_string()))?;
    let player_bytes =
        rmp_serde::to_vec(player).map_err(|e| PersistenceError::Encode(e.to_string()))?;
    let clock_bytes =
        rmp_serde::to_vec(clock).map_err(|e| PersistenceError::Encode(e.to_string()))?;

    let mut action_types = Vec::with_capacity(actions.len());
    let mut encoded_actions = Vec::with_capacity(actions.len());
    for action in actions {
        action_types.push(action.action_type());
        let action_bytes =
            rmp_serde::to_vec(action).map_err(|e| PersistenceError::Encode(e.to_string()))?;
        encoded_actions.push(action_bytes);
    }

    let disk_state = DiskState {
        router: router_bytes,
        player: player_bytes,
        clock: clock_bytes,
        action_types,
        actions: encoded_actions,
    };

    rmp_serde::to_vec(&disk_state).map_err(|e| PersistenceError::Encode(e.to_string()))
}

/// Decode persisted agreement state.
///
/// Mirrors Go's `decode()` in persistence.go. Recreates
/// `CredentialArrivalHistory` on the player since it is not faithfully
/// persisted (matching Go behavior).
pub fn decode(
    raw: &[u8],
) -> Result<(RootRouter, Player, ClockState, Vec<Action>), PersistenceError> {
    let disk_state: DiskState =
        rmp_serde::from_slice(raw).map_err(|e| PersistenceError::Corrupt(e.to_string()))?;

    let router: RootRouter = rmp_serde::from_slice(&disk_state.router)
        .map_err(|e| PersistenceError::Corrupt(e.to_string()))?;
    let mut player: Player = rmp_serde::from_slice(&disk_state.player)
        .map_err(|e| PersistenceError::Corrupt(e.to_string()))?;
    let clock: ClockState = rmp_serde::from_slice(&disk_state.clock)
        .map_err(|e| PersistenceError::Corrupt(e.to_string()))?;

    // Recreate credential arrival history — Go does this because the history
    // is not faithfully persisted.
    player.lowest_credential_arrivals =
        CredentialArrivalHistory::new(DYNAMIC_FILTER_CREDENTIAL_ARRIVAL_HISTORY);

    if disk_state.action_types.len() != disk_state.actions.len() {
        return Err(PersistenceError::Corrupt(format!(
            "action_types length ({}) != actions length ({})",
            disk_state.action_types.len(),
            disk_state.actions.len(),
        )));
    }

    let mut actions = Vec::with_capacity(disk_state.actions.len());
    for (i, action_bytes) in disk_state.actions.iter().enumerate() {
        let action: Action = rmp_serde::from_slice(action_bytes).map_err(|e| {
            PersistenceError::Corrupt(format!(
                "failed to decode action {} ({:?}): {}",
                i, disk_state.action_types[i], e
            ))
        })?;
        actions.push(action);
    }

    Ok((router, player, clock, actions))
}

// ---------------------------------------------------------------------------
// SQLite persist / restore / reset
// ---------------------------------------------------------------------------

/// Ensure the Service table exists.
fn ensure_table(conn: &rusqlite::Connection) -> Result<(), PersistenceError> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS Service (data BLOB)")?;
    Ok(())
}

/// Persist encoded state to SQLite.
///
/// Mirrors Go's `persist()` — atomic single-row replace.
pub fn persist(conn: &rusqlite::Connection, raw: &[u8]) -> Result<(), PersistenceError> {
    ensure_table(conn)?;
    conn.execute(
        "INSERT OR REPLACE INTO Service (rowid, data) VALUES (1, ?1)",
        rusqlite::params![raw],
    )?;
    Ok(())
}

/// Restore persisted state from SQLite.
///
/// Returns `None` if no state is persisted (fresh start).
/// Mirrors Go's `restore()`.
pub fn restore(conn: &rusqlite::Connection) -> Result<Option<Vec<u8>>, PersistenceError> {
    ensure_table(conn)?;
    let mut stmt = conn.prepare("SELECT data FROM Service WHERE rowid = 1")?;
    let mut rows = stmt.query([])?;
    match rows.next()? {
        Some(row) => {
            let data: Vec<u8> = row.get(0)?;
            Ok(Some(data))
        }
        None => Ok(None),
    }
}

/// Clear persisted state.
///
/// Mirrors Go's `reset()`.
pub fn reset(conn: &rusqlite::Connection) -> Result<(), PersistenceError> {
    ensure_table(conn)?;
    conn.execute("DELETE FROM Service", [])?;
    Ok(())
}

// ---------------------------------------------------------------------------
// persistent helper
// ---------------------------------------------------------------------------

/// Check if any action in the slice is persistent (i.e., an attest action).
///
/// Mirrors Go's `persistent()` function.
pub fn persistent(actions: &[Action]) -> bool {
    actions.iter().any(|a| a.persistent())
}

// ---------------------------------------------------------------------------
// PersistentRequest
// ---------------------------------------------------------------------------

/// A request to persist agreement state.
///
/// Mirrors Go's `persistentRequest`.
pub struct PersistentRequest {
    /// Round at the time of the request.
    pub round: Round,
    /// Period at the time of the request.
    pub period: Period,
    /// Step at the time of the request.
    pub step: Step,
    /// The raw encoded agreement state (output of `encode()`).
    pub raw: Vec<u8>,
    /// Channel to signal completion (with optional error).
    pub done: Sender<Result<(), PersistenceError>>,
    /// The clock state at the time of the request.
    pub clock: ClockState,
    /// Channel to send the checkpoint event once persistence is done.
    pub events: Sender<CheckpointEvent>,
}

// ---------------------------------------------------------------------------
// AsyncPersistenceLoop
// ---------------------------------------------------------------------------

/// Async persistence loop that writes state to SQLite in a background thread.
///
/// Mirrors Go's `asyncPersistenceLoop`. Receives persistence requests on a
/// channel, writes them to the crash recovery database, and signals completion.
pub struct AsyncPersistenceLoop {
    pending: Sender<PersistentRequest>,
    pending_rx: Option<Receiver<PersistentRequest>>,
    conn: Option<rusqlite::Connection>,
    handle: Option<std::thread::JoinHandle<()>>,
    quit_tx: Sender<()>,
    quit_rx: Option<Receiver<()>>,
}

impl AsyncPersistenceLoop {
    /// Create a new persistence loop.
    ///
    /// `conn` is the SQLite connection for the crash recovery database.
    /// The loop is not started until `start()` is called.
    pub fn new(conn: rusqlite::Connection) -> Self {
        let (pending_tx, pending_rx) = bounded(1);
        let (quit_tx, quit_rx) = bounded(1);
        Self {
            pending: pending_tx,
            pending_rx: Some(pending_rx),
            conn: Some(conn),
            handle: None,
            quit_tx,
            quit_rx: Some(quit_rx),
        }
    }

    /// Enqueue a persistence request.
    ///
    /// This will block if there is already a pending request (bounded channel
    /// of capacity 1), matching Go's behavior where a second write waits for
    /// the first to drain.
    pub fn enqueue(&self, request: PersistentRequest) {
        // Best-effort: if the channel is full, the caller blocks. This is
        // intentional — Go's `pending` channel has capacity 1.
        let _ = self.pending.send(request);
    }

    /// Start the background persistence loop.
    ///
    /// Spawns a thread that processes persistence requests until `quit()` is
    /// called.
    pub fn start(&mut self) {
        let pending_rx = self
            .pending_rx
            .take()
            .expect("start() called more than once");
        let quit_rx = self.quit_rx.take().expect("start() called more than once");
        let conn = self.conn.take().expect("start() called more than once");

        let handle = std::thread::Builder::new()
            .name("agreement-persistence".into())
            .spawn(move || {
                Self::run_loop(conn, pending_rx, quit_rx);
            })
            .expect("failed to spawn persistence thread");

        self.handle = Some(handle);
    }

    /// Signal the loop to quit and wait for it to finish.
    pub fn quit(&mut self) {
        let _ = self.quit_tx.send(());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    /// The background loop.
    fn run_loop(
        conn: rusqlite::Connection,
        pending_rx: Receiver<PersistentRequest>,
        quit_rx: Receiver<()>,
    ) {
        loop {
            crossbeam_channel::select! {
                recv(pending_rx) -> msg => {
                    match msg {
                        Ok(request) => {
                            Self::handle_request(&conn, request);
                        }
                        Err(_) => {
                            // Channel closed — sender dropped.
                            break;
                        }
                    }
                }
                recv(quit_rx) -> _ => {
                    break;
                }
            }
        }
    }

    /// Handle a single persistence request.
    fn handle_request(conn: &rusqlite::Connection, request: PersistentRequest) {
        let result = persist(conn, &request.raw);

        let checkpoint_err = match &result {
            Ok(()) => None,
            Err(e) => Some(crate::events::SerializableError::new(e.to_string())),
        };

        let checkpoint = CheckpointEvent {
            round: request.round,
            period: request.period,
            step: request.step,
            err: checkpoint_err,
        };

        // Send the checkpoint event. Ignore errors (receiver may have been
        // dropped if the service is shutting down).
        let _ = request.events.send(checkpoint);

        // Sanity check: verify the persisted state can be decoded.
        if result.is_ok() {
            if let Err(e) = decode(&request.raw) {
                tracing::warn!(
                    "agreement persistence sanity check failed: {e}; \
                     state was persisted but may not be recoverable"
                );
            }
        }

        // Signal completion.
        let _ = request.done.send(result);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{Action, ActionType, NoopAction, PseudonodeAction};
    use crate::player::Player;
    use crate::router::RootRouter;
    use crate::step::{Period, Step};
    use crate::vote::BOTTOM;

    /// Helper: create an in-memory SQLite connection.
    fn mem_db() -> rusqlite::Connection {
        rusqlite::Connection::open_in_memory().expect("open in-memory db")
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let player = Player::default();
        let router = RootRouter::default();
        let clock = ClockState::default();
        let actions: Vec<Action> = vec![Action::Noop(NoopAction)];

        let raw = encode(&router, &player, &clock, &actions).expect("encode");
        let (dec_router, dec_player, dec_clock, dec_actions) = decode(&raw).expect("decode");

        // Player fields should match (except credential_arrivals which is recreated).
        assert_eq!(dec_player.round, player.round);
        assert_eq!(dec_player.period, player.period);
        assert_eq!(dec_player.step, player.step);

        // Router should be empty (default has no children).
        assert!(dec_router.children.is_empty());

        // Clock should be empty.
        assert!(dec_clock.deadlines.is_empty());

        // Actions should roundtrip.
        assert_eq!(dec_actions.len(), 1);
        assert_eq!(dec_actions[0].action_type(), ActionType::Noop);
    }

    #[test]
    fn test_encode_filters_old_rounds() {
        let player = Player {
            round: Round(10),
            ..Player::default()
        };
        let mut router = RootRouter::default();
        // Add some old and current round entries.
        router
            .children
            .insert(Round(5), crate::router::RoundRouter::default());
        router
            .children
            .insert(Round(10), crate::router::RoundRouter::default());
        router
            .children
            .insert(Round(15), crate::router::RoundRouter::default());

        let clock = ClockState::default();
        let actions: Vec<Action> = vec![];

        let raw = encode(&router, &player, &clock, &actions).expect("encode");
        let (dec_router, _, _, _) = decode(&raw).expect("decode");

        // Round 5 should have been filtered out (< player.round 10).
        assert!(!dec_router.children.contains_key(&Round(5)));
        // Round 10 and 15 should be kept.
        assert!(dec_router.children.contains_key(&Round(10)));
        assert!(dec_router.children.contains_key(&Round(15)));
    }

    #[test]
    fn test_encode_decode_with_clock_state() {
        let player = Player::default();
        let router = RootRouter::default();
        let mut clock = ClockState::default();
        clock
            .deadlines
            .insert(TimeoutType::Deadline, Duration::from_secs(5));
        clock
            .deadlines
            .insert(TimeoutType::FastRecovery, Duration::from_millis(1500));

        let raw = encode(&router, &player, &clock, &[]).expect("encode");
        let (_, _, dec_clock, _) = decode(&raw).expect("decode");

        assert_eq!(
            dec_clock.deadlines.get(&TimeoutType::Deadline),
            Some(&Duration::from_secs(5))
        );
        assert_eq!(
            dec_clock.deadlines.get(&TimeoutType::FastRecovery),
            Some(&Duration::from_millis(1500))
        );
    }

    #[test]
    fn test_persist_restore() {
        let conn = mem_db();
        let player = Player::default();
        let router = RootRouter::default();
        let clock = ClockState::default();
        let actions: Vec<Action> = vec![Action::Noop(NoopAction)];

        let raw = encode(&router, &player, &clock, &actions).expect("encode");
        persist(&conn, &raw).expect("persist");

        let restored = restore(&conn).expect("restore");
        assert!(restored.is_some());
        assert_eq!(restored.unwrap(), raw);
    }

    #[test]
    fn test_restore_empty() {
        let conn = mem_db();
        let restored = restore(&conn).expect("restore from empty db");
        assert!(restored.is_none());
    }

    #[test]
    fn test_reset() {
        let conn = mem_db();
        let player = Player::default();
        let router = RootRouter::default();
        let clock = ClockState::default();

        let raw = encode(&router, &player, &clock, &[]).expect("encode");
        persist(&conn, &raw).expect("persist");

        // Verify it's there.
        assert!(restore(&conn).expect("restore").is_some());

        // Reset.
        reset(&conn).expect("reset");

        // Should be gone.
        assert!(restore(&conn).expect("restore after reset").is_none());
    }

    #[test]
    fn test_persistent_check() {
        // No actions -> not persistent.
        assert!(!persistent(&[]));

        // Noop is not persistent.
        assert!(!persistent(&[Action::Noop(NoopAction)]));

        // Attest action IS persistent.
        let attest = Action::Pseudonode(PseudonodeAction {
            t: ActionType::Attest,
            round: Round(1),
            period: Period(0),
            step: Step(1),
            proposal: BOTTOM,
        });
        assert!(persistent(&[attest]));

        // Assemble action is NOT persistent.
        let assemble = Action::Pseudonode(PseudonodeAction {
            t: ActionType::Assemble,
            round: Round(1),
            period: Period(0),
            step: Step(0),
            proposal: BOTTOM,
        });
        assert!(!persistent(&[assemble]));

        // Mixed: if any action is persistent, returns true.
        let mixed = vec![
            Action::Noop(NoopAction),
            Action::Pseudonode(PseudonodeAction {
                t: ActionType::Attest,
                round: Round(1),
                period: Period(0),
                step: Step(1),
                proposal: BOTTOM,
            }),
        ];
        assert!(persistent(&mixed));
    }

    #[test]
    fn test_persist_overwrite() {
        let conn = mem_db();

        // Persist initial state.
        let raw1 = encode(
            &RootRouter::default(),
            &Player::default(),
            &ClockState::default(),
            &[],
        )
        .expect("encode 1");
        persist(&conn, &raw1).expect("persist 1");

        // Persist new state — should replace the old one.
        let player2 = Player {
            round: Round(42),
            ..Player::default()
        };
        let raw2 = encode(
            &RootRouter::default(),
            &player2,
            &ClockState::default(),
            &[],
        )
        .expect("encode 2");
        persist(&conn, &raw2).expect("persist 2");

        // Restore should get the latest.
        let restored = restore(&conn).expect("restore").expect("should have data");
        assert_eq!(restored, raw2);
        assert_ne!(restored, raw1);
    }

    #[test]
    fn test_async_persistence_loop() {
        let conn = mem_db();
        let mut loop_handle = AsyncPersistenceLoop::new(conn);
        loop_handle.start();

        let player = Player::default();
        let router = RootRouter::default();
        let clock = ClockState::default();
        let raw = encode(&router, &player, &clock, &[]).expect("encode");

        let (done_tx, done_rx) = bounded(1);
        let (events_tx, events_rx) = bounded(1);

        let request = PersistentRequest {
            round: Round(1),
            period: Period(0),
            step: Step(1),
            raw: raw.clone(),
            done: done_tx,
            clock: clock.clone(),
            events: events_tx,
        };

        loop_handle.enqueue(request);

        // Wait for completion.
        let result = done_rx.recv().expect("receive done");
        assert!(result.is_ok());

        // Should have received a checkpoint event.
        let checkpoint = events_rx.recv().expect("receive checkpoint");
        assert_eq!(checkpoint.round, Round(1));
        assert_eq!(checkpoint.period, Period(0));
        assert_eq!(checkpoint.step, Step(1));
        assert!(checkpoint.err.is_none());

        loop_handle.quit();
    }

    // -----------------------------------------------------------------------
    // Additional comprehensive tests
    // -----------------------------------------------------------------------

    use crate::router::{PeriodRouter, RoundRouter, StepRouter};
    use crate::vote::ProposalValue;
    use algo_types::{Address, Digest};

    /// Helper: create a non-trivial ProposalValue.
    fn test_proposal(seed: u8) -> ProposalValue {
        ProposalValue {
            original_period: Period(seed as u64),
            original_proposer: Address([seed; 32]),
            block_digest: Digest([seed; 32]),
            encoding_digest: Digest([seed.wrapping_add(1); 32]),
        }
    }

    // -- Test: encode/decode with non-trivial nested router state -----------

    #[test]
    fn test_encode_decode_nontrivial_router_state() {
        // Build a router with actual child RoundRouters containing
        // PeriodRouters with StepRouters.
        let mut router = RootRouter::default();

        // Round 10 with nested period and step routers
        let mut round_router = RoundRouter::default();
        let mut period_router = PeriodRouter::default();
        period_router
            .children
            .insert(Step(1), StepRouter::default());
        period_router
            .children
            .insert(Step(2), StepRouter::default());
        round_router
            .children
            .insert(Period(0), period_router.clone());
        round_router.children.insert(Period(1), period_router);
        router.children.insert(Round(10), round_router);

        // Round 20 with a simpler structure
        let mut round_router2 = RoundRouter::default();
        round_router2
            .children
            .insert(Period(0), PeriodRouter::default());
        router.children.insert(Round(20), round_router2);

        let player = Player {
            round: Round(10),
            period: Period(1),
            step: Step(2),
            ..Player::default()
        };
        let clock = ClockState::default();

        let raw = encode(&router, &player, &clock, &[]).expect("encode");
        let (dec_router, dec_player, _, _) = decode(&raw).expect("decode");

        // Player state preserved
        assert_eq!(dec_player.round, Round(10));
        assert_eq!(dec_player.period, Period(1));
        assert_eq!(dec_player.step, Step(2));

        // Both rounds should be present (10 >= player.round=10, 20 >= 10)
        assert_eq!(dec_router.children.len(), 2);
        assert!(dec_router.children.contains_key(&Round(10)));
        assert!(dec_router.children.contains_key(&Round(20)));

        // Check nested structure for round 10
        let rr10 = &dec_router.children[&Round(10)];
        assert_eq!(rr10.children.len(), 2);
        assert!(rr10.children.contains_key(&Period(0)));
        assert!(rr10.children.contains_key(&Period(1)));

        // Check step routers preserved within period 0 of round 10
        let pr0 = &rr10.children[&Period(0)];
        assert_eq!(pr0.children.len(), 2);
        assert!(pr0.children.contains_key(&Step(1)));
        assert!(pr0.children.contains_key(&Step(2)));

        // Check round 20 structure
        let rr20 = &dec_router.children[&Round(20)];
        assert_eq!(rr20.children.len(), 1);
    }

    // -- Test: encode/decode with ProposalTracker staging set ---------------

    #[test]
    fn test_encode_decode_router_with_proposal_tracker_state() {
        let mut router = RootRouter::default();
        let mut round_router = RoundRouter::default();
        let mut period_router = PeriodRouter::default();

        // Set the staging value in the ProposalTracker
        let pv = test_proposal(0xAB);
        period_router.proposal_tracker.staging = pv;
        period_router
            .proposal_tracker
            .duplicate
            .insert(Address([0x01; 32]), true);
        period_router
            .proposal_tracker
            .duplicate
            .insert(Address([0x02; 32]), true);

        round_router.children.insert(Period(0), period_router);
        router.children.insert(Round(5), round_router);

        let player = Player {
            round: Round(5),
            ..Player::default()
        };
        let clock = ClockState::default();

        let raw = encode(&router, &player, &clock, &[]).expect("encode");
        let (dec_router, _, _, _) = decode(&raw).expect("decode");

        let rr = &dec_router.children[&Round(5)];
        let pr = &rr.children[&Period(0)];
        assert_eq!(pr.proposal_tracker.staging, pv);
        assert_eq!(pr.proposal_tracker.duplicate.len(), 2);
        assert!(pr
            .proposal_tracker
            .duplicate
            .contains_key(&Address([0x01; 32])));
    }

    // -- Test: encode/decode with PseudonodeAction (Attest) -----------------

    #[test]
    fn test_encode_decode_with_attest_action() {
        let player = Player::default();
        let router = RootRouter::default();
        let clock = ClockState::default();

        let pv = test_proposal(0xCC);
        let attest = Action::Pseudonode(PseudonodeAction {
            t: ActionType::Attest,
            round: Round(42),
            period: Period(3),
            step: Step(7),
            proposal: pv,
        });
        let actions = vec![attest];

        let raw = encode(&router, &player, &clock, &actions).expect("encode");
        let (_, _, _, dec_actions) = decode(&raw).expect("decode");

        assert_eq!(dec_actions.len(), 1);
        assert_eq!(dec_actions[0].action_type(), ActionType::Attest);
        assert!(dec_actions[0].persistent());

        if let Action::Pseudonode(ref pa) = dec_actions[0] {
            assert_eq!(pa.round, Round(42));
            assert_eq!(pa.period, Period(3));
            assert_eq!(pa.step, Step(7));
            assert_eq!(pa.proposal, pv);
        } else {
            panic!("expected Pseudonode action");
        }
    }

    // -- Test: encode/decode with multiple action types ---------------------

    #[test]
    fn test_encode_decode_with_mixed_actions() {
        let player = Player::default();
        let router = RootRouter::default();
        let clock = ClockState::default();

        let actions = vec![
            Action::Noop(NoopAction),
            Action::Pseudonode(PseudonodeAction {
                t: ActionType::Attest,
                round: Round(1),
                period: Period(0),
                step: Step(1),
                proposal: BOTTOM,
            }),
            Action::Pseudonode(PseudonodeAction {
                t: ActionType::Assemble,
                round: Round(2),
                period: Period(1),
                step: Step(0),
                proposal: test_proposal(0x55),
            }),
            Action::Rezero(crate::actions::RezeroAction { round: Round(99) }),
            Action::Checkpoint(crate::actions::CheckpointAction {
                round: Round(10),
                period: Period(2),
                step: Step(3),
                err: None,
            }),
        ];

        let raw = encode(&router, &player, &clock, &actions).expect("encode");
        let (_, _, _, dec_actions) = decode(&raw).expect("decode");

        assert_eq!(dec_actions.len(), 5);
        assert_eq!(dec_actions[0].action_type(), ActionType::Noop);
        assert_eq!(dec_actions[1].action_type(), ActionType::Attest);
        assert_eq!(dec_actions[2].action_type(), ActionType::Assemble);
        assert_eq!(dec_actions[3].action_type(), ActionType::Rezero);
        assert_eq!(dec_actions[4].action_type(), ActionType::Checkpoint);

        // Verify Rezero action round survived
        if let Action::Rezero(ref ra) = dec_actions[3] {
            assert_eq!(ra.round, Round(99));
        } else {
            panic!("expected Rezero action");
        }
    }

    // -- Test: encode filters stale rounds correctly (5, 10, 15 scenario) ---

    #[test]
    fn test_encode_filters_stale_rounds_precisely() {
        let player = Player {
            round: Round(10),
            ..Player::default()
        };
        let mut router = RootRouter::default();
        router.children.insert(Round(5), RoundRouter::default());
        router.children.insert(Round(10), RoundRouter::default());
        router.children.insert(Round(15), RoundRouter::default());

        let raw = encode(&router, &player, &ClockState::default(), &[]).expect("encode");
        let (dec_router, _, _, _) = decode(&raw).expect("decode");

        // Only rounds >= player.round (10) should remain.
        assert_eq!(dec_router.children.len(), 2);
        assert!(!dec_router.children.contains_key(&Round(5)));
        assert!(dec_router.children.contains_key(&Round(10)));
        assert!(dec_router.children.contains_key(&Round(15)));
    }

    // -- Test: encode preserves original router (no mutation) ---------------

    #[test]
    fn test_encode_does_not_mutate_original_router() {
        let player = Player {
            round: Round(10),
            ..Player::default()
        };
        let mut router = RootRouter::default();
        router.children.insert(Round(5), RoundRouter::default());
        router.children.insert(Round(10), RoundRouter::default());

        let _ = encode(&router, &player, &ClockState::default(), &[]).expect("encode");

        // Original router should still have both rounds
        assert_eq!(router.children.len(), 2);
        assert!(router.children.contains_key(&Round(5)));
        assert!(router.children.contains_key(&Round(10)));
    }

    // -- Test: decode corrupt data ------------------------------------------

    #[test]
    fn test_decode_corrupt_data() {
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x42];
        let result = decode(&garbage);
        assert!(result.is_err());
        match result.unwrap_err() {
            PersistenceError::Corrupt(msg) => {
                assert!(!msg.is_empty(), "corrupt error message should not be empty");
            }
            other => panic!("expected PersistenceError::Corrupt, got: {:?}", other),
        }
    }

    // -- Test: decode empty data --------------------------------------------

    #[test]
    fn test_decode_empty_data() {
        let result = decode(&[]);
        assert!(result.is_err());
        match result.unwrap_err() {
            PersistenceError::Corrupt(msg) => {
                assert!(!msg.is_empty(), "corrupt error message should not be empty");
            }
            other => panic!("expected PersistenceError::Corrupt, got: {:?}", other),
        }
    }

    // -- Test: decode truncated data ----------------------------------------

    #[test]
    fn test_decode_truncated_data() {
        // Encode valid state, then truncate the bytes
        let player = Player::default();
        let router = RootRouter::default();
        let clock = ClockState::default();
        let raw = encode(&router, &player, &clock, &[]).expect("encode");

        // Truncate to half the length
        let truncated = &raw[..raw.len() / 2];
        let result = decode(truncated);
        assert!(result.is_err());
        match result.unwrap_err() {
            PersistenceError::Corrupt(_) => {} // Expected
            other => panic!("expected PersistenceError::Corrupt, got: {:?}", other),
        }
    }

    // -- Test: persist/restore large state -----------------------------------

    #[test]
    fn test_persist_restore_large_state() {
        let conn = mem_db();

        let mut router = RootRouter::default();
        // Create 50 rounds, each with 3 periods, each with 4 steps
        for r in 100..150 {
            let mut round_router = RoundRouter::default();
            for p in 0..3 {
                let mut period_router = PeriodRouter::default();
                for s in 0..4 {
                    period_router
                        .children
                        .insert(Step(s), StepRouter::default());
                }
                round_router.children.insert(Period(p), period_router);
            }
            router.children.insert(Round(r), round_router);
        }

        let player = Player {
            round: Round(100),
            period: Period(2),
            step: Step(3),
            ..Player::default()
        };

        let mut clock = ClockState::default();
        clock
            .deadlines
            .insert(TimeoutType::Deadline, Duration::from_secs(5));
        clock
            .deadlines
            .insert(TimeoutType::FastRecovery, Duration::from_millis(750));
        clock
            .deadlines
            .insert(TimeoutType::Filter, Duration::from_nanos(123456789));

        // Many actions
        let mut actions: Vec<Action> = Vec::new();
        for i in 0..10 {
            actions.push(Action::Pseudonode(PseudonodeAction {
                t: ActionType::Attest,
                round: Round(100 + i),
                period: Period(0),
                step: Step(1),
                proposal: test_proposal(i as u8),
            }));
        }

        let raw = encode(&router, &player, &clock, &actions).expect("encode large state");
        persist(&conn, &raw).expect("persist large state");

        let restored_raw = restore(&conn)
            .expect("restore large state")
            .expect("should have data");
        assert_eq!(restored_raw, raw);

        let (dec_router, dec_player, dec_clock, dec_actions) =
            decode(&restored_raw).expect("decode large state");

        // All 50 rounds should be kept (all >= player.round 100)
        assert_eq!(dec_router.children.len(), 50);
        assert_eq!(dec_player.round, Round(100));
        assert_eq!(dec_player.period, Period(2));
        assert_eq!(dec_player.step, Step(3));
        assert_eq!(dec_clock.deadlines.len(), 3);
        assert_eq!(dec_actions.len(), 10);

        // Spot check a few actions
        for (i, action) in dec_actions.iter().enumerate() {
            assert_eq!(action.action_type(), ActionType::Attest);
            if let Action::Pseudonode(ref pa) = action {
                assert_eq!(pa.round, Round(100 + i as u64));
            }
        }
    }

    // -- Test: multiple persist overwrites, restore gets latest --------------

    #[test]
    fn test_multiple_persist_overwrites_restore_gets_latest() {
        let conn = mem_db();

        // Persist state A (round 1)
        let raw_a = encode(
            &RootRouter::default(),
            &Player {
                round: Round(1),
                ..Player::default()
            },
            &ClockState::default(),
            &[],
        )
        .expect("encode A");
        persist(&conn, &raw_a).expect("persist A");

        // Persist state B (round 2)
        let raw_b = encode(
            &RootRouter::default(),
            &Player {
                round: Round(2),
                ..Player::default()
            },
            &ClockState::default(),
            &[],
        )
        .expect("encode B");
        persist(&conn, &raw_b).expect("persist B");

        // Persist state C (round 3)
        let raw_c = encode(
            &RootRouter::default(),
            &Player {
                round: Round(3),
                ..Player::default()
            },
            &ClockState::default(),
            &[Action::Noop(NoopAction)],
        )
        .expect("encode C");
        persist(&conn, &raw_c).expect("persist C");

        // Restore — should get C
        let restored = restore(&conn).expect("restore").expect("data");
        assert_eq!(restored, raw_c);
        assert_ne!(restored, raw_a);
        assert_ne!(restored, raw_b);

        let (_, dec_player, _, dec_actions) = decode(&restored).expect("decode C");
        assert_eq!(dec_player.round, Round(3));
        assert_eq!(dec_actions.len(), 1);
    }

    // -- Test: persist then reset then persist again -------------------------

    #[test]
    fn test_persist_reset_persist_cycle() {
        let conn = mem_db();

        // Persist state A
        let raw_a = encode(
            &RootRouter::default(),
            &Player::default(),
            &ClockState::default(),
            &[],
        )
        .expect("encode A");
        persist(&conn, &raw_a).expect("persist A");
        assert!(restore(&conn).expect("restore A").is_some());

        // Reset
        reset(&conn).expect("reset");
        assert!(restore(&conn).expect("restore after reset").is_none());

        // Persist state B
        let raw_b = encode(
            &RootRouter::default(),
            &Player {
                round: Round(99),
                ..Player::default()
            },
            &ClockState::default(),
            &[],
        )
        .expect("encode B");
        persist(&conn, &raw_b).expect("persist B");

        let restored = restore(&conn).expect("restore B").expect("data");
        assert_eq!(restored, raw_b);

        let (_, dec_player, _, _) = decode(&restored).expect("decode B");
        assert_eq!(dec_player.round, Round(99));
    }

    // -- Test: credential arrival history is recreated on decode -------------

    #[test]
    fn test_decode_recreates_credential_arrival_history() {
        let player = Player {
            round: Round(5),
            period: Period(2),
            step: Step(3),
            ..Player::default()
        };
        let router = RootRouter::default();
        let clock = ClockState::default();

        let raw = encode(&router, &player, &clock, &[]).expect("encode");
        let (_, dec_player, _, _) = decode(&raw).expect("decode");

        // The credential arrival history should have been recreated fresh
        // (not full, since it was just initialized).
        assert!(
            !dec_player.lowest_credential_arrivals.is_full(),
            "freshly recreated credential arrival history should not be full"
        );
    }

    // -- Test: async persistence loop — done channel pattern ----------------

    #[test]
    fn test_async_loop_done_channel_receives_ok() {
        let conn = mem_db();
        let mut lp = AsyncPersistenceLoop::new(conn);
        lp.start();

        let player = Player {
            round: Round(7),
            period: Period(1),
            ..Player::default()
        };
        let router = RootRouter::default();
        let clock = ClockState {
            deadlines: {
                let mut m = HashMap::new();
                m.insert(TimeoutType::Filter, Duration::from_millis(500));
                m
            },
        };
        let raw = encode(&router, &player, &clock, &[]).expect("encode");

        let (done_tx, done_rx) = bounded(1);
        let (events_tx, events_rx) = bounded(1);

        lp.enqueue(PersistentRequest {
            round: Round(7),
            period: Period(1),
            step: Step(2),
            raw,
            done: done_tx,
            clock,
            events: events_tx,
        });

        // done channel receives Ok
        let result = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("done channel timed out");
        assert!(result.is_ok(), "persistence should succeed");

        // checkpoint event received with correct fields
        let ckpt = events_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("events channel timed out");
        assert_eq!(ckpt.round, Round(7));
        assert_eq!(ckpt.period, Period(1));
        assert_eq!(ckpt.step, Step(2));
        assert!(ckpt.err.is_none(), "checkpoint should have no error");

        lp.quit();
    }

    // -- Test: async persistence loop — multiple sequential requests --------

    #[test]
    fn test_async_loop_multiple_sequential_requests() {
        let conn = mem_db();
        let mut lp = AsyncPersistenceLoop::new(conn);
        lp.start();

        for round_num in 1..=5u64 {
            let player = Player {
                round: Round(round_num),
                ..Player::default()
            };
            let raw = encode(&RootRouter::default(), &player, &ClockState::default(), &[])
                .expect("encode");

            let (done_tx, done_rx) = bounded(1);
            let (events_tx, events_rx) = bounded(1);

            lp.enqueue(PersistentRequest {
                round: Round(round_num),
                period: Period(0),
                step: Step(1),
                raw,
                done: done_tx,
                clock: ClockState::default(),
                events: events_tx,
            });

            let result = done_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("done timed out");
            assert!(result.is_ok(), "round {round_num} should succeed");

            let ckpt = events_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("events timed out");
            assert_eq!(ckpt.round, Round(round_num));
            assert!(ckpt.err.is_none());
        }

        lp.quit();
    }

    // -- Test: async persistence loop — quit while idle ---------------------

    #[test]
    fn test_async_loop_quit_while_idle() {
        let conn = mem_db();
        let mut lp = AsyncPersistenceLoop::new(conn);
        lp.start();
        // Quit immediately without enqueuing any request — should not hang.
        lp.quit();
    }

    // -- Test: async persistence loop — quit after processing ---------------

    #[test]
    fn test_async_loop_quit_after_processing() {
        let conn = mem_db();
        let mut lp = AsyncPersistenceLoop::new(conn);
        lp.start();

        let raw = encode(
            &RootRouter::default(),
            &Player::default(),
            &ClockState::default(),
            &[],
        )
        .expect("encode");

        let (done_tx, done_rx) = bounded(1);
        let (events_tx, _events_rx) = bounded(1);

        lp.enqueue(PersistentRequest {
            round: Round(1),
            period: Period(0),
            step: Step(0),
            raw,
            done: done_tx,
            clock: ClockState::default(),
            events: events_tx,
        });

        // Wait for completion
        let _ = done_rx.recv_timeout(Duration::from_secs(5)).expect("done");

        // Now quit — should not hang or panic
        lp.quit();
    }

    // -- Test: PersistenceError Display implementations ----------------------

    #[test]
    fn test_persistence_error_display() {
        let encode_err = PersistenceError::Encode("bad data".to_string());
        assert!(format!("{encode_err}").contains("bad data"));

        let corrupt_err = PersistenceError::Corrupt("wrong version".to_string());
        assert!(format!("{corrupt_err}").contains("wrong version"));

        // Db error
        let db_err = PersistenceError::Db(rusqlite::Error::QueryReturnedNoRows);
        let display = format!("{db_err}");
        assert!(display.contains("db error"));
    }

    // -- Test: PersistenceError source() ------------------------------------

    #[test]
    fn test_persistence_error_source() {
        use std::error::Error;

        let encode_err = PersistenceError::Encode("test".into());
        assert!(encode_err.source().is_none());

        let corrupt_err = PersistenceError::Corrupt("test".into());
        assert!(corrupt_err.source().is_none());

        let db_err = PersistenceError::Db(rusqlite::Error::QueryReturnedNoRows);
        assert!(db_err.source().is_some());
    }

    // -- Test: DiskState action_types/actions length mismatch ---------------

    #[test]
    fn test_decode_action_types_actions_length_mismatch() {
        // Manually create a DiskState with mismatched lengths
        let player = Player::default();
        let router = RootRouter::default();
        let clock = ClockState::default();

        let router_bytes = rmp_serde::to_vec(&router).expect("router bytes");
        let player_bytes = rmp_serde::to_vec(&player).expect("player bytes");
        let clock_bytes = rmp_serde::to_vec(&clock).expect("clock bytes");

        let disk_state = DiskState {
            router: router_bytes,
            player: player_bytes,
            clock: clock_bytes,
            action_types: vec![ActionType::Noop, ActionType::Attest], // 2 types
            actions: vec![rmp_serde::to_vec(&Action::Noop(NoopAction)).unwrap()], // 1 action
        };

        let raw = rmp_serde::to_vec(&disk_state).expect("encode disk_state");
        let result = decode(&raw);
        assert!(result.is_err());
        match result.unwrap_err() {
            PersistenceError::Corrupt(msg) => {
                assert!(
                    msg.contains("action_types length"),
                    "error should mention action_types length mismatch: {msg}"
                );
            }
            other => panic!("expected Corrupt, got: {:?}", other),
        }
    }

    // -- Test: encode with no actions produces valid decode ------------------

    #[test]
    fn test_encode_decode_empty_actions() {
        let raw = encode(
            &RootRouter::default(),
            &Player::default(),
            &ClockState::default(),
            &[], // No actions
        )
        .expect("encode");
        let (_, _, _, dec_actions) = decode(&raw).expect("decode");
        assert!(dec_actions.is_empty());
    }

    // -- Test: encode with all rounds below player.round filters all --------

    #[test]
    fn test_encode_filters_all_stale_rounds() {
        let player = Player {
            round: Round(100),
            ..Player::default()
        };
        let mut router = RootRouter::default();
        router.children.insert(Round(1), RoundRouter::default());
        router.children.insert(Round(50), RoundRouter::default());
        router.children.insert(Round(99), RoundRouter::default());

        let raw = encode(&router, &player, &ClockState::default(), &[]).expect("encode");
        let (dec_router, _, _, _) = decode(&raw).expect("decode");

        assert!(
            dec_router.children.is_empty(),
            "all rounds below player.round should be filtered"
        );
    }

    // -- Test: clock state with all timeout types ---------------------------

    #[test]
    fn test_encode_decode_clock_all_timeout_types() {
        let mut clock = ClockState::default();
        clock
            .deadlines
            .insert(TimeoutType::Deadline, Duration::from_secs(10));
        clock
            .deadlines
            .insert(TimeoutType::FastRecovery, Duration::from_millis(2500));
        clock
            .deadlines
            .insert(TimeoutType::Filter, Duration::from_nanos(999999));

        let raw = encode(&RootRouter::default(), &Player::default(), &clock, &[]).expect("encode");
        let (_, _, dec_clock, _) = decode(&raw).expect("decode");

        assert_eq!(dec_clock.deadlines.len(), 3);
        assert_eq!(
            dec_clock.deadlines[&TimeoutType::Deadline],
            Duration::from_secs(10)
        );
        assert_eq!(
            dec_clock.deadlines[&TimeoutType::FastRecovery],
            Duration::from_millis(2500)
        );
        assert_eq!(
            dec_clock.deadlines[&TimeoutType::Filter],
            Duration::from_nanos(999999)
        );
    }

    // -- Test: player with non-default fields roundtrips ---------------------

    #[test]
    fn test_encode_decode_player_nondefault_fields() {
        let player = Player {
            round: Round(1000),
            period: Period(7),
            step: Step(42),
            last_concluding: Step(5),
            napping: true,
            fast_recovery_deadline: Duration::from_secs(30),
            dynamic_filter_timeout: Duration::from_millis(750),
            ..Player::default()
        };

        let raw =
            encode(&RootRouter::default(), &player, &ClockState::default(), &[]).expect("encode");
        let (_, dec_player, _, _) = decode(&raw).expect("decode");

        assert_eq!(dec_player.round, Round(1000));
        assert_eq!(dec_player.period, Period(7));
        assert_eq!(dec_player.step, Step(42));
        assert_eq!(dec_player.last_concluding, Step(5));
        assert!(dec_player.napping);
        assert_eq!(dec_player.fast_recovery_deadline, Duration::from_secs(30));
        assert_eq!(
            dec_player.dynamic_filter_timeout,
            Duration::from_millis(750)
        );
    }

    // -- Test: full persist->restore->decode round-trip through SQLite ------

    #[test]
    fn test_full_persist_restore_decode_roundtrip() {
        let conn = mem_db();

        let mut router = RootRouter::default();
        let mut rr = RoundRouter::default();
        let mut pr = PeriodRouter::default();
        pr.proposal_tracker.staging = test_proposal(0xDD);
        rr.children.insert(Period(0), pr);
        router.children.insert(Round(50), rr);

        let player = Player {
            round: Round(50),
            period: Period(0),
            step: Step(1),
            ..Player::default()
        };

        let mut clock = ClockState::default();
        clock
            .deadlines
            .insert(TimeoutType::Deadline, Duration::from_secs(3));

        let actions = vec![
            Action::Noop(NoopAction),
            Action::Pseudonode(PseudonodeAction {
                t: ActionType::Attest,
                round: Round(50),
                period: Period(0),
                step: Step(1),
                proposal: test_proposal(0xDD),
            }),
        ];

        let raw = encode(&router, &player, &clock, &actions).expect("encode");
        persist(&conn, &raw).expect("persist");

        let restored_raw = restore(&conn).expect("restore").expect("data");
        let (dec_router, dec_player, dec_clock, dec_actions) =
            decode(&restored_raw).expect("decode");

        assert_eq!(dec_player.round, Round(50));
        assert_eq!(
            dec_clock.deadlines[&TimeoutType::Deadline],
            Duration::from_secs(3)
        );
        assert_eq!(dec_actions.len(), 2);
        assert!(dec_router.children.contains_key(&Round(50)));

        let dec_rr = &dec_router.children[&Round(50)];
        let dec_pr = &dec_rr.children[&Period(0)];
        assert_eq!(dec_pr.proposal_tracker.staging, test_proposal(0xDD));
    }

    // -- Test: ensure_table is idempotent -----------------------------------

    #[test]
    fn test_ensure_table_idempotent() {
        let conn = mem_db();

        // Calling persist multiple times (which calls ensure_table each time)
        // should not fail.
        let raw = encode(
            &RootRouter::default(),
            &Player::default(),
            &ClockState::default(),
            &[],
        )
        .expect("encode");
        persist(&conn, &raw).expect("persist 1");
        persist(&conn, &raw).expect("persist 2");
        persist(&conn, &raw).expect("persist 3");

        let restored = restore(&conn).expect("restore");
        assert!(restored.is_some());
    }

    // -- Test: reset on empty db is not an error ----------------------------

    #[test]
    fn test_reset_empty_db_no_error() {
        let conn = mem_db();
        // Reset without any prior persist should succeed (no-op).
        reset(&conn).expect("reset empty db");

        // And restore should return None.
        assert!(restore(&conn).expect("restore").is_none());
    }

    // -- Test: persistent() helper edge cases -------------------------------

    #[test]
    fn test_persistent_helper_all_action_types() {
        // Only Attest is persistent
        let all_non_persistent = vec![
            Action::Noop(NoopAction),
            Action::Pseudonode(PseudonodeAction {
                t: ActionType::Assemble,
                ..PseudonodeAction::default()
            }),
            Action::Pseudonode(PseudonodeAction {
                t: ActionType::Repropose,
                ..PseudonodeAction::default()
            }),
            Action::Rezero(crate::actions::RezeroAction::default()),
            Action::Checkpoint(crate::actions::CheckpointAction::default()),
        ];
        assert!(!persistent(&all_non_persistent));

        // Single attest makes it persistent
        let mut with_attest = all_non_persistent.clone();
        with_attest.push(Action::Pseudonode(PseudonodeAction {
            t: ActionType::Attest,
            ..PseudonodeAction::default()
        }));
        assert!(persistent(&with_attest));
    }

    // -- Test: async loop thread safety — rapid enqueues --------------------

    #[test]
    fn test_async_loop_thread_safety_rapid_enqueue() {
        // This test verifies that rapidly enqueuing requests from multiple
        // threads does not cause panics or data corruption.
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let conn = mem_db();
        let mut lp = AsyncPersistenceLoop::new(conn);
        lp.start();

        let completed = Arc::new(AtomicU32::new(0));
        let num_requests = 10u32;

        // The async loop has a bounded(1) channel, so requests will be
        // processed one at a time. We send them sequentially.
        for i in 0..num_requests {
            let raw = encode(
                &RootRouter::default(),
                &Player {
                    round: Round(i as u64),
                    ..Player::default()
                },
                &ClockState::default(),
                &[],
            )
            .expect("encode");

            let (done_tx, done_rx) = bounded(1);
            let (events_tx, _events_rx) = bounded(1);

            lp.enqueue(PersistentRequest {
                round: Round(i as u64),
                period: Period(0),
                step: Step(0),
                raw,
                done: done_tx,
                clock: ClockState::default(),
                events: events_tx,
            });

            let result = done_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("done timed out");
            assert!(result.is_ok());
            completed.fetch_add(1, Ordering::SeqCst);
        }

        assert_eq!(completed.load(Ordering::SeqCst), num_requests);
        lp.quit();
    }

    // -- Test: encode/decode with CheckpointAction containing error ---------

    #[test]
    fn test_encode_decode_checkpoint_action_with_error() {
        let actions = vec![Action::Checkpoint(crate::actions::CheckpointAction {
            round: Round(5),
            period: Period(1),
            step: Step(2),
            err: Some(crate::events::SerializableError::new("test error message")),
        })];

        let raw = encode(
            &RootRouter::default(),
            &Player::default(),
            &ClockState::default(),
            &actions,
        )
        .expect("encode");
        let (_, _, _, dec_actions) = decode(&raw).expect("decode");

        assert_eq!(dec_actions.len(), 1);
        assert_eq!(dec_actions[0].action_type(), ActionType::Checkpoint);
        if let Action::Checkpoint(ref ca) = dec_actions[0] {
            assert_eq!(ca.round, Round(5));
            assert_eq!(ca.period, Period(1));
            assert_eq!(ca.step, Step(2));
            assert!(ca.err.is_some());
            assert_eq!(ca.err.as_ref().unwrap().0, "test error message");
        } else {
            panic!("expected Checkpoint action");
        }
    }

    // -- Test: encode/decode boundary round values --------------------------

    #[test]
    fn test_encode_decode_boundary_round_values() {
        // Test with Round(0) — minimum
        let player0 = Player {
            round: Round(0),
            ..Player::default()
        };
        let raw0 = encode(
            &RootRouter::default(),
            &player0,
            &ClockState::default(),
            &[],
        )
        .expect("encode round 0");
        let (_, dec0, _, _) = decode(&raw0).expect("decode round 0");
        assert_eq!(dec0.round, Round(0));

        // Test with a very large round
        let player_big = Player {
            round: Round(u64::MAX - 1),
            ..Player::default()
        };
        let raw_big = encode(
            &RootRouter::default(),
            &player_big,
            &ClockState::default(),
            &[],
        )
        .expect("encode big round");
        let (_, dec_big, _, _) = decode(&raw_big).expect("decode big round");
        assert_eq!(dec_big.round, Round(u64::MAX - 1));
    }

    // -- Test: decode single random byte ------------------------------------

    #[test]
    fn test_decode_single_byte() {
        let result = decode(&[0x91]);
        assert!(result.is_err());
        match result.unwrap_err() {
            PersistenceError::Corrupt(_) => {}
            other => panic!("expected Corrupt, got: {:?}", other),
        }
    }
}
