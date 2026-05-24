//! Localnet lifecycle management (TASK-184).
//!
//! `Localnet::bring_up()` is idempotent: if a localnet is already responding
//! on the well-known port (4001), the harness reuses it and does NOT tear it
//! down on `Drop`. If no localnet is up, the harness drives
//! `docker compose up -d algod-go` directly (matching the `make localnet-up`
//! target's content but skipping the Makefile's unbounded shell `until` loop)
//! and `Drop` runs `docker compose down -v`. All health-waiting happens in
//! Rust with explicit timeouts — no risk of an orphaned shell loop hanging
//! the test.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use algo_error::{AlgoError, Result};
use algo_rest_client::{AlgodClient, ClientConfig};

/// Localnet's algod REST endpoint (matches `Makefile` ALGOD_URL).
pub const REST_URL: &str = "http://localhost:4001";

/// Localnet's algod REST token (matches `docker/docker-compose.yml`).
pub const REST_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Upper bound on `docker compose up -d`. With `-d` the command exits as soon
/// as the container is started (NOT healthy), so this is just to catch the
/// pathological case where the docker daemon itself hangs.
const COMPOSE_UP_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for algod's REST surface to start responding after
/// `docker compose up -d` returns. Generous because dev-mode algod needs to
/// produce a genesis block before `/v2/status` is reachable.
const REST_HEALTH_TIMEOUT: Duration = Duration::from_secs(60);

/// Container name (matches `docker/docker-compose.yml`).
pub(crate) const ALGOD_CONTAINER: &str = "algod-go";

/// A live (or borrowed) algod-go localnet plus a configured REST client.
pub struct Localnet {
    client: AlgodClient,
    /// True if this instance brought the localnet up itself; controls whether
    /// `Drop` tears it down. When `false`, an existing localnet was reused and
    /// is left running for the next test (or for a developer's session).
    owned: bool,
}

impl Localnet {
    /// Bring up (or detect) the localnet and wait until algod responds.
    ///
    /// Idempotent: if `/v2/status` is already reachable, the existing
    /// localnet is reused and `Drop` will leave it running.
    pub async fn bring_up() -> Result<Self> {
        let client = AlgodClient::with_config(
            REST_URL,
            REST_TOKEN,
            ClientConfig {
                // Short timeouts during health-wait so a slow startup doesn't
                // hang the test for the default 30s per attempt.
                timeout: Duration::from_secs(3),
                long_poll_timeout: Duration::from_secs(30),
                max_retries: 0,
                initial_backoff: Duration::from_millis(100),
            },
        );

        // Probe first — reuse a running localnet if present.
        if status_ok(&client).await {
            return Ok(Self {
                client: full_client(),
                owned: false,
            });
        }

        // Otherwise start algod-go via docker compose directly. We deliberately
        // do NOT use `make localnet-up` here — the Makefile target wraps the
        // compose invocation in an unbounded `until docker inspect ... healthy`
        // shell loop, and killing that loop reliably across process boundaries
        // is more work than just driving compose ourselves.
        run_compose(&["up", "-d", "algod-go"], COMPOSE_UP_TIMEOUT)?;

        // Health-wait for algod's REST surface. `docker compose up -d` returns
        // as soon as the container is started, not when it's healthy.
        let deadline = Instant::now() + REST_HEALTH_TIMEOUT;
        while Instant::now() < deadline {
            if status_ok(&client).await {
                return Ok(Self {
                    client: full_client(),
                    owned: true,
                });
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        Err(AlgoError::Network {
            message: format!(
                "localnet did not become REST-responsive within {}s after `docker compose up -d algod-go`",
                REST_HEALTH_TIMEOUT.as_secs()
            ),
        })
    }

    /// REST base URL the localnet is listening on.
    pub fn rest_url(&self) -> &str {
        REST_URL
    }

    /// API token (matches docker-compose's `TOKEN` env var).
    pub fn rest_token(&self) -> &str {
        REST_TOKEN
    }

    /// A long-lived REST client with default timeouts. Reused across tests
    /// to avoid stacking up connections.
    pub fn client(&self) -> &AlgodClient {
        &self.client
    }

    /// True if this instance brought up the localnet (and will tear it down
    /// on `Drop`). Useful for tests that want to assert lifecycle semantics.
    pub fn owned(&self) -> bool {
        self.owned
    }
}

impl Drop for Localnet {
    fn drop(&mut self) {
        if !self.owned {
            return;
        }
        // Best-effort teardown — log on failure but don't panic from Drop.
        // `down -v` matches the `make localnet-down` target.
        if let Err(e) = run_compose(&["down", "-v"], COMPOSE_UP_TIMEOUT) {
            eprintln!("warning: localnet teardown failed: {e}");
        }
    }
}

/// Path to the workspace's docker-compose.yml, resolved at compile time from
/// the algokey-rust crate's manifest dir. Lets the harness run from any CWD
/// (cargo sets it to the package dir during tests).
fn compose_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../docker/docker-compose.yml")
}

/// Run `docker compose -f <compose_file> <args>` with the given wall-clock
/// budget. The single subprocess (`docker`) is well-behaved on kill — no
/// runaway shell loops to worry about, unlike `make localnet-up`.
fn run_compose(args: &[&str], timeout: Duration) -> Result<()> {
    let compose = compose_file();
    let mut child = Command::new("docker")
        .arg("compose")
        .arg("-f")
        .arg(&compose)
        .args(args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| AlgoError::Network {
            message: format!(
                "failed to spawn `docker compose -f {} {}`: {e}",
                compose.display(),
                args.join(" ")
            ),
        })?;

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err(AlgoError::Network {
                        message: format!(
                            "`docker compose {}` exited with status {status}",
                            args.join(" ")
                        ),
                    });
                }
                return Ok(());
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(AlgoError::Network {
                        message: format!(
                            "`docker compose {}` did not complete within {}s — killed",
                            args.join(" "),
                            timeout.as_secs()
                        ),
                    });
                }
                // Synchronous sleep — Drop also calls this from outside an
                // async context, so we can't `tokio::time::sleep` here.
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                return Err(AlgoError::Network {
                    message: format!("error polling docker compose: {e}"),
                });
            }
        }
    }
}

/// Probe `/v2/status` and return true on success. Any error (connection
/// refused, timeout, HTTP error, parse error) is treated as "not up".
async fn status_ok(client: &AlgodClient) -> bool {
    use algo_rest_client::BlockSource;
    client.get_status().await.is_ok()
}

/// Build a client with the production default config (longer timeouts,
/// retries enabled) — used for the lifetime of the harness once the
/// localnet is confirmed up.
fn full_client() -> AlgodClient {
    AlgodClient::new(REST_URL, REST_TOKEN)
}
