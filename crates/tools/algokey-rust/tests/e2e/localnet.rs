//! Localnet lifecycle management (TASK-184).
//!
//! `Localnet::bring_up()` is idempotent: if a localnet is already responding
//! on the well-known port (4001), the harness reuses it and does NOT tear it
//! down on `Drop`. If no localnet is up, the harness shells out to
//! `make localnet-up` and `Drop` runs `make localnet-down`.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use algo_error::{AlgoError, Result};
use algo_rest_client::{AlgodClient, ClientConfig};

/// Localnet's algod REST endpoint (matches `Makefile` ALGOD_URL).
pub const REST_URL: &str = "http://localhost:4001";

/// Localnet's algod REST token (matches `docker/docker-compose.yml`).
pub const REST_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Upper bound on `make localnet-up` itself. The Makefile target runs an
/// unbounded `until docker inspect ... healthy` loop, so we spawn it as a
/// child and kill it if it doesn't complete within this budget.
const MAKE_TIMEOUT: Duration = Duration::from_secs(90);

/// Additional budget for the post-Make REST health-wait loop (algod's HTTP
/// surface may need a beat after docker reports healthy). Small — if make
/// returned but REST never answers, something is wrong.
const REST_HEALTH_TIMEOUT: Duration = Duration::from_secs(15);

/// Container name (matches `docker/docker-compose.yml`).
pub(crate) const ALGOD_CONTAINER: &str = "algod-go";

/// A live (or borrowed) algod-go localnet plus a configured REST client.
pub struct Localnet {
    client: AlgodClient,
    /// True if this instance ran `make localnet-up`; controls whether `Drop`
    /// tears the localnet down. When `false`, an existing localnet was reused
    /// and is left running for the next test (or for a developer's session).
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

        // Otherwise shell out to the Makefile, with a hard upper bound on
        // wall-clock so a stuck docker health-check can't hang the test.
        run_make_localnet_up().await?;

        // Post-make REST health-wait — the Makefile already waited on docker
        // health, but algod's HTTP surface may need a beat after the container
        // reports healthy.
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
                "localnet did not become REST-responsive within {}s after `make localnet-up`",
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
        let result = Command::new("make").arg("localnet-down").status();
        if let Err(e) = result {
            eprintln!("warning: `make localnet-down` failed to spawn: {e}");
        } else if let Ok(status) = result {
            if !status.success() {
                eprintln!("warning: `make localnet-down` exited with status {status}");
            }
        }
    }
}

/// Spawn `make localnet-up` and wait for it to finish, killing it if it
/// exceeds [`MAKE_TIMEOUT`]. The Makefile's `until docker inspect ... healthy`
/// loop has no internal timeout, so without this guard a stuck docker health
/// check would hang the test indefinitely.
async fn run_make_localnet_up() -> Result<()> {
    let mut child = Command::new("make")
        .arg("localnet-up")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| AlgoError::Network {
            message: format!("failed to spawn `make localnet-up`: {e}"),
        })?;

    let deadline = Instant::now() + MAKE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err(AlgoError::Network {
                        message: format!("`make localnet-up` exited with status {status}"),
                    });
                }
                return Ok(());
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    // Best-effort kill; don't shadow the original timeout error.
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(AlgoError::Network {
                        message: format!(
                            "`make localnet-up` did not complete within {}s — killed",
                            MAKE_TIMEOUT.as_secs()
                        ),
                    });
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => {
                return Err(AlgoError::Network {
                    message: format!("error polling `make localnet-up`: {e}"),
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
