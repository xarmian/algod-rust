mod cli;
mod commands;

use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging (JSON in prod, pretty for dev).
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Capture {
            algod_url,
            algod_token,
            start,
            end,
            out,
        } => {
            commands::capture::run(&algod_url, &algod_token, start, end, &out).await?;
        }
        Commands::Validate {
            algod_url,
            algod_token,
            start,
            end,
            fail_fast,
            report,
        } => {
            commands::validate::run(
                &algod_url,
                &algod_token,
                start,
                end,
                fail_fast,
                report.as_deref(),
            )
            .await?;
        }
        Commands::Replay {
            network,
            algod_url,
            algod_token,
            start,
            end,
            fail_fast,
            report,
            stateful,
            genesis,
            compare,
            compare_url,
            compare_token,
            sample_rate,
            db,
            trie,
            compare_trie_db,
            avm_execute,
        } => {
            let (resolved_url, resolved_token, net_name) = match network.as_str() {
                "mainnet" => (
                    "https://mainnet-api.4160.nodely.dev".to_string(),
                    String::new(),
                    "mainnet",
                ),
                "testnet" => (
                    "https://testnet-api.4160.nodely.dev".to_string(),
                    String::new(),
                    "testnet",
                ),
                "custom" => {
                    let url = algod_url.ok_or_else(|| {
                        anyhow::anyhow!("--algod-url is required when --network=custom")
                    })?;
                    (url, algod_token, "custom")
                }
                other => {
                    anyhow::bail!(
                        "unknown network '{}': use mainnet, testnet, or custom",
                        other
                    );
                }
            };

            if stateful {
                commands::replay::run_stateful(
                    net_name,
                    &resolved_url,
                    &resolved_token,
                    start,
                    end,
                    fail_fast,
                    report.as_deref(),
                    genesis.as_deref(),
                    compare,
                    &compare_url,
                    &compare_token,
                    sample_rate,
                    &db,
                    trie,
                    compare_trie_db.as_deref(),
                    avm_execute,
                )
                .await?;
            } else {
                commands::replay::run(
                    net_name,
                    &resolved_url,
                    &resolved_token,
                    start,
                    end,
                    fail_fast,
                    report.as_deref(),
                )
                .await?;
            }
        }
        Commands::Follow {
            algod_url,
            algod_token,
            report_dir,
        } => {
            commands::follow::run(&algod_url, &algod_token, report_dir.as_deref()).await?;
        }
    }

    Ok(())
}
