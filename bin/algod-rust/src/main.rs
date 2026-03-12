mod cli;
mod commands;

use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

use cli::{CatchpointAction, Cli, Commands};

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
            let (resolved_url, resolved_token, net_name) =
                commands::resolve_network(&network, algod_url.as_deref(), &algod_token)?;

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
        Commands::Sync {
            network,
            algod_url,
            algod_token,
            genesis,
            db,
            start,
            end,
            concurrency,
            avm_execute,
            fail_fast,
            trie,
            catchpoint,
            catchpoint_auto,
            follow,
            compare,
            trie_path,
        } => {
            let (resolved_url, resolved_token, net_name) =
                commands::resolve_network(&network, algod_url.as_deref(), &algod_token)?;

            if catchpoint.is_some() || catchpoint_auto {
                // Catchpoint sync path.
                commands::catchpoint_sync::run(
                    net_name,
                    &resolved_url,
                    &resolved_token,
                    &db,
                    catchpoint.as_deref(),
                    catchpoint_auto,
                    concurrency,
                    follow,
                    compare,
                    trie_path.as_deref(),
                    avm_execute,
                    fail_fast,
                    end,
                )
                .await?;
            } else {
                // Genesis-based sync path.
                commands::sync::run(
                    net_name,
                    &resolved_url,
                    &resolved_token,
                    genesis.as_deref(),
                    &db,
                    start,
                    end,
                    concurrency,
                    avm_execute,
                    fail_fast,
                    trie,
                )
                .await?;
            }
        }
        Commands::Catchpoint { action } => match action {
            CatchpointAction::Import {
                file,
                db,
                label,
                reward_unit,
                no_verify,
            } => {
                commands::catchpoint::run_import(
                    &file,
                    &db,
                    label.as_deref(),
                    reward_unit,
                    !no_verify,
                )
                .await?;
            }
            CatchpointAction::Verify { db, file } => {
                commands::catchpoint::run_verify(&db, file.as_deref()).await?;
            }
            CatchpointAction::Download {
                url,
                token,
                genesis_id,
                round,
                output,
            } => {
                commands::catchpoint::run_download(&url, &token, &genesis_id, round, &output)
                    .await?;
            }
        },
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
