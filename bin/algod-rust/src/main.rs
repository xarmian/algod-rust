mod cli;
mod commands;

use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

use cli::{BenchAction, CatchpointAction, Cli, Commands};

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
            gossip,
            genesis_id,
            relay_addr,
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
                    gossip,
                    genesis_id.as_deref(),
                    &relay_addr,
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
        Commands::Bench { action } => match action {
            BenchAction::Replay {
                algod_url,
                token,
                start_round,
                count,
                output,
                quick,
            } => {
                let effective_count = if quick { 100 } else { count };
                commands::bench::run_replay(
                    &algod_url,
                    &token,
                    start_round,
                    effective_count,
                    &output,
                )
                .await?;
            }
            BenchAction::Decode {
                algod_url,
                token,
                start_round,
                count,
                output,
                quick,
            } => {
                let effective_count = if quick { 100 } else { count };
                commands::bench::run_decode(
                    &algod_url,
                    &token,
                    start_round,
                    effective_count,
                    &output,
                )
                .await?;
            }
            BenchAction::Compare {
                rust_json,
                go_json,
                markdown,
            } => {
                commands::bench::run_compare(&rust_json, &go_json, markdown)?;
            }
        },
        Commands::Relay {
            bind_address,
            ledger_path,
            genesis_id,
            network,
            peers,
            incoming_limit,
            max_per_ip,
            rate_limit,
            broadcast_limit,
            tls_cert,
            tls_key,
            mem_cap_mb,
        } => {
            commands::relay::run(
                &bind_address,
                genesis_id.as_deref().unwrap_or(""),
                &network,
                &peers,
                incoming_limit,
                max_per_ip,
                rate_limit,
                broadcast_limit,
                tls_cert.as_deref(),
                tls_key.as_deref(),
                mem_cap_mb,
                &ledger_path,
            )
            .await?;
        }
        Commands::Observe {
            network,
            relay_addr,
            genesis_id,
            dns_bootstrap,
        } => {
            commands::observe::run(
                &network,
                &relay_addr,
                genesis_id.as_deref(),
                dns_bootstrap.as_deref(),
            )
            .await?;
        }
        Commands::CaptureWire {
            relay_addr,
            output_dir,
            count,
            duration,
            genesis_id,
        } => {
            commands::capture_wire::run(
                &relay_addr,
                &output_dir,
                count,
                duration,
                genesis_id.as_deref(),
            )
            .await?;
        }
        Commands::Participate {
            ledger_path,
            genesis_id,
            network,
            peers,
            partkey_path,
            listen_address,
            genesis_hash,
        } => {
            commands::participate::run(
                &ledger_path,
                genesis_id.as_deref(),
                &network,
                &peers,
                &partkey_path,
                listen_address.as_deref(),
                genesis_hash.as_deref(),
            )
            .await?;
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
