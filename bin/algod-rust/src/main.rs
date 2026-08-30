// Copyright (C) 2019-2026 Algorand Foundation Ltd.
// Modifications Copyright (C) 2026 Algod DAO
// This file is part of algod-rust, a modified work based on go-algorand
// (https://github.com/algorand/go-algorand).
//
// algod-rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// algod-rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

mod cli;
mod commands;
mod config;
mod dev_producer;
mod node_interface_impl;

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
            CatchpointAction::Export {
                db,
                output,
                round,
                blocks_round,
                block_digest,
                no_online_data,
                no_gzip,
            } => {
                commands::catchpoint::run_export(
                    &db,
                    &output,
                    round,
                    blocks_round,
                    block_digest.as_deref(),
                    no_online_data,
                    no_gzip,
                )
                .await?;
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
            genesis_json,
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
                genesis_json.as_deref(),
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
        Commands::Autopsy { cadaver, json } => {
            let format = if json {
                commands::autopsy::AutopsyFormat::Json
            } else {
                commands::autopsy::AutopsyFormat::Text
            };
            commands::autopsy::run(&cadaver, format)?;
        }
        Commands::Participate {
            ledger_path,
            genesis_id,
            network,
            peers,
            partkey_path,
            import_partkey,
            partkey_dir,
            genesis_json,
            listen_address,
            relay_messages,
            genesis_hash,
            rest_listen,
            data_dir,
            genesis_path,
            config,
            enable_p2p,
            enable_p2p_hybrid_mode,
            p2p_persist_peer_id,
            p2p_bootstrap_peers,
            p2p_listen_address,
        } => {
            let file_config = crate::config::AlgodRustConfig::load(config.as_deref())?;
            // Load `<data-dir>/config.json` (go-algorand `config.Local`
            // equivalent — issue #754/epic #745). This is currently
            // observational only: the loaded fields aren't yet wired into
            // runtime behavior (e.g. `algo-network`'s connection limits
            // still come from `WsNetworkConfig`'s hardcoded defaults) —
            // that wiring, and its exact precedence against the
            // `--config` TOML file and CLI flags above, is each
            // per-area follow-up issue's own call to make (#748 for
            // networking, etc.). Loading it here now proves the mechanism
            // works end-to-end against a real data directory and keeps
            // operators informed of what a dropped-in `config.json` would
            // resolve to once that wiring lands.
            if let Some(dir) = data_dir.as_deref() {
                match algo_config::Local::load_from_data_dir(dir) {
                    Ok(node_config) => {
                        tracing::debug!(
                            version = node_config.version,
                            max_connections_per_ip = node_config.max_connections_per_ip,
                            incoming_connections_limit = node_config.incoming_connections_limit,
                            enable_p2p = node_config.enable_p2p,
                            enable_p2p_hybrid_mode = node_config.enable_p2p_hybrid_mode,
                            p2p_persist_peer_id = node_config.p2p_persist_peer_id,
                            "loaded config.json (not yet wired into runtime behavior)"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "failed to load config.json; continuing without it"
                        );
                    }
                }
            }
            let rest_opts = commands::participate::RestOptions {
                listen: rest_listen,
                data_dir,
                genesis_path,
                file_rest: file_config.rest().cloned(),
            };
            let p2p_opts = commands::p2p_transport::P2pOptions {
                enable_p2p,
                enable_p2p_hybrid_mode,
                p2p_persist_peer_id,
                p2p_bootstrap_peers,
                p2p_listen_address,
                file_p2p: file_config.p2p().cloned(),
            };
            commands::participate::run(
                &ledger_path,
                genesis_id.as_deref(),
                &network,
                &peers,
                &partkey_path,
                &import_partkey,
                &partkey_dir,
                genesis_json.as_deref(),
                listen_address.as_deref(),
                relay_messages,
                genesis_hash.as_deref(),
                rest_opts,
                p2p_opts,
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
        Commands::Node { cmd } => {
            commands::node::run(cmd).await?;
        }
        Commands::Loadgen { cmd } => match cmd {
            cli::LoadgenCommands::GenAccounts { count, out } => {
                commands::loadgen::gen_accounts(count, &out)?;
            }
            cli::LoadgenCommands::Run {
                algod_urls,
                token,
                keys,
                target_tps,
                duration_secs,
                ramp_secs,
                group_size,
                concurrency,
                fee_multiplier,
                confirm_sample,
                confirm_timeout_secs,
                output,
            } => {
                commands::loadgen::run(commands::loadgen::LoadgenConfig {
                    endpoints: algod_urls,
                    token,
                    keys,
                    target_tps,
                    duration_secs,
                    ramp_secs,
                    group_size,
                    concurrency,
                    fee_multiplier,
                    confirm_sample,
                    confirm_timeout_secs,
                    output,
                })
                .await?;
            }
        },
    }

    Ok(())
}
