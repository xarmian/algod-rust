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
