use anyhow::Context;
use clap::Parser;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use carapace::cli::{Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let verbose = match &cli.command {
        Command::Render(a) => a.verbose,
        Command::Serve(a) => a.verbose,
    };

    let filter = if verbose {
        EnvFilter::new("carapace=debug,warn")
    } else {
        EnvFilter::new("carapace=info,warn")
    };

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false).compact())
        .with(filter)
        .init();

    match cli.command {
        Command::Render(args) => {
            carapace::run(&args)
                .await
                .context("render pipeline failed")?;
        }
        Command::Serve(args) => {
            carapace::api::serve(args)
                .await
                .context("API server error")?;
        }
    }

    Ok(())
}
