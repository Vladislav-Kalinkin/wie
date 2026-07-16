//! `wie-cli` — WIE PE64 userspace emulator CLI.

mod commands;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "wie-cli")]
#[command(about = "WIE — PE64 userspace emulator")]
#[command(long_about = "\
Generic PE64 userspace emulator CLI.\n\
\n\
Primary gate: run-micro (freestanding micro-PEs).\n\
CPU backend: WIE_CPU=jit (default) | iced.\
")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    // --- PE inspection -------------------------------------------------------
    Inspect {
        path: PathBuf,
    },
    Sections {
        path: PathBuf,
    },
    Imports {
        path: PathBuf,
        #[arg(long)]
        find: Option<String>,
    },
    Image {
        path: PathBuf,
    },
    WinapiMap {
        path: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    // --- Run -----------------------------------------------------------------
    RunMicro {
        path: PathBuf,
        #[arg(long, default_value_t = 256)]
        max_api: usize,

        /// Expected ExitProcess code.
        #[arg(long, default_value_t = 0)]
        expect_code: u32,

        /// Bottle root: guest `C:\…` maps to `{root}/drive_c/…` (also `WIE_ROOT`).
        #[arg(long)]
        root: Option<PathBuf>,
    },
    Run {
        path: PathBuf,
        #[arg(long, default_value_t = 3400)]
        max_api: usize,
    },
    EntryTrace {
        path: PathBuf,
        #[arg(long, default_value_t = 20)]
        max_api: usize,
    },
}

fn main() -> Result<()> {
    let env_filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".to_owned());
    if let Err(error) = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .try_init()
    {
        bail!("failed to initialize tracing subscriber: {error}");
    }

    let cli = Cli::parse();

    match cli.command {
        Command::Inspect { path } => commands::inspect(&path)?,
        Command::Sections { path } => commands::sections(&path)?,
        Command::Imports { path, find } => commands::imports(&path, find.as_deref())?,
        Command::Image { path } => commands::image(&path)?,
        Command::WinapiMap { path, out } => commands::winapi_map(&path, out.as_deref())?,
        Command::RunMicro {
            path,
            max_api,
            expect_code,
            root,
        } => {
            commands::run_micro(&path, max_api, expect_code, root.as_deref())?;
        }
        Command::Run { path, max_api } => {
            commands::run_until_yield(&path, max_api)?;
        }
        Command::EntryTrace { path, max_api } => {
            commands::entry_trace(&path, max_api)?;
        }
    }

    Ok(())
}
