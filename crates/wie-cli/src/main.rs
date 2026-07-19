//! `wie-cli` — WIE PE64 userspace emulator CLI.

mod commands;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "wie-cli")]
#[command(about = "WIE — PE64 userspace emulator")]
#[command(long_about = "\
Generic PE64 userspace emulator CLI.\n\
\n\
Fundamental commands: inspect | run | trace.\n\
CPU backend: WIE_CPU=jit (default) | iced.\n\
Guest memory: mmap arenas only (soft translate).\
")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// PE static inspection (metadata, sections, imports, image, WinAPI map).
    Inspect {
        path: PathBuf,

        /// List PE sections.
        #[arg(long)]
        sections: bool,

        /// List import address table entries.
        #[arg(long)]
        imports: bool,

        /// Filter imports by substring (implies --imports).
        #[arg(long)]
        find: Option<String>,

        /// Print loaded-image summary (Windows-loader-like).
        #[arg(long)]
        image: bool,

        /// Print WinAPI import coverage map.
        #[arg(long)]
        winapi_map: bool,

        /// Write WinAPI map to this path instead of stdout (implies --winapi-map).
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// Run a PE until ExitProcess (micro gate) or until the persistent loop yields.
    #[command(alias = "run-micro")]
    Run {
        path: PathBuf,

        /// Cap host API stops (micro default 256; persistent default 3400).
        #[arg(long)]
        max_api: Option<usize>,

        /// Expected ExitProcess code (micro mode only; default 0).
        #[arg(long, default_value_t = 0)]
        expect_code: u32,

        /// Bottle root: guest `C:\…` maps to `{root}/drive_c/…` (also `WIE_ROOT`).
        #[arg(long)]
        root: Option<PathBuf>,

        /// Host root for guest `D:\…` bridge (also `WIE_DRIVE_D`; use `auto` for host cwd).
        #[arg(long)]
        drive_d: Option<PathBuf>,

        /// Host file whose bytes are injected as guest console stdin.
        #[arg(long)]
        stdin: Option<PathBuf>,

        /// Persistent run loop (old `run`): yield on idle instead of ExitProcess gate.
        #[arg(long)]
        persistent: bool,

        /// Guest argv after the module name (`wie-cli run pe -- -n 3 -m hi`).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        guest_args: Vec<String>,
    },

    /// Controlled entry-point API trace (first N host stops).
    #[command(alias = "entry-trace")]
    Trace {
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
        Command::Inspect {
            path,
            sections,
            imports,
            find,
            image,
            winapi_map,
            out,
        } => {
            let want_imports = imports || find.is_some();
            let want_winapi = winapi_map || out.is_some();
            let any_detail = sections || want_imports || image || want_winapi;
            if !any_detail {
                commands::inspect(&path)?;
            } else {
                // Always print core metadata first when any detail flag is set.
                commands::inspect(&path)?;
                if sections {
                    println!();
                    commands::sections(&path)?;
                }
                if want_imports {
                    println!();
                    commands::imports(&path, find.as_deref())?;
                }
                if image {
                    println!();
                    commands::image(&path)?;
                }
                if want_winapi {
                    println!();
                    commands::winapi_map(&path, out.as_deref())?;
                }
            }
        }
        Command::Run {
            path,
            max_api,
            expect_code,
            root,
            drive_d,
            stdin,
            persistent,
            guest_args,
        } => {
            if persistent {
                let max = max_api.unwrap_or(3400);
                if !guest_args.is_empty() {
                    bail!("guest argv is only supported in micro mode (omit --persistent)");
                }
                if root.is_some() || stdin.is_some() || drive_d.is_some() {
                    bail!("--root / --drive-d / --stdin are only supported in micro mode");
                }
                if expect_code != 0 {
                    bail!("--expect-code is only supported in micro mode");
                }
                commands::run_until_yield(&path, max)?;
            } else {
                let max = max_api.unwrap_or(256);
                commands::run_micro(
                    &path,
                    max,
                    expect_code,
                    root.as_deref(),
                    drive_d.as_deref(),
                    stdin.as_deref(),
                    &guest_args,
                )?;
            }
        }
        Command::Trace { path, max_api } => {
            commands::entry_trace(&path, max_api)?;
        }
    }

    Ok(())
}
