//! `agent-bash` — general-purpose always-background bash spooler for AI agents.

mod cgroup;
mod delivery;
mod guard;
mod state;
mod supervisor;

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use clap::{Parser, Subcommand};

use crate::guard::AttachedGuard;
use crate::state::{Meta, StatePaths};

const EX_USAGE: i32 = 64;
const EX_DATAERR: i32 = 65;
const EX_NOINPUT: i32 = 66;
const EX_SOFTWARE: i32 = 70;
const EX_CANTCREAT: i32 = 73;
const EX_IOERR: i32 = 74;

#[derive(Parser)]
#[command(
    name = "agent-bash",
    about = "Always-background bash spooler. Foreground is not offered; detached invocation is rejected."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Spool a command. Always runs in the background; returns a handle immediately.
    Run {
        /// Treat the workload as a long-lived server: report ready on this stdout
        /// marker (regex) instead of waiting for process-tree exit.
        #[arg(long)]
        ready_sentinel: Option<String>,
        /// The command and its arguments (after `--`).
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Non-blocking status of a spooled job: RUNNING, or DONE rc=<n> + captured output.
    Status {
        /// Print this many trailing log bytes. Defaults to 65536.
        #[arg(long, conflicts_with = "full")]
        tail_bytes: Option<u64>,
        /// Print the whole captured log.
        #[arg(long)]
        full: bool,
        handle: String,
    },
    /// List spooled jobs owned by the calling agent's process tree.
    List {
        /// List all handles under the state root, not just this caller PPID.
        #[arg(long)]
        all: bool,
        /// Emit JSON instead of line-oriented text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug)]
struct AppError {
    code: i32,
    message: Option<String>,
}

impl AppError {
    fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: Some(message.into()),
        }
    }
}

fn main() {
    let guard = AttachedGuard::capture();
    let cli = Cli::parse();
    if let Err(err) = run_cli(cli, guard) {
        if let Some(message) = err.message {
            eprintln!("{message}");
        }
        std::process::exit(err.code);
    }
}

fn run_cli(cli: Cli, guard: AttachedGuard) -> Result<(), AppError> {
    validate_guard(&guard)?;
    match cli.command {
        Command::Run {
            ready_sentinel,
            argv,
        } => run_command(guard, ready_sentinel, argv),
        Command::Status {
            tail_bytes,
            full,
            handle,
        } => status_command(handle, tail_bytes.unwrap_or(65_536), full),
        Command::List { all, json } => list_command(guard.startup_ppid(), all, json),
    }
}

fn validate_guard(guard: &AttachedGuard) -> Result<(), AppError> {
    guard.validate().map_err(|_| {
        AppError::new(
            EX_USAGE,
            "agent-bash: must be called as an attached subprocess",
        )
    })
}

fn run_command(
    guard: AttachedGuard,
    ready_sentinel: Option<String>,
    argv: Vec<String>,
) -> Result<(), AppError> {
    if let Some(pattern) = &ready_sentinel {
        regex::bytes::Regex::new(pattern).map_err(|err| {
            AppError::new(
                EX_USAGE,
                format!("agent-bash: invalid --ready-sentinel regex: {err}"),
            )
        })?;
    }

    supervisor::validate_argv(&argv).map_err(|err| AppError::new(EX_USAGE, err))?;

    let state_root = state::state_root().map_err(|err| {
        AppError::new(
            EX_CANTCREAT,
            format!("agent-bash: state root unavailable: {err}"),
        )
    })?;
    let handle = state::generate_handle().map_err(|err| {
        AppError::new(
            EX_SOFTWARE,
            format!("agent-bash: supervisor bootstrap failed: {err}"),
        )
    })?;
    let paths = StatePaths::new(state_root, handle.clone());
    state::create_handle_state(&paths).map_err(|err| {
        AppError::new(
            EX_CANTCREAT,
            format!(
                "agent-bash: failed to create handle state: {}: {err}",
                paths.state_dir.display()
            ),
        )
    })?;
    state::create_log(&paths).map_err(|err| {
        AppError::new(
            EX_CANTCREAT,
            format!(
                "agent-bash: failed to create handle state: {}: {err}",
                paths.log.display()
            ),
        )
    })?;

    let caller_chain = state::capture_caller_chain(guard.startup_ppid());
    let cwd = std::env::current_dir().map_err(|err| {
        AppError::new(
            EX_IOERR,
            format!("agent-bash: failed to read current directory: {err}"),
        )
    })?;
    let mode = if ready_sentinel.is_some() {
        "sentinel"
    } else {
        "exit"
    };
    let meta = Meta::new(
        handle.clone(),
        guard.startup_ppid(),
        unsafe { libc::getpid() },
        argv.clone(),
        cwd,
        mode,
        ready_sentinel.clone(),
        caller_chain,
    );
    state::write_meta_atomic(&paths, &meta).map_err(|err| {
        AppError::new(
            EX_CANTCREAT,
            format!("agent-bash: failed to create handle state: {err}"),
        )
    })?;

    validate_guard(&guard)?;
    supervisor::fork_supervisor(supervisor::SupervisorConfig {
        paths: paths.clone(),
        meta: meta.clone(),
        argv: argv.clone(),
        ready_sentinel: ready_sentinel.clone(),
    })
    .map_err(|err| {
        AppError::new(
            EX_SOFTWARE,
            format!("agent-bash: supervisor bootstrap failed: {err}"),
        )
    })?;

    let output = state::RunOutput::new(paths, meta.caller_ppid, mode, ready_sentinel);
    serde_json::to_writer(io::stdout(), &output).map_err(|err| {
        AppError::new(EX_IOERR, format!("agent-bash: failed to write JSON: {err}"))
    })?;
    io::stdout().write_all(b"\n").map_err(|err| {
        AppError::new(EX_IOERR, format!("agent-bash: failed to write JSON: {err}"))
    })?;
    Ok(())
}

fn status_command(handle: String, tail_bytes: u64, full: bool) -> Result<(), AppError> {
    let paths = paths_for_existing_handle(&handle)?;
    let meta = state::read_meta(&paths).map_err(|err| {
        AppError::new(
            EX_DATAERR,
            format!("agent-bash: failed to read meta for {handle}: {err}"),
        )
    })?;

    let rc_from_file = if paths.rc.exists() {
        Some(state::read_rc(&paths).map_err(|err| {
            AppError::new(
                EX_DATAERR,
                format!("agent-bash: failed to read rc for {handle}: {err}"),
            )
        })?)
    } else {
        None
    };

    let first_line = render_status_header(&meta, rc_from_file)?;
    println!("{first_line}");
    println!("--- output ---");
    let output = read_log_for_status(&paths.log, full, tail_bytes).map_err(|err| {
        AppError::new(
            EX_IOERR,
            format!("agent-bash: failed to read log for {handle}: {err}"),
        )
    })?;
    io::stdout().write_all(&output).map_err(|err| {
        AppError::new(
            EX_IOERR,
            format!("agent-bash: failed to write status: {err}"),
        )
    })?;
    Ok(())
}

fn render_status_header(meta: &Meta, rc_from_file: Option<i32>) -> Result<String, AppError> {
    match meta.state.as_str() {
        "RUNNING" => Ok(format!("RUNNING handle={}", meta.handle)),
        "DONE" => {
            let rc = rc_from_file.ok_or_else(|| {
                AppError::new(
                    EX_DATAERR,
                    format!("agent-bash: inconsistent state for handle {}", meta.handle),
                )
            })?;
            match (meta.mode.as_str(), meta.completion_reason.as_deref()) {
                ("sentinel", Some("ready-sentinel")) => {
                    let workload = if meta.workload_rc.is_some() {
                        "exited"
                    } else {
                        "running"
                    };
                    Ok(format!(
                        "DONE rc={rc} handle={} reason=ready-sentinel workload={workload}",
                        meta.handle
                    ))
                }
                ("sentinel", Some("exit-before-ready")) => Ok(format!(
                    "DONE rc={rc} handle={} reason=exit-before-ready",
                    meta.handle
                )),
                _ => Ok(format!("DONE rc={rc} handle={}", meta.handle)),
            }
        }
        "ERROR" => {
            let rc = rc_from_file.or(meta.rc).unwrap_or(EX_SOFTWARE);
            Ok(format!("ERROR rc={rc} handle={}", meta.handle))
        }
        _ => Err(AppError::new(
            EX_DATAERR,
            format!("agent-bash: corrupt state for handle {}", meta.handle),
        )),
    }
}

fn read_log_for_status(path: &Path, full: bool, tail_bytes: u64) -> io::Result<Vec<u8>> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    if !full {
        let len = file.metadata()?.len();
        if len > tail_bytes {
            file.seek(SeekFrom::Start(len - tail_bytes))?;
        }
    }
    let mut output = Vec::new();
    file.read_to_end(&mut output)?;
    Ok(output)
}

fn list_command(caller_ppid: libc::pid_t, all: bool, json: bool) -> Result<(), AppError> {
    let root = state::state_root().map_err(|err| {
        AppError::new(
            EX_CANTCREAT,
            format!("agent-bash: state root unavailable: {err}"),
        )
    })?;
    let mut summaries = Vec::new();
    if root.exists() {
        let entries = std::fs::read_dir(&root).map_err(|err| {
            AppError::new(
                EX_IOERR,
                format!(
                    "agent-bash: failed to read state root {}: {err}",
                    root.display()
                ),
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|err| {
                AppError::new(
                    EX_IOERR,
                    format!("agent-bash: failed to read state root: {err}"),
                )
            })?;
            if !entry.file_type().map(|ty| ty.is_dir()).unwrap_or(false) {
                continue;
            }
            let handle = entry.file_name().to_string_lossy().into_owned();
            let paths = StatePaths::new(root.clone(), handle);
            let Ok(meta) = state::read_meta(&paths) else {
                continue;
            };
            if !all && meta.caller_ppid != caller_ppid {
                continue;
            }
            summaries.push(state::ListSummary::from_meta(&meta, paths.state_dir));
        }
    }
    summaries.sort_by(|left, right| {
        left.created_at_unix_ms
            .cmp(&right.created_at_unix_ms)
            .then_with(|| left.handle.cmp(&right.handle))
    });
    if json {
        serde_json::to_writer(io::stdout(), &summaries).map_err(|err| {
            AppError::new(EX_IOERR, format!("agent-bash: failed to write JSON: {err}"))
        })?;
        io::stdout().write_all(b"\n").map_err(|err| {
            AppError::new(EX_IOERR, format!("agent-bash: failed to write JSON: {err}"))
        })?;
    } else {
        for summary in summaries {
            let rc = summary
                .rc
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string());
            println!(
                "{} {} rc={} mode={} created_at={} state_dir={}",
                summary.handle,
                summary.state,
                rc,
                summary.mode,
                summary.created_at_unix_ms,
                summary.state_dir.display()
            );
        }
    }
    Ok(())
}

fn paths_for_existing_handle(handle: &str) -> Result<StatePaths, AppError> {
    let root = state::state_root().map_err(|err| {
        AppError::new(
            EX_CANTCREAT,
            format!("agent-bash: state root unavailable: {err}"),
        )
    })?;
    let paths = StatePaths::new(root, handle.to_string());
    if !paths.meta.exists() {
        return Err(AppError::new(
            EX_NOINPUT,
            format!("agent-bash: unknown handle: {handle}"),
        ));
    }
    Ok(paths)
}
