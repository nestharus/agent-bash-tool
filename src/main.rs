//! `agent-bash` - general-purpose detached bash spooler for AI agents.

mod cgroup;
mod delivery;
mod guard;
mod state;
mod supervisor;

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand, ValueEnum};

use crate::guard::AttachedGuard;
use crate::state::{CallerChainEntry, DeliveryMode, ListSummary, Meta, RunOutput, StatePaths};

const EX_USAGE: i32 = 64;
const EX_DATAERR: i32 = 65;
const EX_NOINPUT: i32 = 66;
const EX_SOFTWARE: i32 = 70;
const EX_CANTCREAT: i32 = 73;
const EX_IOERR: i32 = 74;
const OWNER_SESSION_ID_ENV: &str = "AGENT_BASH_OWNER_SESSION_ID";
const OWNER_INVOCATION_UUID_ENV: &str = "AGENT_BASH_OWNER_INVOCATION_UUID";
const PARENT_INVOCATION_ENV: &str = "OULIPOLY_PARENT_INVOCATION";

struct OwnerContext {
    session_id: Option<String>,
    invocation_uuid: Option<String>,
}

#[derive(Parser)]
#[command(
    name = "agent-bash",
    about = "Detached bash spooler with explicit synchronous or asynchronous completion delivery."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Spool a command under a surviving detached supervisor.
    Run {
        /// Completion delivery policy. Sync results stay in-band; async results notify the mailbox.
        #[arg(long, value_enum, default_value_t = CliDeliveryMode::Async)]
        delivery: CliDeliveryMode,
        /// Completion boundary for exit-mode workloads. Tree waits for every adopted
        /// descendant; root completes when the launched process exits and output closes.
        #[arg(long, value_enum, default_value_t = CliCompletionScope::Tree)]
        completion_scope: CliCompletionScope,
        /// Treat the workload as a long-lived server: report ready on this stdout
        /// marker (regex) instead of waiting for process-tree exit.
        #[arg(long)]
        ready_sentinel: Option<String>,
        /// Cancel the supervised process tree when the exact owner PID exits.
        #[arg(long, requires = "owner_pid")]
        cancel_on_owner_exit: bool,
        /// Ancestor PID whose identity owns this workload lease.
        #[arg(long, requires = "cancel_on_owner_exit")]
        owner_pid: Option<libc::pid_t>,
        /// The command and its arguments (after `--`).
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Convert a running synchronous call to asynchronous mailbox delivery.
    Detach { handle: String },
    /// Cancel a supervised workload and all of its adopted descendants.
    Cancel { handle: String },
    /// Print the current completion delivery mode for a handle.
    Mode { handle: String },
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
        /// List all handles under the state root, not just this caller's process tree.
        #[arg(long)]
        all: bool,
        /// Emit JSON instead of line-oriented text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CliDeliveryMode {
    Sync,
    Async,
}

#[derive(Clone, Copy, ValueEnum)]
enum CliCompletionScope {
    Tree,
    Root,
}

impl From<CliCompletionScope> for supervisor::CompletionScope {
    fn from(value: CliCompletionScope) -> Self {
        match value {
            CliCompletionScope::Tree => Self::Tree,
            CliCompletionScope::Root => Self::Root,
        }
    }
}

impl From<CliDeliveryMode> for DeliveryMode {
    fn from(value: CliDeliveryMode) -> Self {
        match value {
            CliDeliveryMode::Sync => Self::Sync,
            CliDeliveryMode::Async => Self::Async,
        }
    }
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
            delivery,
            completion_scope,
            ready_sentinel,
            cancel_on_owner_exit,
            owner_pid,
            argv,
        } => run_command(
            guard,
            delivery.into(),
            completion_scope.into(),
            ready_sentinel,
            cancel_on_owner_exit,
            owner_pid,
            argv,
        ),
        Command::Detach { handle } => detach_command(handle),
        Command::Cancel { handle } => cancel_command(handle),
        Command::Mode { handle } => mode_command(handle),
        Command::Status {
            tail_bytes,
            full,
            handle,
        } => status_command(handle, tail_bytes.unwrap_or(65_536), full),
        Command::List { all, json } => list_command(
            guard.startup_ppid(),
            nonempty_env(OWNER_SESSION_ID_ENV),
            all,
            json,
        ),
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
    delivery_mode: DeliveryMode,
    completion_scope: supervisor::CompletionScope,
    ready_sentinel: Option<String>,
    cancel_on_owner_exit: bool,
    owner_pid: Option<libc::pid_t>,
    argv: Vec<String>,
) -> Result<(), AppError> {
    validate_ready_sentinel(ready_sentinel.as_deref())?;
    supervisor::validate_argv(&argv).map_err(workload_argv_error)?;

    let state_root = load_state_root().map_err(state_root_unavailable)?;
    reap_state_dirs_at_startup(&state_root);
    let handle = state::generate_handle().map_err(supervisor_bootstrap_error)?;
    let paths = state_paths(state_root, handle.clone());

    let caller_chain = state::capture_caller_chain(guard.startup_ppid());
    let cancel_owner = resolve_cancel_owner(&caller_chain, cancel_on_owner_exit, owner_pid)?;
    let cwd = current_directory().map_err(current_directory_error)?;
    let mode = run_mode(&ready_sentinel);
    let owner = owner_context(&caller_chain)?;
    let meta = Meta::new(
        handle,
        guard.startup_ppid(),
        unsafe { libc::getpid() },
        argv.clone(),
        cwd,
        mode,
        delivery_mode,
        ready_sentinel.clone(),
        caller_chain,
        cancel_owner,
    )
    .with_owner_context(owner.session_id, owner.invocation_uuid);
    create_run_state(&paths)?;
    persist_delivery_mode(&paths, delivery_mode)?;
    if let Err(err) = delivery::prepare_registration(&paths) {
        let _ = fs::remove_dir_all(&paths.state_dir);
        return Err(completion_event_registration_error(err));
    }
    persist_initial_meta(&paths, &meta)?;
    if let Err(err) = delivery::register(&paths, &meta) {
        let _ = fs::remove_dir_all(&paths.state_dir);
        return Err(completion_event_registration_error(err));
    }

    validate_guard(&guard)?;
    let config = supervisor_config(
        paths.clone(),
        meta.clone(),
        argv,
        completion_scope,
        ready_sentinel.clone(),
    );
    supervisor::fork_supervisor(config).map_err(supervisor_bootstrap_error)?;

    let output = run_output(paths, meta.caller_ppid, mode, delivery_mode, ready_sentinel);
    emit_run_output(&output)?;
    Ok(())
}

fn resolve_cancel_owner(
    caller_chain: &[CallerChainEntry],
    enabled: bool,
    owner_pid: Option<libc::pid_t>,
) -> Result<Option<CallerChainEntry>, AppError> {
    if !enabled {
        return Ok(None);
    }
    let owner_pid = owner_pid.ok_or_else(|| {
        AppError::new(
            EX_USAGE,
            "agent-bash: --cancel-on-owner-exit requires --owner-pid",
        )
    })?;
    caller_chain
        .iter()
        .find(|entry| entry.pid == owner_pid)
        .cloned()
        .map(Some)
        .ok_or_else(|| {
            AppError::new(
                EX_USAGE,
                format!("agent-bash: owner PID {owner_pid} is not in the caller ancestry"),
            )
        })
}

fn cancel_command(handle: String) -> Result<(), AppError> {
    let paths = paths_for_existing_handle(&handle)?;
    let requested =
        supervisor::request_cancel(&paths).map_err(|err| cancel_request_error(&handle, err))?;
    serde_json::to_writer(
        io::stdout(),
        &serde_json::json!({ "handle": handle, "requested": requested }),
    )
    .map_err(json_write_error)?;
    io::stdout().write_all(b"\n").map_err(json_write_error)
}

fn cancel_request_error(handle: &str, err: io::Error) -> AppError {
    AppError::new(
        EX_IOERR,
        format!("agent-bash: failed to cancel {handle}: {err}"),
    )
}

fn persist_delivery_mode(paths: &StatePaths, delivery_mode: DeliveryMode) -> Result<(), AppError> {
    state::write_delivery_mode_atomic(paths, delivery_mode).map_err(initial_meta_create_error)
}

fn validate_ready_sentinel(pattern: Option<&str>) -> Result<(), AppError> {
    let Some(pattern) = pattern else {
        return Ok(());
    };
    regex::bytes::Regex::new(pattern).map_err(invalid_ready_sentinel_error)?;
    Ok(())
}

fn workload_argv_error(err: String) -> AppError {
    AppError::new(EX_USAGE, err)
}

fn invalid_ready_sentinel_error(err: regex::Error) -> AppError {
    AppError::new(
        EX_USAGE,
        format!("agent-bash: invalid --ready-sentinel regex: {err}"),
    )
}

fn load_state_root() -> Result<PathBuf, state::StateError> {
    state::state_root()
}

fn state_root_unavailable(err: state::StateError) -> AppError {
    AppError::new(
        EX_CANTCREAT,
        format!("agent-bash: state root unavailable: {err}"),
    )
}

fn reap_state_dirs_at_startup(root: &Path) {
    let stats = state::reap_state_dirs(root, state::ReapConfig::from_env());
    if should_report_reap_stats(&stats) {
        report_reap_stats(&stats);
    }
}

fn should_report_reap_stats(stats: &state::ReapStats) -> bool {
    stats.reaped > 0 || stats.errors > 0
}

fn report_reap_stats(stats: &state::ReapStats) {
    eprintln!(
        "agent-bash: state reaper scanned={} reaped={} errors={}",
        stats.scanned, stats.reaped, stats.errors
    );
}

fn supervisor_bootstrap_error(err: impl std::fmt::Display) -> AppError {
    AppError::new(
        EX_SOFTWARE,
        format!("agent-bash: supervisor bootstrap failed: {err}"),
    )
}

fn state_paths(root: PathBuf, handle: String) -> StatePaths {
    StatePaths::new(root, handle)
}

fn create_run_state(paths: &StatePaths) -> Result<(), AppError> {
    state::create_handle_state(paths).map_err(|err| handle_state_create_error(paths, err))?;
    state::create_log(paths).map_err(|err| handle_log_create_error(paths, err))?;
    Ok(())
}

fn handle_state_create_error(paths: &StatePaths, err: io::Error) -> AppError {
    AppError::new(
        EX_CANTCREAT,
        format!(
            "agent-bash: failed to create handle state: {}: {err}",
            paths.state_dir.display()
        ),
    )
}

fn handle_log_create_error(paths: &StatePaths, err: io::Error) -> AppError {
    AppError::new(
        EX_CANTCREAT,
        format!(
            "agent-bash: failed to create handle state: {}: {err}",
            paths.log.display()
        ),
    )
}

fn current_directory() -> io::Result<PathBuf> {
    std::env::current_dir()
}

fn current_directory_error(err: io::Error) -> AppError {
    AppError::new(
        EX_IOERR,
        format!("agent-bash: failed to read current directory: {err}"),
    )
}

fn run_mode(ready_sentinel: &Option<String>) -> &'static str {
    if ready_sentinel.is_some() {
        "sentinel"
    } else {
        "exit"
    }
}

fn owner_context(caller_chain: &[CallerChainEntry]) -> Result<OwnerContext, AppError> {
    let explicit = OwnerContext {
        session_id: nonempty_env(OWNER_SESSION_ID_ENV),
        invocation_uuid: nonempty_env(OWNER_INVOCATION_UUID_ENV),
    };
    if let (Some(explicit_invocation_uuid), Some(_)) = (
        explicit.invocation_uuid.as_deref(),
        explicit.session_id.as_deref(),
    ) && parent_invocation_uuid().as_deref() == Some(explicit_invocation_uuid)
        && let Some((session_id, invocation_uuid)) =
            delivery::resolve_owner_binding(caller_chain, explicit_invocation_uuid)
                .map_err(owner_resolution_error)?
    {
        return Ok(OwnerContext {
            session_id: Some(session_id),
            invocation_uuid: Some(invocation_uuid),
        });
    }
    if explicit.session_id.is_some() || explicit.invocation_uuid.is_some() {
        return Ok(explicit);
    }

    let Some(expected_invocation_uuid) = parent_invocation_uuid() else {
        return Ok(explicit);
    };
    let Some((session_id, invocation_uuid)) =
        delivery::resolve_owner_binding(caller_chain, &expected_invocation_uuid)
            .map_err(owner_resolution_error)?
    else {
        return Ok(explicit);
    };
    Ok(OwnerContext {
        session_id: Some(session_id),
        invocation_uuid: Some(invocation_uuid),
    })
}

fn owner_resolution_error(err: io::Error) -> AppError {
    AppError::new(
        EX_IOERR,
        format!("agent-bash: failed to resolve completion owner: {err}"),
    )
}

fn parent_invocation_uuid() -> Option<String> {
    let raw = nonempty_env(PARENT_INVOCATION_ENV)?;
    let marker: serde_json::Value = serde_json::from_str(&raw).ok()?;
    marker
        .get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn persist_initial_meta(paths: &StatePaths, meta: &Meta) -> Result<(), AppError> {
    state::write_meta_atomic(paths, meta).map_err(initial_meta_create_error)?;
    state::write_owner_atomic(paths, &state::OwnerMeta::from_meta(meta))
        .map_err(initial_meta_create_error)
}

fn initial_meta_create_error(err: io::Error) -> AppError {
    AppError::new(
        EX_CANTCREAT,
        format!("agent-bash: failed to create handle state: {err}"),
    )
}

fn completion_event_registration_error(err: io::Error) -> AppError {
    AppError::new(
        EX_IOERR,
        format!("agent-bash: failed to register completion event: {err}"),
    )
}

fn supervisor_config(
    paths: StatePaths,
    meta: Meta,
    argv: Vec<String>,
    completion_scope: supervisor::CompletionScope,
    ready_sentinel: Option<String>,
) -> supervisor::SupervisorConfig {
    supervisor::SupervisorConfig {
        paths,
        meta,
        argv,
        completion_scope,
        ready_sentinel,
    }
}

fn run_output(
    paths: StatePaths,
    caller_ppid: libc::pid_t,
    mode: &str,
    delivery_mode: DeliveryMode,
    ready_sentinel: Option<String>,
) -> RunOutput {
    RunOutput::new(paths, caller_ppid, mode, delivery_mode, ready_sentinel)
}

fn detach_command(handle: String) -> Result<(), AppError> {
    let paths = paths_for_existing_handle(&handle)?;
    let outcome = delivery::detach(&paths).map_err(|err| delivery_mode_error(&handle, err))?;
    serde_json::to_writer(io::stdout(), &outcome).map_err(json_write_error)?;
    io::stdout().write_all(b"\n").map_err(json_write_error)
}

fn mode_command(handle: String) -> Result<(), AppError> {
    let paths = paths_for_existing_handle(&handle)?;
    let mode =
        state::read_delivery_mode(&paths).map_err(|err| delivery_mode_error(&handle, err))?;
    println!("{}", mode.as_str());
    Ok(())
}

fn delivery_mode_error(handle: &str, err: io::Error) -> AppError {
    AppError::new(
        EX_IOERR,
        format!("agent-bash: failed to update delivery mode for {handle}: {err}"),
    )
}

fn emit_run_output(output: &RunOutput) -> Result<(), AppError> {
    serde_json::to_writer(io::stdout(), output).map_err(json_write_error)?;
    io::stdout().write_all(b"\n").map_err(json_write_error)
}

fn json_write_error(err: impl std::fmt::Display) -> AppError {
    AppError::new(EX_IOERR, format!("agent-bash: failed to write JSON: {err}"))
}

fn status_command(handle: String, tail_bytes: u64, full: bool) -> Result<(), AppError> {
    let paths = paths_for_existing_handle(&handle)?;
    let meta = reconcile_status_meta(&paths, &handle)?;

    let rc_from_file = if rc_file_exists(&paths) {
        Some(read_rc_for_handle(&paths, &handle)?)
    } else {
        None
    };

    emit_status_header(&meta, rc_from_file)?;
    emit_output_separator();
    let output = read_log_for_status(&paths.log, full, tail_bytes)
        .map_err(|err| status_log_read_error(&handle, err))?;
    io::stdout()
        .write_all(&output)
        .map_err(status_write_error)?;
    Ok(())
}

fn reconcile_status_meta(paths: &StatePaths, handle: &str) -> Result<Meta, AppError> {
    let mut meta = read_meta_for_handle(paths, handle)?;
    if delivery::delivery_needs_retry(&meta) {
        delivery::complete(paths, &mut meta)
            .map_err(|err| status_reconciliation_error(handle, err))?;
        return Ok(meta);
    }
    if !state::running_exit_mode(&meta) {
        return Ok(meta);
    }
    supervisor::reconcile_lost_supervisor(paths)
        .map_err(|err| status_reconciliation_error(handle, err))
}

fn status_reconciliation_error(handle: &str, err: io::Error) -> AppError {
    AppError::new(
        EX_IOERR,
        format!("agent-bash: failed to reconcile state for {handle}: {err}"),
    )
}

fn status_log_read_error(handle: &str, err: io::Error) -> AppError {
    AppError::new(
        EX_IOERR,
        format!("agent-bash: failed to read log for {handle}: {err}"),
    )
}

fn status_write_error(err: io::Error) -> AppError {
    AppError::new(
        EX_IOERR,
        format!("agent-bash: failed to write status: {err}"),
    )
}

fn read_meta_for_handle(paths: &StatePaths, handle: &str) -> Result<Meta, AppError> {
    state::read_meta(paths).map_err(|err| read_meta_error(handle, err))
}

fn read_meta_error(handle: &str, err: io::Error) -> AppError {
    AppError::new(
        EX_DATAERR,
        format!("agent-bash: failed to read meta for {handle}: {err}"),
    )
}

fn rc_file_exists(paths: &StatePaths) -> bool {
    paths.rc.exists()
}

fn read_rc_for_handle(paths: &StatePaths, handle: &str) -> Result<i32, AppError> {
    state::read_rc(paths).map_err(|err| read_rc_error(handle, err))
}

fn read_rc_error(handle: &str, err: io::Error) -> AppError {
    AppError::new(
        EX_DATAERR,
        format!("agent-bash: failed to read rc for {handle}: {err}"),
    )
}

fn emit_status_header(meta: &Meta, rc_from_file: Option<i32>) -> Result<(), AppError> {
    let first_line = render_status_header(meta, rc_from_file)?;
    println!("{first_line}");
    Ok(())
}

fn emit_output_separator() {
    println!("--- output ---");
}

enum StatusHeader {
    Running {
        handle: String,
    },
    Done {
        handle: String,
        rc: i32,
        reason: DoneReason,
    },
    Error {
        handle: String,
        rc: i32,
    },
}

enum DoneReason {
    Exit,
    ReadySentinel { workload_running: bool },
    ExitBeforeReady,
    CancelRequest,
    OwnerExit,
}

fn render_status_header(meta: &Meta, rc_from_file: Option<i32>) -> Result<String, AppError> {
    let header = validated_status_header(meta, rc_from_file)?;
    Ok(format_status_header(&header))
}

fn validated_status_header(
    meta: &Meta,
    rc_from_file: Option<i32>,
) -> Result<StatusHeader, AppError> {
    match meta.state.as_str() {
        "RUNNING" => Ok(StatusHeader::Running {
            handle: meta.handle.clone(),
        }),
        "DONE" => {
            let rc = required_done_rc(meta, rc_from_file)?;
            Ok(StatusHeader::Done {
                handle: meta.handle.clone(),
                rc,
                reason: done_reason(meta),
            })
        }
        "ERROR" => {
            let rc = rc_from_file.or(meta.rc).unwrap_or(EX_SOFTWARE);
            Ok(StatusHeader::Error {
                handle: meta.handle.clone(),
                rc,
            })
        }
        _ => Err(corrupt_state_error(meta)),
    }
}

fn required_done_rc(meta: &Meta, rc_from_file: Option<i32>) -> Result<i32, AppError> {
    rc_from_file.ok_or_else(|| inconsistent_state_error(meta))
}

fn inconsistent_state_error(meta: &Meta) -> AppError {
    AppError::new(
        EX_DATAERR,
        format!("agent-bash: inconsistent state for handle {}", meta.handle),
    )
}

fn corrupt_state_error(meta: &Meta) -> AppError {
    AppError::new(
        EX_DATAERR,
        format!("agent-bash: corrupt state for handle {}", meta.handle),
    )
}

fn done_reason(meta: &Meta) -> DoneReason {
    match (meta.mode.as_str(), meta.completion_reason.as_deref()) {
        ("sentinel", Some("ready-sentinel")) => DoneReason::ReadySentinel {
            workload_running: meta.workload_rc.is_none(),
        },
        ("sentinel", Some("exit-before-ready")) => DoneReason::ExitBeforeReady,
        (_, Some("cancel-request")) => DoneReason::CancelRequest,
        (_, Some("owner-exit")) => DoneReason::OwnerExit,
        _ => DoneReason::Exit,
    }
}

fn format_status_header(header: &StatusHeader) -> String {
    match header {
        StatusHeader::Running { handle } => format!("RUNNING handle={handle}"),
        StatusHeader::Done { handle, rc, reason } => format_done_header(handle, *rc, reason),
        StatusHeader::Error { handle, rc } => format!("ERROR rc={rc} handle={handle}"),
    }
}

fn format_done_header(handle: &str, rc: i32, reason: &DoneReason) -> String {
    match reason {
        DoneReason::ReadySentinel { workload_running } => format!(
            "DONE rc={rc} handle={handle} reason=ready-sentinel workload={}",
            workload_state(*workload_running)
        ),
        DoneReason::ExitBeforeReady => {
            format!("DONE rc={rc} handle={handle} reason=exit-before-ready")
        }
        DoneReason::CancelRequest => {
            format!("DONE rc={rc} handle={handle} reason=cancel-request")
        }
        DoneReason::OwnerExit => format!("DONE rc={rc} handle={handle} reason=owner-exit"),
        DoneReason::Exit => format!("DONE rc={rc} handle={handle}"),
    }
}

fn workload_state(running: bool) -> &'static str {
    if running { "running" } else { "exited" }
}

fn read_log_for_status(path: &Path, full: bool, tail_bytes: u64) -> io::Result<Vec<u8>> {
    let Some(mut file) = open_status_log(path)? else {
        return Ok(Vec::new());
    };
    seek_status_log(&mut file, full, tail_bytes)?;
    read_open_status_log(file)
}

fn open_status_log(path: &Path) -> io::Result<Option<std::fs::File>> {
    match state::open_read_no_follow(path) {
        Ok(file) => Ok(Some(file)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn seek_status_log(file: &mut std::fs::File, full: bool, tail_bytes: u64) -> io::Result<()> {
    if full {
        return Ok(());
    }
    let len = file.metadata()?.len();
    if len > tail_bytes {
        file.seek(SeekFrom::Start(len - tail_bytes))?;
    }
    Ok(())
}

fn read_open_status_log(mut file: std::fs::File) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    file.read_to_end(&mut output)?;
    Ok(output)
}

fn list_command(
    caller_ppid: libc::pid_t,
    owner_session_id: Option<String>,
    all: bool,
    json: bool,
) -> Result<(), AppError> {
    let root = load_state_root().map_err(state_root_unavailable)?;
    let caller_chain = if all {
        Vec::new()
    } else {
        state::capture_caller_chain(caller_ppid)
    };
    let mut summaries = list_summaries(&root, &caller_chain, owner_session_id.as_deref(), all)?;
    sort_summaries(&mut summaries);
    emit_list_summaries(&summaries, json)?;
    Ok(())
}

fn list_summaries(
    root: &Path,
    caller_chain: &[state::CallerChainEntry],
    owner_session_id: Option<&str>,
    all: bool,
) -> Result<Vec<ListSummary>, AppError> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let entries = read_state_entries(root)?;
    let mut summaries = Vec::new();
    for entry in entries {
        let entry = read_state_entry(entry)?;
        if let Some(summary) =
            list_summary_for_entry(root, entry, caller_chain, owner_session_id, all)
        {
            summaries.push(summary);
        }
    }
    Ok(summaries)
}

fn read_state_entries(root: &Path) -> Result<std::fs::ReadDir, AppError> {
    std::fs::read_dir(root).map_err(|err| read_state_root_error(root, err))
}

fn read_state_root_error(root: &Path, err: io::Error) -> AppError {
    AppError::new(
        EX_IOERR,
        format!(
            "agent-bash: failed to read state root {}: {err}",
            root.display()
        ),
    )
}

fn read_state_entry(entry: io::Result<std::fs::DirEntry>) -> Result<std::fs::DirEntry, AppError> {
    entry.map_err(read_state_entry_error)
}

fn read_state_entry_error(err: io::Error) -> AppError {
    AppError::new(
        EX_IOERR,
        format!("agent-bash: failed to read state root: {err}"),
    )
}

fn list_summary_for_entry(
    root: &Path,
    entry: std::fs::DirEntry,
    caller_chain: &[state::CallerChainEntry],
    owner_session_id: Option<&str>,
    all: bool,
) -> Option<ListSummary> {
    if !entry_is_state_dir(&entry) {
        return None;
    }
    let paths = paths_for_entry(root, &entry);
    let meta = reconcile_list_meta(&paths, read_entry_meta(&paths)?)?;
    if !include_list_meta(&meta, &paths, caller_chain, owner_session_id, all) {
        return None;
    }
    Some(list_summary_from_meta(&meta, paths.state_dir))
}

fn reconcile_list_meta(paths: &StatePaths, meta: Meta) -> Option<Meta> {
    if !state::running_exit_mode(&meta) {
        return Some(meta);
    }
    supervisor::reconcile_lost_supervisor_without_delivery(paths).ok()
}

fn entry_is_state_dir(entry: &std::fs::DirEntry) -> bool {
    entry.file_type().map(|ty| ty.is_dir()).unwrap_or(false)
}

fn paths_for_entry(root: &Path, entry: &std::fs::DirEntry) -> StatePaths {
    let handle = entry.file_name().to_string_lossy().into_owned();
    StatePaths::new(root.to_path_buf(), handle)
}

fn read_entry_meta(paths: &StatePaths) -> Option<Meta> {
    state::read_meta(paths).ok()
}

fn include_list_meta(
    meta: &Meta,
    paths: &StatePaths,
    caller_chain: &[state::CallerChainEntry],
    owner_session_id: Option<&str>,
    all: bool,
) -> bool {
    if all {
        return true;
    }
    if owner_session_matches(meta, paths, owner_session_id) {
        return true;
    }
    let Some(anchor) = meta.caller_chain.first() else {
        return false;
    };
    if anchor.pid <= 1 || anchor.starttime_ticks == 0 || anchor.boot_id.is_empty() {
        return false;
    }
    caller_chain.iter().any(|entry| {
        entry.pid == anchor.pid
            && entry.starttime_ticks == anchor.starttime_ticks
            && entry.boot_id == anchor.boot_id
    })
}

fn owner_session_matches(meta: &Meta, paths: &StatePaths, owner_session_id: Option<&str>) -> bool {
    let Some(session_id) = owner_session_id else {
        return false;
    };
    if let Some(meta_session_id) = meta.owner_session_id.as_deref() {
        return meta_session_id == session_id;
    }
    state::read_owner(paths)
        .ok()
        .and_then(|owner| owner.owner_session_id)
        .as_deref()
        == Some(session_id)
}

fn list_summary_from_meta(meta: &Meta, state_dir: PathBuf) -> ListSummary {
    ListSummary::from_meta(meta, state_dir)
}

fn sort_summaries(summaries: &mut [ListSummary]) {
    summaries.sort_by(|left, right| {
        left.created_at_unix_ms
            .cmp(&right.created_at_unix_ms)
            .then_with(|| left.handle.cmp(&right.handle))
    });
}

fn emit_list_summaries(summaries: &[ListSummary], json: bool) -> Result<(), AppError> {
    if json {
        return emit_json_list_summaries(summaries);
    }
    emit_text_list_summaries(summaries);
    Ok(())
}

fn emit_json_list_summaries(summaries: &[ListSummary]) -> Result<(), AppError> {
    serde_json::to_writer(io::stdout(), summaries).map_err(json_write_error)?;
    io::stdout().write_all(b"\n").map_err(json_write_error)
}

fn emit_text_list_summaries(summaries: &[ListSummary]) {
    for summary in summaries {
        println!("{}", format_list_summary(summary));
    }
}

fn format_list_summary(summary: &ListSummary) -> String {
    format!(
        "{} {} rc={} mode={} delivery={} created_at={} state_dir={}",
        summary.handle,
        summary.state,
        format_optional_rc(summary.rc),
        summary.mode,
        summary.delivery_mode.as_str(),
        summary.created_at_unix_ms,
        summary.state_dir.display()
    )
}

fn format_optional_rc(rc: Option<i32>) -> String {
    rc.map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn paths_for_existing_handle(handle: &str) -> Result<StatePaths, AppError> {
    let root = load_state_root().map_err(state_root_unavailable)?;
    let paths = state_paths(root, handle.to_string());
    validate_existing_handle(handle, &paths)?;
    Ok(paths)
}

fn validate_existing_handle(handle: &str, paths: &StatePaths) -> Result<(), AppError> {
    if paths.meta.exists() {
        return Ok(());
    }
    Err(unknown_handle_error(handle))
}

fn unknown_handle_error(handle: &str) -> AppError {
    AppError::new(EX_NOINPUT, format!("agent-bash: unknown handle: {handle}"))
}
