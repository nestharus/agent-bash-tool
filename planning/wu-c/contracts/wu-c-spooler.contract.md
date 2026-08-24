# WU-C Spooler Phase-6a Code-Quality Contract

Scope: the WU-C spooler is one multi-file production component covering `src/main.rs`, `src/state.rs`, `src/guard.rs`, `src/supervisor.rs`, `src/cgroup.rs`, and `src/delivery.rs`. Test-only functions in `#[cfg(test)]` modules and `tests/spooler_cli.rs` are runtime-proof context and are excluded from production function classification.

## Component declared roles

Component: WU-C spooler component

Declared role set: `orchestration`, `filter`, `validator`, `predicate`, `mapper`, `accessor`, `formatter`, `parser`.

Justification: the spooler is one cohesive systems component split across focused modules. The component legitimately sequences Linux supervision, filters cgroup/list/log surfaces, validates guard and input invariants, evaluates readiness/completion predicates, maps state metadata, accesses files/proc/fds, formats CLI/state output, and parses proc/cgroup/JSON/rc surfaces. This component declaration is the honest union of the focused module roles below; it is not a waiver for multi-classifier functions. Each production function remains inventoried with one A1 classification.

## Per-file declared roles

| File | Declared roles | Justification |
|---|---|---|
| `src/main.rs` | `orchestration`, `filter`, `validator`, `mapper`, `accessor`, `formatter` | CLI command sequencing plus validation, state/log access, list/log filtering, command metadata mapping, and user-facing output/error formatting. |
| `src/state.rs` | `orchestration`, `validator`, `mapper`, `accessor`, `formatter`, `parser` | Shared state paths, metadata, environment selection, time/random/proc/file access, atomic persistence, and JSON/rc/proc parsing. |
| `src/guard.rs` | `accessor`, `validator` | Captures/exposes startup PPID and validates parent stability. |
| `src/supervisor.rs` | `orchestration`, `validator`, `predicate`, `mapper`, `accessor`, `formatter`, `parser`, `filter` | Daemonization, spawn, polling, reaping, completion, argv validation, completion predicates, status mapping, fd/pid access, errno/status formatting, exec-error parsing, and poll/fd readiness filtering. |
| `src/cgroup.rs` | `orchestration`, `validator`, `mapper`, `accessor`, `formatter`, `parser`, `filter` | Cgroup setup/teardown, path/PID validation, setup metadata mapping, fd/live-state access, PID formatting, proc/cgroup parsing, and live PID line filtering. |
| `src/delivery.rs` | `orchestration`, `mapper`, `formatter`, `accessor` | Delivery command sequencing, result metadata mapping, CLI argv/error formatting, and delivery-binary environment access. |

## Function inventory

The inventory is grouped by file and A1 classification. Each row lists production functions with the same single classification after the remediation split.

| File | A1 classification | Functions | Justification |
|---|---|---|---|
| `src/main.rs` | `orchestration` | `main`, `run_cli`, `run_command`, `create_run_state`, `persist_initial_meta`, `emit_run_output`, `status_command`, `emit_status_header`, `render_status_header`, `read_log_for_status`, `list_command`, `list_summaries`, `list_summary_for_entry`, `emit_list_summaries`, `paths_for_existing_handle` | These functions sequence named helpers and side effects without inlining parse/format/map logic. |
| `src/main.rs` | `validator` | `validate_guard`, `validate_ready_sentinel`, `validated_status_header`, `required_done_rc`, `validate_existing_handle` | These accept/reject guard, regex, status, rc, and handle invariants. |
| `src/main.rs` | `mapper` | `AppError::new`, `state_paths`, `run_mode`, `initial_meta`, `supervisor_config`, `run_output`, `done_reason`, `list_summary_from_meta` | These transform accepted inputs into internal state/config/result shapes. |
| `src/main.rs` | `accessor` | `load_state_root`, `current_directory`, `read_meta_for_handle`, `rc_file_exists`, `read_rc_for_handle`, `open_status_log`, `read_open_status_log`, `read_state_entries`, `read_state_entry`, `read_entry_meta` | These retrieve state, directory, rc, metadata, log, and filesystem entries. |
| `src/main.rs` | `filter` | `seek_status_log`, `entry_is_state_dir`, `include_list_meta`, `sort_summaries` | These select tail windows, directory entries, caller-owned jobs, or list order. |
| `src/main.rs` | `formatter` | `workload_argv_error`, `invalid_ready_sentinel_error`, `state_root_unavailable`, `supervisor_bootstrap_error`, `handle_state_create_error`, `handle_log_create_error`, `current_directory_error`, `initial_meta_create_error`, `json_write_error`, `status_log_read_error`, `status_write_error`, `read_meta_error`, `read_rc_error`, `emit_output_separator`, `inconsistent_state_error`, `corrupt_state_error`, `format_status_header`, `format_done_header`, `workload_state`, `read_state_root_error`, `read_state_entry_error`, `emit_json_list_summaries`, `emit_text_list_summaries`, `format_list_summary`, `format_optional_rc`, `unknown_handle_error` | These produce user-facing text, JSON lines, list/status output, or error messages. |
| `src/state.rs` | `orchestration` | `state_root_from_env_values`, `create_handle_state`, `write_meta_atomic`, `read_meta`, `write_rc_atomic`, `read_rc`, `atomic_write`, `capture_caller_chain`, `read_proc_stat` | These sequence named validation/access/parse/format helpers and persistence operations. |
| `src/state.rs` | `validator` | `select_state_root_env`, `non_empty_env_value`, `atomic_parent`, `atomic_file_name` | These accept/reject environment and atomic-write path invariants. |
| `src/state.rs` | `mapper` | `StatePaths::new`, `CgroupMeta::subreaper_only`, `Meta::new`, `Meta::touch`, `RunOutput::new`, `ListSummary::from_meta`, `state_root_path`, `caller_chain_entry` | These map accepted inputs into state paths, metadata, summaries, and caller-chain rows. |
| `src/state.rs` | `accessor` | `unix_ms`, `state_root`, `fill_getrandom`, `create_log`, `open_log_append`, `open_read_no_follow`, `read_meta_bytes`, `read_rc_text`, `read_file_bytes`, `read_file_text`, `read_boot_id`, `read_proc_stat_text` | These retrieve time, environment, random bytes, files, and proc text. |
| `src/state.rs` | `formatter` | `generate_handle`, `format_meta_bytes`, `format_rc_bytes`, `atomic_temp_path` | These format handles, persisted JSON/rc bytes, and temporary filenames. |
| `src/state.rs` | `parser` | `parse_meta_bytes`, `parse_rc_text`, `parse_proc_stat` | These parse JSON, rc text, and `/proc/<pid>/stat`. |
| `src/guard.rs` | `accessor` | `AttachedGuard::capture`, `AttachedGuard::startup_ppid` | These retrieve or expose parent PID state. |
| `src/guard.rs` | `validator` | `AttachedGuard::validate`, `validate_parent_pair` | These accept/reject parent-stability invariants. |
| `src/supervisor.rs` | `orchestration` | `fork_supervisor`, `daemonization_child`, `redirect_stdio_to_devnull`, `run_supervisor`, `set_private_umask`, `persist_supervisor_meta_best_effort`, `set_subreaper`, `spawn_workload`, `workload_child`, `set_workload_process_group`, `enroll_workload_in_cgroup`, `redirect_workload_output`, `redirect_workload_stdin`, `close_workload_output_writes`, `exec_workload`, `unblock_sigchld`, `write_errno_and_exit`, `write_error_bytes_and_exit`, `set_nonblocking`, `close_fd`, `Sigchld::new`, `Sigchld::drain`, `Sigchld::drop`, `event_loop`, `dispatch_ready_pollfds`, `EventLoop::dispatch_poll_key`, `EventLoop::handle_sigchld`, `EventLoop::handle_cgroup_event`, `EventLoop::read_stdout`, `EventLoop::handle_stdout_chunks`, `EventLoop::handle_stdout_bytes`, `EventLoop::close_stdout_if_closed`, `EventLoop::read_stderr`, `EventLoop::write_stderr_chunks`, `EventLoop::close_stderr_if_closed`, `EventLoop::read_exec_error`, `EventLoop::handle_exec_error_read`, `EventLoop::record_exec_error_chunks`, `EventLoop::close_exec_error_if_closed`, `EventLoop::record_exec_error_read_failure`, `EventLoop::reap_children`, `EventLoop::record_root_status`, `EventLoop::close_root_pidfd`, `EventLoop::maybe_finish`, `EventLoop::persist_completion_and_delivery`, `EventLoop::record_ready_sentinel`, `EventLoop::record_exit_completion`, `EventLoop::record_supervisor_error_in_loop`, `record_supervisor_error`, `sync_optional_log`, `persist_meta_with_delivery`, `EventLoop::drop` | These sequence syscalls, fd setup, poll dispatch, reads, reaping, persistence, and delivery over named helpers. |
| `src/supervisor.rs` | `validator` | `validate_argv`, `validate_cstring_argv` | These accept/reject workload argv invariants. |
| `src/supervisor.rs` | `predicate` | `SentinelMatcher::push_stdout`, `SentinelMatcher::matches`, `EventLoop::stdout_reaches_sentinel`, `EventLoop::output_closed`, `EventLoop::should_exit`, `spawn_error_complete`, `exit_completion_ready`, `exit_completion_reason` | These answer readiness, completion, and exit-reason questions. |
| `src/supervisor.rs` | `mapper` | `supervisor_meta`, `apply_cgroup_setup_meta`, `apply_spawn_metadata`, `map_sentinel_matcher`, `event_loop_state`, `event_loop_exit_code`, `argv_to_cstrings`, `map_argv_to_cstrings`, `validated_arg_to_cstring`, `workload_spawn`, `current_pid`, `argv_pointers`, `make_pipe`, `available_read`, `finish_decision`, `apply_root_status_metadata`, `apply_ready_sentinel_metadata`, `apply_exit_completion_metadata`, `apply_supervisor_error_metadata`, `status_to_root_status`, `signal_to_shell_rc` | These transform inputs/statuses into supervisor state, argv, poll, completion, or metadata shapes. |
| `src/supervisor.rs` | `accessor` | `open_supervisor_log`, `pidfd_open`, `last_errno`, `read_available`, `read_fd_chunk` | These retrieve logs, pidfds, errno, and currently available fd bytes. |
| `src/supervisor.rs` | `formatter` | `open_log_failed_message`, `subreaper_failed_message`, `signalfd_failed_message`, `spawn_failed_message`, `invalid_sentinel_after_fork_message`, `errno_bytes`, `exec_error_message`, `spawn_error_message_for_completion` | These produce error text or wire bytes. |
| `src/supervisor.rs` | `parser` | `parse_sentinel_regex`, `exec_error_errno` | These parse regex patterns and exec-error bytes. |
| `src/supervisor.rs` | `filter` | `poll_entries`, `push_optional_poll_entry`, `poll_entry`, `readable_events`, `cgroup_inotify_fd`, `pollfds_for_entries`, `poll_until_ready` | These select and shape pollable fd readiness surfaces. |
| `src/cgroup.rs` | `orchestration` | `ActiveCgroup::drain_inotify`, `ActiveCgroup::drop`, `setup`, `try_setup`, `open_raw`, `setup_inotify`, `write_pid_to_procs_fd`, `remove_child_cgroup`, `close_fd` | These sequence cgroup setup/teardown, fd operations, cleanup, and PID writes over named helpers. |
| `src/cgroup.rs` | `validator` | `path_cstring`, `validate_nonnegative_pid` | These accept/reject path and PID invariants. |
| `src/cgroup.rs` | `mapper` | `subreaper_only_setup`, `current_cgroup_path`, `child_cgroup_path`, `cgroup_procs_path`, `cgroup_events_path`, `active_cgroup`, `cgroup_v2_meta` | These map cgroup inputs into paths, setup metadata, or active cgroup state. |
| `src/cgroup.rs` | `accessor` | `ActiveCgroup::procs_fd`, `ActiveCgroup::inotify_fd`, `ActiveCgroup::populated`, `ActiveCgroup::live_pids`, `open_raw_cstring`, `read_cgroup_events`, `read_cgroup_procs`, `cgroup_disabled`, `read_mountinfo_text`, `read_self_cgroup_text`, `open_cgroup_procs`, `open_cgroup_events`, `create_inotify_fd`, `add_inotify_watch`, `write_fd_all` | These retrieve cgroup fds, files, environment switches, and syscall results. |
| `src/cgroup.rs` | `formatter` | `path_display_string`, `format_pid_line`, `format_valid_pid_line` | These format path display text and cgroup PID write bytes. |
| `src/cgroup.rs` | `parser` | `parse_cgroup_pid_lines`, `parse_cgroup_pid_line`, `parse_proc_self_cgroup_v2_entry`, `parse_mountinfo_cgroup2_mount`, `unescape_mountinfo`, `parse_cgroup_events_populated` | These parse cgroup/proc/mountinfo text into structured values. |
| `src/delivery.rs` | `orchestration` | `notify`, `run_notify_command` | These sequence request construction, external command execution, and result handling. |
| `src/delivery.rs` | `accessor` | `delivery_binary` | Retrieves the configured delivery binary from the environment. |
| `src/delivery.rs` | `mapper` | `notify_request`, `delivery_meta_from_status`, `delivery_meta_from_error`, `attempted_delivery_meta` | These map notify inputs and process results into request/metadata structures. |
| `src/delivery.rs` | `formatter` | `notify_args`, `path_arg`, `delivery_signal_error` | These format notify CLI argv and signal-error text. |

## Adapter declarations

```yaml
adapter_declarations:
  - component: src/delivery.rs
    role: adapter
    Translates:
      - agent-runner-notify-cli-contract
```

No other adapter is declared. The delivery module translates the stable external notify CLI contract; other modules implement the spooler itself.

## Intrinsic-surface declarations

```yaml
intrinsic_surface_declarations:
  - component: WU-C spooler component
    role: intrinsic-surface
    Domain: linux_spooler_kernel_surface
    Owns:
      - attached_parent_ppid_guard
      - double_fork_session_and_workload_spawn_syscalls
      - child_reaping_pidfd_signalfd_poll_supervision
      - cgroup_v2_membership_events_and_live_process_set
      - no_follow_atomic_spooler_state_files
  - component: WU-C spooler component
    role: intrinsic-surface
    Domain: spooler_state_metadata_surface
    Owns:
      - StatePaths
      - Meta
      - RunOutput
      - ListSummary
      - CompletionDeliveryMeta
      - CgroupMeta
      - state_root
      - generate_handle
      - create_handle_state
      - create_log
      - open_log_append
      - open_read_no_follow
      - write_meta_atomic
      - read_meta
      - write_rc_atomic
      - read_rc
      - capture_caller_chain
  - component: WU-C spooler component
    role: intrinsic-surface
    Domain: spooler_attached_guard_surface
    Owns:
      - AttachedGuard
      - validate_parent_pair
      - startup_ppid
      - attached_parent_validation_error
  - component: WU-C spooler component
    role: intrinsic-surface
    Domain: spooler_supervisor_launch_surface
    Owns:
      - SupervisorConfig
      - validate_argv
      - fork_supervisor
      - supervisor_event_loop
      - workload_spawn_and_reap
      - ready_sentinel_completion
  - component: WU-C spooler component
    role: intrinsic-surface
    Domain: spooler_cgroup_membership_surface
    Owns:
      - CgroupSetup
      - ActiveCgroup
      - setup
      - write_pid_to_procs_fd
      - cgroup_events_populated
      - cgroup_live_pids
```

Justification: WU-C is a Linux-first spooler, and the modules above are internal surfaces of that one component rather than separate product systems. `src/state.rs` is the shared state-and-metadata surface consumed by launcher, supervisor, cgroup, and delivery code. The guard, supervisor launch/event-loop, and cgroup membership surfaces are similarly coherent internal spooler domains. These declarations do not cover unrelated external contracts and do not create facade types; they document the intrinsic component surfaces already present in the implementation. The agent-runner notify CLI remains the separate adapter declaration above.
