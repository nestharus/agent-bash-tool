//! `agent-bash` — general-purpose always-background bash spooler for AI agents.
//!
//! See `docs/DESIGN.md` for the architecture. This is the scaffold entry point;
//! the spooler core (cgroup tree capture, detached supervisor, pidfd / sentinel
//! completion, attached-parent guard) is built per WU-C.

use clap::{Parser, Subcommand};

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
        /// marker (regex) instead of waiting for process exit.
        #[arg(long)]
        ready_sentinel: Option<String>,
        /// The command and its arguments (after `--`).
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Non-blocking status of a spooled job: RUNNING, or DONE rc=<n> + captured output.
    Status { handle: String },
    /// List spooled jobs owned by the calling agent's process tree.
    List,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Run { .. } | Command::Status { .. } | Command::List => {
            eprintln!("agent-bash: not yet implemented (scaffold). See docs/DESIGN.md / WU-C.");
            std::process::exit(70); // EX_SOFTWARE
        }
    }
}
