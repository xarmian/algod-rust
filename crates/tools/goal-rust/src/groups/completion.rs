//! `goal completion` — port of `../go-algorand/cmd/goal/completion.go`.

use std::process::ExitCode;

use clap::Subcommand;

use crate::unimplemented;

#[derive(Subcommand, Debug)]
pub enum CompletionCmd {
    /// Generate bash completion commands.
    Bash,
    /// Generate zsh completion commands.
    Zsh,
}

pub fn run(cmd: CompletionCmd) -> ExitCode {
    let leaf = match cmd {
        CompletionCmd::Bash => "bash",
        CompletionCmd::Zsh => "zsh",
    };
    unimplemented("completion", leaf)
}
