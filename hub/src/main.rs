// SPDX-License-Identifier: AGPL-3.0-or-later
//! `spacegoat-hub`: the command line in `cli.rs`, with the process's arguments and streams.

fn main() -> std::process::ExitCode {
    let code = spacegoat_hub::cli::run(
        std::env::args_os().skip(1),
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    std::process::ExitCode::from(code)
}
