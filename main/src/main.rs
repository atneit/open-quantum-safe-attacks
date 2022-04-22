#![feature(test, bench_black_box)]
#![feature(int_roundings)]

//use liboqs_rs_bindings as oqs;

use std::path::PathBuf;
use std::time::Duration;
use std::{panic, process};

use log::{debug, error};
use structopt::clap::Shell;
use structopt::StructOpt;

use crate::utils::setup_logging;

#[macro_use]
mod utils;
mod attack;

#[derive(StructOpt, Debug)]
#[structopt(name = "command")]
/// The libOQS Attack FrameWork (OQS-AFW)
enum Command {
    /// Known attacks
    Attack(attack::AttackOptions),
    /// Generate auto completions for all supported shells
    Completions {
        /// the shell to generate the auto completions file for. possible values: bash, fish, zsh, powershell & elvish
        shell: Shell,
    },
}
#[derive(StructOpt, Debug)]
#[structopt(name = "oqs-afw")]
struct ProgramArgs {
    /// Set log level to trace, debug, info, warn or error
    #[structopt(short, long, default_value("info"))]
    loglevel: log::Level,
    #[structopt(short("d"), long)]
    logdest: Option<PathBuf>,
    #[structopt(subcommand)]
    command: Command,
}

fn main() {
    // Let's make sure the entire program exits when a single thread panics
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        orig_hook(panic_info);
        process::exit(1);
    }));

    let matches = ProgramArgs::from_args();

    let _log_scope_guard = setup_logging(matches.loglevel, &matches.logdest);
    debug!("command line arguments parsed: {:?}", matches);

    let result = match matches.command {
        Command::Attack(opt) => attack::run(opt),
        Command::Completions { shell } => {
            let mut app = ProgramArgs::clap();
            app.gen_completions("oqs-afw", shell, "./");
            Ok(())
        }
    };

    if let Err(errmsg) = result {
        error!("Aborting due to error: {}", errmsg);
        std::process::exit(-1);
    }

    // Add a sleep for any progressbars to have time to disappear
    std::thread::sleep(Duration::from_millis(500));
}
