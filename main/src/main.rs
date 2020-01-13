//use liboqs_rs_bindings as oqs;

use log::debug;
use structopt::clap::Shell;
use structopt::StructOpt;

mod attack;
mod utils;

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
    #[structopt(short, long, default_value = "info")]
    /// Set log level to trace, debug, info, warn or error
    loglevel: log::Level,
    #[structopt(subcommand)]
    command: Command,
}

fn main() -> Result<(), String> {
    let matches = ProgramArgs::from_args();
    simple_logger::init_with_level(matches.loglevel).unwrap();
    debug!("command line arguments parsed: {:?}", matches);

    match matches.command {
        Command::Attack(opt) => attack::run(opt)?,
        Command::Completions { shell } => {
            let mut app = ProgramArgs::clap();
            app.gen_completions("oqs-afw", shell, "./");
        }
    };

    Ok(())
}
