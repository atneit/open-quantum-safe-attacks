//use liboqs_rs_bindings as oqs;

use log::debug;
use structopt::StructOpt;

mod attack;

#[derive(StructOpt, Debug)]
#[structopt(name = "command")]
/// the stupid content tracker
enum Command {
    /// Known attacks
    Attack(attack::AttackOptions),
}

#[derive(StructOpt, Debug)]
#[structopt(name = "aoqs-afw")]
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
    };

    Ok(())
}
