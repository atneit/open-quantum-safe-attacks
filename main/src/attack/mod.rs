mod memcmp_frodo;

use log_derive::logfn_inputs;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
pub enum Attacks {
    /// Run the MEMCPY attack against FrodoKEM640AES
    MemcmpFrodoKEM640AES { samples: usize, warmup: usize },
}

#[derive(StructOpt, Debug)]
pub struct AttackOptions {
    #[structopt(short, long)]
    /// dummy argument
    dummy: bool,

    #[structopt(subcommand)]
    /// Select attack variant
    attack: Attacks,
}

#[logfn_inputs(Trace)]
pub fn run(options: AttackOptions) -> Result<(), String> {
    match options.attack {
        Attacks::MemcmpFrodoKEM640AES { samples, warmup } => {
            memcmp_frodo::memcmp_frodo640aes(samples, warmup)?
        }
    }

    Ok(())
}
