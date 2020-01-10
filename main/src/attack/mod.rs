mod memcmp_frodo;

use log_derive::logfn_inputs;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
pub enum Attacks {
    /// Run the MEMCPY attack against FrodoKEM640AES
    MemcmpFrodoKEM640AES,
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
        Attacks::MemcmpFrodoKEM640AES => memcmp_frodo::memcmp_frodo640aes()?,
    }

    Ok(())
}
