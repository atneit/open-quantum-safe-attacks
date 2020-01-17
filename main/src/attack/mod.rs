mod memcmp_frodo;

use liboqs_rs_bindings::frodokem::{FrodoKem1344aes, FrodoKem640aes};
use log_derive::logfn_inputs;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "type")]
pub enum Attacks {
    /// Run the MEMCPY attack against FrodoKEM640AES
    MemcmpFrodoBaseline {
        #[structopt(subcommand, name = "frodo-params")]
        params: FrodoParams,

        /// Number of warmup iterations to run before starting sampling
        #[structopt(short, long)]
        warmup: usize,

        /// Number of samples to run
        #[structopt(short, long)]
        samples: usize,

        /// Measurment source, either external, internal or oracle
        #[structopt(short, long)]
        measure_source: memcmp_frodo::MeasureSource,
    },
    MemcmpFrodoFindE {
        #[structopt(subcommand, name = "frodo-params")]
        params: FrodoParams,

        /// Number of warmup iterations to run before starting sampling
        #[structopt(short, long)]
        warmup: usize,

        /// Number of iterations to measure before making a decision.
        #[structopt(short, long)]
        iterations: usize,

        /// Measurment source, either external, internal or oracle
        #[structopt(short, long)]
        measure_source: memcmp_frodo::MeasureSource,
    },
}

#[derive(StructOpt, Debug)]
#[structopt(name = "frodo-params")]
pub enum FrodoParams {
    FrodoKem640aes,
    FrodoKem1344aes,
}

#[derive(StructOpt, Debug)]
pub struct AttackOptions {
    #[structopt(subcommand)]
    /// Select attack variant
    attack: Attacks,
}

#[logfn_inputs(Trace)]
pub fn run(options: AttackOptions) -> Result<(), String> {
    match options.attack {
        Attacks::MemcmpFrodoBaseline {
            params,
            samples,
            warmup,
            measure_source,
        } => {
            let f = match params {
                FrodoParams::FrodoKem640aes => {
                    memcmp_frodo::baseline_memcmp_frodo::<FrodoKem640aes>
                }
                FrodoParams::FrodoKem1344aes => {
                    memcmp_frodo::baseline_memcmp_frodo::<FrodoKem1344aes>
                }
            };

            f(samples, warmup, measure_source)
        }
        Attacks::MemcmpFrodoFindE {
            params,
            warmup,
            iterations,
            measure_source,
        } => {
            let f = match params {
                FrodoParams::FrodoKem640aes => memcmp_frodo::find_e::<FrodoKem640aes>,
                FrodoParams::FrodoKem1344aes => memcmp_frodo::find_e::<FrodoKem1344aes>,
            };

            f(warmup, iterations, measure_source)
        }
    }
}
