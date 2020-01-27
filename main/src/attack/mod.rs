mod memcmp_frodo;

use liboqs_rs_bindings::frodokem::{FrodoKem1344aes, FrodoKem640aes};
use log_derive::logfn_inputs;
use std::path::PathBuf;
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

        /// Save measurments to a csv file
        #[structopt(short("f"), long)]
        save: Option<PathBuf>,

        /// Measurment source, either external, internal or oracle
        #[structopt(short, long)]
        measure_source: memcmp_frodo::MeasureSource,
    },
    MemcmpFrodoCrackS {
        #[structopt(subcommand, name = "frodo-params")]
        params: FrodoParams,

        /// Number of warmup iterations to run before starting sampling
        #[structopt(short, long)]
        warmup: usize,

        /// Number of iterations to measure when profiling.
        #[structopt(short, long)]
        profiling: usize,

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
            save,
        } => {
            let f = match params {
                FrodoParams::FrodoKem640aes => {
                    memcmp_frodo::baseline_memcmp_frodo::<FrodoKem640aes>
                }
                FrodoParams::FrodoKem1344aes => {
                    memcmp_frodo::baseline_memcmp_frodo::<FrodoKem1344aes>
                }
            };

            f(samples, warmup, measure_source, save)
        }
        Attacks::MemcmpFrodoCrackS {
            params,
            warmup,
            profiling,
            iterations,
            measure_source,
        } => {
            let f = match params {
                FrodoParams::FrodoKem640aes => memcmp_frodo::crack_s::<FrodoKem640aes>,
                FrodoParams::FrodoKem1344aes => memcmp_frodo::crack_s::<FrodoKem1344aes>,
            };

            f(warmup, iterations, profiling, measure_source)
        }
    }
}
