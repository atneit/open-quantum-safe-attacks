mod memcmp_frodo;

use liboqs_rs_bindings as oqs;
use log_derive::logfn_inputs;
use memcmp_frodo::FrodoParams;
use oqs::frodokem::{FrodoKem1344aes, FrodoKem640aes};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "type")]
pub enum Attacks {
    /// Run the baseline analysis against FrodoKEM MEMCMP vulnerability
    MemcmpFrodoBaseline {
        #[structopt(subcommand, name = "frodo-params")]
        params: FrodoParams,

        /// Number of warmup iterations to run before starting sampling
        #[structopt(short, long)]
        warmup: u64,

        /// Number of samples to run
        #[structopt(short, long)]
        samples: u64,

        /// Save measurments to a csv file
        #[structopt(short("f"), long)]
        save: Option<PathBuf>,

        /// Measurment source, either external, internal or oracle
        #[structopt(short, long)]
        measure_source: memcmp_frodo::MeasureSource,
    },
    /// Run the MEMCPY attack against FrodoKEM
    MemcmpFrodoCrackS {
        #[structopt(subcommand, name = "frodo-params")]
        params: FrodoParams,

        /// Number of warmup iterations to run before starting sampling
        #[structopt(short, long)]
        warmup: u64,

        /// Number of iterations to measure when profiling.
        #[structopt(short, long)]
        profiling: u64,

        /// Number of iterations to measure before making a decision.
        #[structopt(short, long)]
        iterations: u64,

        /// Save profiling measurments to a csv file
        #[structopt(short("f"), long("save-profiling"))]
        save_to_file: Option<PathBuf>,

        /// Measurment source, either external, internal or oracle
        #[structopt(short, long)]
        measure_source: memcmp_frodo::MeasureSource,
    },
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
            save_to_file,
        } => {
            let f = match params {
                FrodoParams::FrodoKem640aes => memcmp_frodo::crack_s::<FrodoKem640aes>,
                FrodoParams::FrodoKem1344aes => memcmp_frodo::crack_s::<FrodoKem1344aes>,
            };

            f(warmup, iterations, profiling, measure_source, save_to_file)
        }
    }
}
