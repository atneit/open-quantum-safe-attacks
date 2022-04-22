mod fo_timing;
#[cfg(feature = "rapl")]
mod rapl;
mod rejection_sampling;

use liboqs_rs_bindings as oqs;
use log_derive::logfn_inputs;
use oqs::{
    frodokem::{FrodoKem1344aes, FrodoKem640aes},
    kyber::{Kyber1024, Kyber1024_90S, Kyber512, Kyber512_90S, Kyber768, Kyber768_90S},
};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
pub enum FrodoParams {
    // Select the 640 AES paramter set
    Kem640aes,
    // Select the 1344 AES paramter set
    Kem1344aes,
}

#[derive(StructOpt, Debug)]
pub enum KyberParams {
    // Select the 512 paramter set
    Kem512,
    // Select the 512 paramter set, 90's version
    Kem512_90S,
    // Select the 768 paramter set
    Kem768,
    // Select the 768 paramter set, 90's version
    Kem768_90S,
    // Select the 1024 paramter set
    Kem1024,
    // Select the 1024 paramter set, 90's version
    Kem1024_90S,
}

// Choose which algorithm to run
#[derive(StructOpt, Debug)]
pub enum KemAlg {
    // Select the FrodoKEM algorithm
    Frodo(FrodoParams),
    // Select the Kyber algorithm
    Kyber(KyberParams),
}

#[derive(StructOpt, Debug)]
#[structopt(name = "type")]
pub enum Attacks {
    /// Run a basic baseline analysis to find vulnerable implementations of the Fujisaki
    /// Okamoto transform employed by many KEMs
    FOBaseline {
        #[structopt(subcommand, name = "kem-algs")]
        params: KemAlg,

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
        measure_source: fo_timing::MeasureSource,
    },
    /// Run the MEMCPY attack against the FrodoKEM implementation. See sources for liboqs to know
    /// if your version is patched aginst this vulnerability or not.
    MemcmpFrodoCrackS {
        #[structopt(subcommand, name = "frodo-alg")]
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
        measure_source: fo_timing::MeasureSource,
    },
    /// Run a variant of the baseline analysis better geared towards finding
    /// small runtime differences due to cache and other non-constant time behaviour.
    CacheAttackFOBaseline {
        #[structopt(subcommand, name = "kem-alg")]
        params: KemAlg,

        /// Number of warmup iterations to run before starting sampling
        #[structopt(short, long)]
        warmup: u64,

        /// Number of samples to test, per encapsulation
        #[structopt(short, long)]
        samples: u64,

        /// Number of encapsulations to test, per key
        #[structopt(short("e"), long)]
        nencaps: u64,

        /// Number of keys to test
        #[structopt(short("k"), long)]
        nkeys: u64,

        /// Save measurments to a csv file
        #[structopt(short("f"), long)]
        save: Option<PathBuf>,

        /// Measurment source, either external, internal or oracle
        #[structopt(short, long)]
        measure_source: fo_timing::MeasureSource,
    },
    /// Run a muiltipoint profiling of the supported algorithms
    FOMultipointProfiling {
        #[structopt(subcommand, name = "kem-alg")]
        params: KemAlg,

        /// Number of warmup iterations to run before starting sampling
        #[structopt(short, long)]
        warmup: u64,

        /// Number of samples to test, per encapsulation
        #[structopt(short, long)]
        samples: u64,

        /// Number of encapsulations to test, per key
        #[structopt(short("e"), long)]
        nencaps: u64,

        /// Number of keys to test
        #[structopt(short("k"), long)]
        nkeys: u64,

        /// Save measurments to a csv file
        #[structopt(short("f"), long)]
        save: Option<PathBuf>,
    },
    /// Run an attack on the Rejection Sampling techniques used by BIKE and HQC
    RejectionSampling {
        /// Select a subroutine to run
        #[structopt(subcommand, name = "subroutine")]
        sub: rejection_sampling::Subroutine,
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
        Attacks::FOBaseline {
            params,
            samples,
            warmup,
            measure_source,
            save,
        } => {
            let f = match params {
                KemAlg::Frodo(FrodoParams::Kem640aes) => {
                    fo_timing::fujisaki_okamoto_baseline::<FrodoKem640aes>
                }
                KemAlg::Frodo(FrodoParams::Kem1344aes) => {
                    fo_timing::fujisaki_okamoto_baseline::<FrodoKem1344aes>
                }
                KemAlg::Kyber(KyberParams::Kem512) => {
                    fo_timing::fujisaki_okamoto_baseline::<Kyber512>
                }
                KemAlg::Kyber(KyberParams::Kem512_90S) => {
                    fo_timing::fujisaki_okamoto_baseline::<Kyber512_90S>
                }
                KemAlg::Kyber(KyberParams::Kem768) => {
                    fo_timing::fujisaki_okamoto_baseline::<Kyber768>
                }
                KemAlg::Kyber(KyberParams::Kem768_90S) => {
                    fo_timing::fujisaki_okamoto_baseline::<Kyber768_90S>
                }
                KemAlg::Kyber(KyberParams::Kem1024) => {
                    fo_timing::fujisaki_okamoto_baseline::<Kyber1024>
                }
                KemAlg::Kyber(KyberParams::Kem1024_90S) => {
                    fo_timing::fujisaki_okamoto_baseline::<Kyber1024_90S>
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
                FrodoParams::Kem640aes => fo_timing::frodo_crack_s::<FrodoKem640aes>,
                FrodoParams::Kem1344aes => fo_timing::frodo_crack_s::<FrodoKem1344aes>,
            };

            f(warmup, iterations, profiling, measure_source, save_to_file)
        }
        Attacks::CacheAttackFOBaseline {
            params,
            warmup,
            nencaps,
            nkeys,
            samples,
            save,
            measure_source,
        } => {
            let f = match params {
                KemAlg::Frodo(FrodoParams::Kem640aes) => {
                    fo_timing::fujisaki_okamoto_baseline_cache::<FrodoKem640aes>
                }
                KemAlg::Frodo(FrodoParams::Kem1344aes) => {
                    fo_timing::fujisaki_okamoto_baseline_cache::<FrodoKem1344aes>
                }
                KemAlg::Kyber(KyberParams::Kem512) => {
                    fo_timing::fujisaki_okamoto_baseline_cache::<Kyber512>
                }
                KemAlg::Kyber(KyberParams::Kem512_90S) => {
                    fo_timing::fujisaki_okamoto_baseline_cache::<Kyber512_90S>
                }
                KemAlg::Kyber(KyberParams::Kem768) => {
                    fo_timing::fujisaki_okamoto_baseline_cache::<Kyber768>
                }
                KemAlg::Kyber(KyberParams::Kem768_90S) => {
                    fo_timing::fujisaki_okamoto_baseline_cache::<Kyber768_90S>
                }
                KemAlg::Kyber(KyberParams::Kem1024) => {
                    fo_timing::fujisaki_okamoto_baseline_cache::<Kyber1024>
                }
                KemAlg::Kyber(KyberParams::Kem1024_90S) => {
                    fo_timing::fujisaki_okamoto_baseline_cache::<Kyber1024_90S>
                }
            };

            f(samples, nencaps, nkeys, warmup, measure_source, save)
        }
        Attacks::FOMultipointProfiling {
            params,
            warmup,
            samples,
            nencaps,
            nkeys,
            save,
        } => {
            let f = match params {
                KemAlg::Frodo(FrodoParams::Kem640aes) => {
                    fo_timing::fujisaki_okamoto_baseline_multipoint_profiling::<FrodoKem640aes>
                }
                KemAlg::Frodo(FrodoParams::Kem1344aes) => {
                    fo_timing::fujisaki_okamoto_baseline_multipoint_profiling::<FrodoKem1344aes>
                }
                KemAlg::Kyber(KyberParams::Kem512) => {
                    fo_timing::fujisaki_okamoto_baseline_multipoint_profiling::<Kyber512>
                }
                KemAlg::Kyber(KyberParams::Kem512_90S) => {
                    fo_timing::fujisaki_okamoto_baseline_multipoint_profiling::<Kyber512_90S>
                }
                KemAlg::Kyber(KyberParams::Kem768) => {
                    fo_timing::fujisaki_okamoto_baseline_multipoint_profiling::<Kyber768>
                }
                KemAlg::Kyber(KyberParams::Kem768_90S) => {
                    fo_timing::fujisaki_okamoto_baseline_multipoint_profiling::<Kyber768_90S>
                }
                KemAlg::Kyber(KyberParams::Kem1024) => {
                    fo_timing::fujisaki_okamoto_baseline_multipoint_profiling::<Kyber1024>
                }
                KemAlg::Kyber(KyberParams::Kem1024_90S) => {
                    fo_timing::fujisaki_okamoto_baseline_multipoint_profiling::<Kyber1024_90S>
                }
            };

            f(samples, nencaps, nkeys, warmup, save)
        }
        Attacks::RejectionSampling { sub } => rejection_sampling::run(sub),
    }
}
