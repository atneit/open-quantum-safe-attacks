use std::{fs::File, io::BufWriter};

use liboqs_rs_bindings as oqs;
use log::info;
use log_derive::logfn_inputs;
use oqs::{
    bike::{BikeL1, BikeL3},
    hqc::{Hqc128, Hqc192, Hqc256},
};
use structopt::StructOpt;

use crate::utils::StrErr;

use self::{
    attack::SimulateAttackOptions,
    bike_attack::BikeAttackOptions,
    bike_distance_spectrum::BikeDistanceSpectrumOptions,
    bike_error_weight::{BikeErrorWeightSearchOptions, BikeErrorWeightTestOptions},
    bike_eval_distinguisher::BikeEvalDistinguisherOptions,
    histogram_rejections::HistogramRejectionsOptions,
    iteration_timings::IterationTimingsOptions,
    plaintexts::CollectPlaintextsOptions,
    verify_timing_attack::VerifyTimingAttackOptions,
};

mod attack;
mod bike_attack;
mod bike_distance_spectrum;
mod bike_error_weight;
mod bike_eval_distinguisher;
mod histogram_rejections;
mod iteration_timings;
mod plaintexts;
mod verify_timing_attack;

#[derive(StructOpt, Debug)]
pub enum BikeParams {
    KemL1,
    KemL3,
}

#[derive(StructOpt, Debug)]
pub enum HqcParams {
    Kem128,
    Kem192,
    Kem256,
}

// Choose which algorithm to run
#[derive(StructOpt, Debug)]
pub enum RejectionSamplingAlgorithms {
    // Select the BIKE algorithm
    Bike(BikeParams),
    // Select the HQC algorithm
    Hqc(HqcParams),
}

#[derive(StructOpt, Debug)]
#[structopt(name = "type")]
pub enum Subroutine {
    /// Make a histogram of the distribution of the number of iterations in the rejection sampling algorithm, for the specified algorithm
    HistogramRejections {
        #[structopt(subcommand, name = "kem-algs")]
        alg: RejectionSamplingAlgorithms,

        #[structopt(flatten)]
        opt: HistogramRejectionsOptions,
    },
    /// Find pairs of plaintext that results in min and max amount of iterations and record the wall-clock time required by the decapsulation mechanism. Run for all supported algorithms.
    VerifyTimingAttacks {
        #[structopt(flatten)]
        opt: VerifyTimingAttackOptions,
    },
    /// Run through the generic attack steps for the selected algorithm, as detailed in [TODO]. This is only for verifying the existence of a non-constant time rejection sampling algorithm in the selected algorithm.
    SimulateAttack {
        #[structopt(subcommand, name = "kem-algs")]
        alg: RejectionSamplingAlgorithms,

        #[structopt(flatten)]
        opt: SimulateAttackOptions,
    },
    /// Collects as many candidate plaintexts as possible and sorts them according to the number of required iterations in the rejection sampling algorithm
    CollectPlaintexts {
        #[structopt(subcommand, name = "hqc-algs")]
        alg: RejectionSamplingAlgorithms,

        #[structopt(flatten)]
        opt: CollectPlaintextsOptions,
    },
    /// Measures the timings of all plaintexts in specified DB. Outputs recodings in CSV format.
    IterationTimings {
        #[structopt(subcommand, name = "hqc-algs")]
        alg: RejectionSamplingAlgorithms,

        #[structopt(flatten)]
        opt: IterationTimingsOptions,
    },
    /// Attempts to find a suitable error_weight to use with the rejection sampling attack on BIKE
    ///
    /// Note the distinction that the entire error weight is located in e_1 instead of spread out over e_0 and e_1.
    /// The impact of this is what this command is used to simulate.
    BikeErrorWeightSearch {
        #[structopt(subcommand, name = "bike-algs")]
        alg: BikeParams,

        #[structopt(flatten)]
        opt: BikeErrorWeightSearchOptions,
    },
    /// Evaluates the decoding failure rate of a choosen error weight
    ///
    /// Note the distinction that the entire error weight is located in e_1 instead of spread out over e_0 and e_1.
    /// The impact of this is what this command is used to simulate.
    BikeErrorWeightTest {
        #[structopt(subcommand, name = "bike-algs")]
        alg: BikeParams,

        #[structopt(flatten)]
        opt: BikeErrorWeightTestOptions,
    },
    /// Rejection sampling attack on BIKE
    BikeAttack {
        #[structopt(subcommand, name = "bike-algs")]
        alg: BikeParams,

        #[structopt(flatten)]
        opt: BikeAttackOptions,
    },
    /// Evaluate the timing distinguisher for the current BIKE implementation
    BikeEvalDistinguisher {
        #[structopt(subcommand, name = "bike-algs")]
        alg: BikeParams,

        #[structopt(flatten)]
        opt: BikeEvalDistinguisherOptions,
    },
    /// Calculate distance spectrum of secret key
    BikeDistanceSpectrum {
        #[structopt(subcommand, name = "bike-algs")]
        alg: BikeParams,

        #[structopt(flatten)]
        opt: BikeDistanceSpectrumOptions,
    },
}

#[logfn_inputs(Debug)]
pub fn run(sub: Subroutine) -> Result<(), String> {
    match sub {
        Subroutine::HistogramRejections { alg, opt } => {
            let f = match alg {
                RejectionSamplingAlgorithms::Bike(BikeParams::KemL1) => {
                    histogram_rejections::run::<BikeL1>
                }
                RejectionSamplingAlgorithms::Bike(BikeParams::KemL3) => {
                    histogram_rejections::run::<BikeL3>
                }
                RejectionSamplingAlgorithms::Hqc(HqcParams::Kem128) => {
                    histogram_rejections::run::<Hqc128>
                }
                RejectionSamplingAlgorithms::Hqc(HqcParams::Kem192) => {
                    histogram_rejections::run::<Hqc192>
                }
                RejectionSamplingAlgorithms::Hqc(HqcParams::Kem256) => {
                    histogram_rejections::run::<Hqc256>
                }
            };
            f(opt)
        }
        Subroutine::VerifyTimingAttacks { opt } => {
            let mut save = None;
            if let Some(path) = &opt.save {
                info!("(Re)creating {:?} to serve as save target!", path);
                let mut writer =
                    csv::Writer::from_writer(BufWriter::new(File::create(path).strerr()?));
                writer
                    .write_record(&["algorithm", "iterations", "clock cycles"])
                    .strerr()?;
                save.replace(writer);
            }
            verify_timing_attack::run::<BikeL1, _>(&opt, &mut save)?;
            verify_timing_attack::run::<BikeL3, _>(&opt, &mut save)?;
            verify_timing_attack::run::<Hqc128, _>(&opt, &mut save)?;
            verify_timing_attack::run::<Hqc192, _>(&opt, &mut save)?;
            verify_timing_attack::run::<Hqc256, _>(&opt, &mut save)?;

            Ok(())
        }
        Subroutine::SimulateAttack { alg, opt } => {
            let f = match alg {
                RejectionSamplingAlgorithms::Bike(BikeParams::KemL1) => attack::run::<BikeL1>,
                RejectionSamplingAlgorithms::Bike(BikeParams::KemL3) => attack::run::<BikeL3>,
                RejectionSamplingAlgorithms::Hqc(HqcParams::Kem128) => attack::run::<Hqc128>,
                RejectionSamplingAlgorithms::Hqc(HqcParams::Kem192) => attack::run::<Hqc192>,
                RejectionSamplingAlgorithms::Hqc(HqcParams::Kem256) => attack::run::<Hqc256>,
            };
            f(opt)
        }
        Subroutine::CollectPlaintexts { alg, opt } => {
            let f = match alg {
                RejectionSamplingAlgorithms::Bike(BikeParams::KemL1) => plaintexts::run::<BikeL1>,
                RejectionSamplingAlgorithms::Bike(BikeParams::KemL3) => plaintexts::run::<BikeL3>,
                RejectionSamplingAlgorithms::Hqc(HqcParams::Kem128) => plaintexts::run::<Hqc128>,
                RejectionSamplingAlgorithms::Hqc(HqcParams::Kem192) => plaintexts::run::<Hqc192>,
                RejectionSamplingAlgorithms::Hqc(HqcParams::Kem256) => plaintexts::run::<Hqc256>,
            };
            f(opt)
        }
        Subroutine::IterationTimings { alg, opt } => {
            let f = match alg {
                RejectionSamplingAlgorithms::Bike(BikeParams::KemL1) => {
                    iteration_timings::run::<BikeL1>
                }
                RejectionSamplingAlgorithms::Bike(BikeParams::KemL3) => {
                    iteration_timings::run::<BikeL3>
                }
                RejectionSamplingAlgorithms::Hqc(HqcParams::Kem128) => {
                    iteration_timings::run::<Hqc128>
                }
                RejectionSamplingAlgorithms::Hqc(HqcParams::Kem192) => {
                    iteration_timings::run::<Hqc192>
                }
                RejectionSamplingAlgorithms::Hqc(HqcParams::Kem256) => {
                    iteration_timings::run::<Hqc256>
                }
            };
            f(opt)
        }
        Subroutine::BikeErrorWeightSearch { alg, opt } => {
            let f = match alg {
                BikeParams::KemL1 => bike_error_weight::run_search::<BikeL1>,
                BikeParams::KemL3 => bike_error_weight::run_search::<BikeL3>,
            };
            f(opt)
        }
        Subroutine::BikeErrorWeightTest { alg, opt } => {
            let f = match alg {
                BikeParams::KemL1 => bike_error_weight::run_test::<BikeL1>,
                BikeParams::KemL3 => bike_error_weight::run_test::<BikeL3>,
            };
            f(opt)
        }
        Subroutine::BikeAttack { alg, opt } => {
            let f = match alg {
                BikeParams::KemL1 => bike_attack::run::<BikeL1>,
                BikeParams::KemL3 => bike_attack::run::<BikeL3>,
            };
            f(opt)
        }
        Subroutine::BikeEvalDistinguisher { alg, opt } => {
            let f = match alg {
                BikeParams::KemL1 => bike_eval_distinguisher::run::<BikeL1>,
                BikeParams::KemL3 => bike_eval_distinguisher::run::<BikeL3>,
            };
            f(opt)
        }
        Subroutine::BikeDistanceSpectrum { alg, opt } => {
            let f = match alg {
                BikeParams::KemL1 => bike_distance_spectrum::run::<BikeL1>,
                BikeParams::KemL3 => bike_distance_spectrum::run::<BikeL3>,
            };
            f(opt)
        }
    }
}
