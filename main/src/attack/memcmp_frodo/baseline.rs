use super::modify_and_measure::*;
use crate::attack::memcmp_frodo::MeasureSource;
use crate::utils::save_to_csv;
use crate::utils::{Rec, Recorder};
use liboqs_rs_bindings as oqs;
use log::{info, Level};
use log_derive::logfn_inputs;
use oqs::frodokem::*;
use oqs::Result;
use std::path::PathBuf;

#[logfn_inputs(Trace)]
pub fn baseline_memcmp_frodo<FRODO: FrodoKem>(
    samples: u64,
    warmup: u64,
    measure_source: MeasureSource,
    save: Option<PathBuf>,
) -> Result {
    info!(
        "Launching the baseline routine against {} MEMCMP vulnerability.",
        FRODO::name()
    );
    let mut public_key = FRODO::PublicKey::new();
    let mut secret_key = FRODO::SecretKey::new();
    let mut ciphertext = FRODO::Ciphertext::new();

    info!("Generating keypair");
    FRODO::keypair(&mut public_key, &mut secret_key)?;

    info!("Encapsulating shared secret and generating ciphertext");
    let mut shared_secret_e = FRODO::SharedSecret::new();
    let mut shared_secret_d = FRODO::SharedSecret::new();
    FRODO::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;

    let maxmod = error_correction_limit::<FRODO>() * 2;

    info!("Warming up with {} decaps", warmup);
    let low = mod_measure::<FRODO, _>(
        maxmod,
        0,
        warmup,
        &measure_source,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
        Recorder::minval(),
    )?
    .aggregated_value()?;
    info!("Aggregated (median) time is {}", low);

    let mut recorders = vec![];

    for t in 0..10 {
        info!("Encapsulating shared secret and generating ciphertext");
        FRODO::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;

        info!(
            "(NOMOD) Sampling {} decaps without modifications, using \"{:?}\" as source of measurment.",
            samples, measure_source
        );
        let rec_unmodified = mod_measure::<FRODO, _>(
            0,
            0,
            samples,
            &measure_source,
            &mut ciphertext,
            &mut shared_secret_d,
            &mut secret_key,
            Recorder::saveall(format!("{}-NOMOD", t), None),
        )?;
        let low = rec_unmodified.aggregated_value()?;
        info!("Aggregated (median) time is {}", low);
        rec_unmodified.log(Level::Debug);

        recorders.push(rec_unmodified);

        for i in &[63] {
            // create a histogram with default config

            info!(
                "(MINOR) Sampling {} decaps, modifying C[{}] by adding 1.",
                samples, i
            );
            let rec_modified_minor = mod_measure::<FRODO, _>(
                1,
                *i,
                samples,
                &measure_source,
                &mut ciphertext,
                &mut shared_secret_d,
                &mut secret_key,
                Recorder::saveall(format!("{}-MINOR[{}]", t, i), None),
            )?;
            let low = rec_modified_minor.min()?;
            let median = rec_modified_minor.aggregated_value()?;
            info!("Aggregated (median) time is {}, median: {}", low, median);

            info!(
                "(MAJOR) Sampling {} decaps, modifying C[{}] by adding {}.",
                samples, i, maxmod
            );
            let rec_modified_major = mod_measure::<FRODO, _>(
                maxmod,
                *i,
                samples,
                &measure_source,
                &mut ciphertext,
                &mut shared_secret_d,
                &mut secret_key,
                Recorder::saveall(format!("{}-MAJOR[{}]", t, i), None),
            )?;
            let low = rec_modified_minor.min()?;
            let median = rec_modified_minor.aggregated_value()?;
            info!("Aggregated (median) time is {}, median: {}", low, median);

            rec_modified_minor.log(Level::Debug);
            rec_modified_major.log(Level::Debug);

            recorders.push(rec_modified_minor);
            recorders.push(rec_modified_major);
        }
    }

    if let Some(path) = save {
        info!("Saving measurments to file {:?}", path);
        save_to_csv(&path, &recorders)?;
    }

    info!("Finished!");
    Ok(())
}
