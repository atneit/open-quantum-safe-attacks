use super::modify_and_measure::*;
use crate::attack::fo_timing::MeasureSource;
use crate::utils::save_to_csv;
use crate::utils::{Rec, Recorder};
use liboqs_rs_bindings as oqs;
use log::{info, Level};
use log_derive::logfn_inputs;
use oqs::{InternalKemMeasurments, KemBuf, KemMeasure, Result};
use std::{cell::RefCell, path::PathBuf};

#[logfn_inputs(Trace)]
pub fn fujisaki_okamoto_baseline<KEM: KemMeasure>(
    samples: u64,
    warmup: u64,
    measure_source: MeasureSource,
    save: Option<PathBuf>,
) -> Result<()> {
    measure_source.prep_thread()?;

    let maxmod = KEM::error_correction_limit() * 2;

    info!(
        "Launching the baseline routine against {} MEMCMP vulnerability with maximum modification: {}.",
        KEM::NAME,
        maxmod
    );
    let mut ciphertext = KEM::Ciphertext::new();

    info!("Generating keypair");
    let (mut public_key, mut secret_key) = KEM::keypair()?;

    info!("Encapsulating shared secret and generating ciphertext");
    let mut shared_secret_e = KEM::SharedSecret::new();
    let mut shared_secret_d = KEM::SharedSecret::new();
    KEM::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;

    info!("Warming up with {} decaps", warmup);
    let low = mod_measure::<KEM, _>(
        maxmod,
        0,
        warmup,
        &measure_source,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
        Recorder::minval("warmup"),
    )?
    .aggregated_value()?;
    info!("Aggregated (mean) time is {}", low);

    let mut recorders = vec![];

    for encap_index in 0..1 {
        info!("Encapsulating shared secret and generating ciphertext");
        KEM::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;

        info!(
            "(NOMOD) Sampling {} decaps without modifications, using \"{:?}\" as source of measurment.",
            samples, measure_source
        );
        let rec_unmodified = mod_measure::<KEM, _>(
            0,
            0,
            samples,
            &measure_source,
            &mut ciphertext,
            &mut shared_secret_d,
            &mut secret_key,
            Recorder::saveall(format!("{}-NOMOD", encap_index), None),
        )?;
        let low = rec_unmodified.aggregated_value()?;
        info!("Aggregated (mean) time is {}", low);
        rec_unmodified.log(Level::Debug);

        recorders.push(rec_unmodified);

        #[allow(clippy::single_element_loop)]
        for i in &[63] {
            // create a histogram with default config

            info!(
                "(MINOR) Sampling {} decaps, modifying C[{}] by adding 1.",
                samples, i
            );
            let rec_modified_minor = mod_measure::<KEM, _>(
                1,
                *i,
                samples,
                &measure_source,
                &mut ciphertext,
                &mut shared_secret_d,
                &mut secret_key,
                Recorder::saveall(format!("{}-MINOR[{}]", encap_index, i), None),
            )?;
            let low = rec_modified_minor.min()?;
            let mean = rec_modified_minor.aggregated_value()?;
            info!("Aggregated (mean) time is {}, mean: {}", low, mean);

            info!(
                "(MAJOR) Sampling {} decaps, modifying C[{}] by adding {}.",
                samples, i, maxmod
            );
            let rec_modified_major = mod_measure::<KEM, _>(
                maxmod,
                *i,
                samples,
                &measure_source,
                &mut ciphertext,
                &mut shared_secret_d,
                &mut secret_key,
                Recorder::saveall(format!("{}-MAJOR[{}]", encap_index, i), None),
            )?;
            let low = rec_modified_minor.min()?;
            let mean = rec_modified_minor.aggregated_value()?;
            info!("Aggregated (mean) time is {}, mean: {}", low, mean);

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

#[logfn_inputs(Trace)]
pub fn fujisaki_okamoto_baseline_cache<KEM: KemMeasure>(
    samples: u64,
    nencaps: u64,
    nkeys: u64,
    warmup: u64,
    measure_source: MeasureSource,
    save: Option<PathBuf>,
) -> Result<()> {
    measure_source.prep_thread()?;

    let mut recorders = vec![];

    let maxmod = 16000; // KEM::error_correction_limit() * 2;

    info!(
        "Launching the cache timing baseline routine against {} with maximum modification: {}.",
        KEM::NAME,
        maxmod
    );
    for key in 0..nkeys {
        let mut ciphertext = KEM::Ciphertext::new();

        info!("Generating keypair");
        let (mut public_key, mut secret_key) = KEM::keypair()?;

        info!("Encapsulating shared secret and generating ciphertext");
        let mut shared_secret_e = KEM::SharedSecret::new();
        let mut shared_secret_d = KEM::SharedSecret::new();
        KEM::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;

        info!("Warming up with {} decaps", warmup);
        let low = mod_measure::<KEM, _>(
            maxmod,
            0,
            warmup,
            &measure_source,
            &mut ciphertext,
            &mut shared_secret_d,
            &mut secret_key,
            Recorder::minval("warmup"),
        )?
        .aggregated_value()?;
        info!("Aggregated (mean) time is {}", low);

        for t in 0..nencaps {
            info!("Encapsulating shared secret and generating ciphertext");
            KEM::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;

            #[allow(clippy::single_element_loop)]
            for i in &[31] {
                // create a histogram with default config

                info!(
                    "Sampling {} decaps with minor and major modifications, round robin, using \"{:?}\" as source of measurment.",
                    samples, measure_source
                );
                let mods = vec![
                    ModAmount::new(
                        1,
                        Recorder::saveall(format!("{}-{}-MINOR", key + 1, t + 1), None),
                    ),
                    ModAmount::new(
                        maxmod,
                        Recorder::saveall(format!("{}-{}-MAJOR", key + 1, t + 1), None),
                    ),
                ];
                let newrecs = mod_measure_interleaved::<KEM, _>(
                    mods,
                    *i,
                    samples,
                    &measure_source,
                    &mut ciphertext,
                    &mut shared_secret_d,
                    &mut secret_key,
                )?;
                let low = newrecs[0].min()?;
                let mean = newrecs[0].aggregated_value()?;
                info!("(NOMOD) Aggregated (mean) time is {}, mean: {}", low, mean);
                let low = newrecs[1].min()?;
                let mean = newrecs[1].aggregated_value()?;
                info!("(MAJOR) Aggregated (mean) time is {}, mean: {}", low, mean);

                recorders.extend(newrecs);
            }
            if let Some(ref path) = save {
                info!("Saving measurments to file {:?}", path);
                save_to_csv(path, &recorders)?;
            }
        }
    }

    info!("Finished!");
    Ok(())
}

#[logfn_inputs(Trace)]
pub fn fujisaki_okamoto_baseline_multipoint_profiling<KEM: KemMeasure>(
    samples: u64,
    nencaps: u64,
    nkeys: u64,
    warmup: u64,
    save: Option<PathBuf>,
) -> Result<()> {
    MeasureSource::Internal.prep_thread()?;
    let mut recorders = vec![];

    let maxmod = 16000; // KEM::error_correction_limit() * 2;

    info!(
        "Launching the multipoint profiling routine against {} with maximum modification: {}.",
        KEM::NAME,
        maxmod
    );
    for key in 0..nkeys {
        let mut ciphertext = KEM::Ciphertext::new();

        info!("Generating keypair");
        let (mut public_key, mut secret_key) = KEM::keypair()?;

        info!("Encapsulating shared secret and generating ciphertext");
        let mut shared_secret_e = KEM::SharedSecret::new();
        let mut shared_secret_d = KEM::SharedSecret::new();
        KEM::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;

        let results = KEM::decaps_measure(&mut ciphertext, &mut shared_secret_d, &mut secret_key)?;

        let checkpoint_names: Vec<_> = results.checkpoint_names();

        info!("Listing profiling checkpoints: {:?}", checkpoint_names);

        for t in 0..nencaps {
            info!("Encapsulating shared secret and generating ciphertext");
            KEM::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;

            #[allow(clippy::single_element_loop)]
            for i in &[31] {
                // create a histogram with default config

                info!("Warming up with {} decaps", warmup);
                for _ in 0..warmup {
                    KEM::decaps_measure(&mut ciphertext, &mut shared_secret_d, &mut secret_key)?;
                }

                info!(
                    "Sampling {} decaps with minor and major modifications, round robin",
                    samples
                );
                let mods = vec![
                    ModAmount::new_multipoint(
                        1,
                        vec![Recorder::saveall(
                            format!("{}-{}-all-MINOR", key + 1, t + 1),
                            None,
                        )]
                        .drain(..)
                        .chain(checkpoint_names.iter().map(|name| {
                            Recorder::saveall(format!("{}-{}-{}-MINOR", key + 1, t + 1, name), None)
                        }))
                        .map(RefCell::new)
                        .collect(),
                    ),
                    ModAmount::new_multipoint(
                        maxmod,
                        vec![Recorder::saveall(
                            format!("{}-{}-all-MAJOR", key + 1, t + 1),
                            None,
                        )]
                        .drain(..)
                        .chain(checkpoint_names.iter().map(|name| {
                            Recorder::saveall(format!("{}-{}-{}-MAJOR", key + 1, t + 1, name), None)
                        }))
                        .map(RefCell::new)
                        .collect(),
                    ),
                ];
                let mut newrecs = mod_measure_multipoint_interleaved::<KEM, _>(
                    mods,
                    *i,
                    samples,
                    &mut ciphertext,
                    &mut shared_secret_d,
                    &mut secret_key,
                )?;
                let low = newrecs[0][0].min()?;
                let mean = newrecs[0][0].aggregated_value()?;
                info!("(NOMOD) Aggregated (mean) time is {}, mean: {}", low, mean);
                let low = newrecs[1][0].min()?;
                let mean = newrecs[1][0].aggregated_value()?;
                info!("(MAJOR) Aggregated (mean) time is {}, mean: {}", low, mean);

                recorders.extend(newrecs.drain(..).flatten());
            }
            if let Some(ref path) = save {
                info!("Saving measurments to file {:?}", path);
                save_to_csv(path, &recorders)?;
            }
        }
    }

    info!("Finished!");
    Ok(())
}
