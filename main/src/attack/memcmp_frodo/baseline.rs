use super::modify_and_measure::*;
use crate::attack::memcmp_frodo::MeasureSource;
use crate::utils::save_to_file;
use crate::utils::{Rec, Recorder};
use liboqs_rs_bindings as oqs;
use log::{info, Level};
use log_derive::logfn_inputs;
use oqs::frodokem::*;
use oqs::Result;
use std::path::PathBuf;

#[logfn_inputs(Trace)]
pub fn baseline_memcmp_frodo<FRODO: FrodoKem>(
    samples: usize,
    warmup: usize,
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

    let maxmod = max_mod::<FRODO>();

    info!("Warming up with {} decaps", warmup);
    let low = mod_measure::<FRODO, _>(
        maxmod,
        0,
        warmup,
        &measure_source,
        None,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
        &mut Recorder::devnull(),
    )?;
    info!("Lowest time is {}", low);

    // create a histogram with default config
    let mut rec_unmodified = Recorder::saveall("NOMOD");
    let mut rec_modified_major = Recorder::saveall("MAJOR");
    let mut rec_modified_minor = Recorder::saveall("MINOR");

    info!(
        "(NOMOD) Sampling {} decaps without modifications, using \"{:?}\" as source of measurment.",
        samples, measure_source
    );
    let low = mod_measure::<FRODO, _>(
        0,
        0,
        samples,
        &measure_source,
        None,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
        &mut rec_unmodified,
    )?;
    info!("Lowest time is {}", low);

    info!(
        "(MINOR) Sampling {} decaps, modifying C[0] by adding 1.",
        samples
    );
    let low = mod_measure::<FRODO, _>(
        1,
        0,
        samples,
        &measure_source,
        None,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
        &mut rec_modified_minor,
    )?;
    info!("Lowest time is {}", low);

    info!(
        "(MAJOR) Sampling {} decaps, modifying C[0] by adding {}.",
        samples, maxmod
    );
    let low = mod_measure::<FRODO, _>(
        maxmod,
        0,
        samples,
        &measure_source,
        None,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
        &mut rec_modified_major,
    )?;
    info!("Lowest time is {}", low);

    rec_unmodified.log(Level::Debug, "NOMOD");
    rec_modified_minor.log(Level::Debug, "MINOR");
    rec_modified_major.log(Level::Debug, "MAJOR");

    if let Some(path) = save {
        info!("Saving measurments to file {:?}", path);
        save_to_file(
            &path,
            &vec![rec_unmodified, rec_modified_minor, rec_modified_major],
        )?;
    }

    info!("Finished!");
    Ok(())
}
