use super::modify_and_measure::*;
use crate::attack::memcmp_frodo::MeasureSource;
use crate::utils::{stringify, DevNull, Recorder};
use hdrhistogram::Histogram;
use liboqs_rs_bindings as oqs;
use log::{info, Level};
use log_derive::logfn_inputs;
use oqs::frodokem::*;
use oqs::Result;

#[logfn_inputs(Trace)]
pub fn baseline_memcmp_frodo<FRODO: FrodoKem>(
    samples: usize,
    warmup: usize,
    measure_source: MeasureSource,
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
        &mut DevNull,
    )?;
    info!("Lowest time is {}", low);

    let hist_low = low;
    let hist_high = low * 2;
    let hist_sigfig = 5;

    // create a histogram with default config
    let mut hist_unmodified =
        Histogram::new_with_bounds(hist_low, hist_high, hist_sigfig).map_err(stringify)?;
    let mut hist_modified_minor =
        Histogram::new_with_bounds(hist_low, hist_high, hist_sigfig).map_err(stringify)?;
    let mut hist_modified_major =
        Histogram::new_with_bounds(hist_low, hist_high, hist_sigfig).map_err(stringify)?;

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
        &mut hist_unmodified,
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
        &mut hist_modified_minor,
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
        &mut hist_modified_major,
    )?;
    info!("Lowest time is {}", low);

    hist_unmodified.log(Level::Info, "NOMOD");
    hist_modified_minor.log(Level::Info, "MINOR");
    hist_modified_major.log(Level::Info, "MAJOR");

    info!("Finished!");
    Ok(())
}
