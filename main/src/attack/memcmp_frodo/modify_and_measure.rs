use super::MeasureSource;
use crate::utils::Rec;
use liboqs_rs_bindings as oqs;
use log::{trace, warn};
use log_derive::logfn_inputs;
use oqs::frodokem::{FrodoKem, KemBuf};
use std::convert::TryInto;

#[derive(Debug)]
pub enum Sign<T> {
    Plus(T),
    Minus(T),
}

/// Returns the element-wise maximum error correction capability
pub fn error_correction_limit<FRODO: FrodoKem>() -> u16 {
    let params = FRODO::params::<u32>();
    2u16.pow(params.PARAM_LOGQ - params.PARAM_B - 1)
}

/// Function that deterministically modifies the input vector.
///
/// To undo apply the same modification with Sign::Minus instead.alloc
/// We operate on modulo q
#[logfn_inputs(Trace)]
pub fn modify<FRODO: FrodoKem>(
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
pub fn mod_measure<'a, FRODO: FrodoKem, R: Rec<'a>>(
    amount: u16,
    index_ij: usize,
    iterations: u64,
    measure_source: &MeasureSource,
    ct: &mut FRODO::Ciphertext,
    ss: &mut FRODO::SharedSecret,
    sk: &mut FRODO::SecretKey,
    mut recorder: R,
) -> Result<R, String> {
    //Modify
    modify::<FRODO>(ct, index_ij, Sign::Plus(amount))?;
    'sample: for _ in 0..iterations {
        MeasureSource::clflush_inputs(vec![ct.as_slice(), ss.as_slice(), sk.as_slice()]);
        let m = measure_source.measure(|| FRODO::decaps_measure(ct, ss, sk))?;
        if let Some(time) = m {
            recorder.record(time)?;
        };
    }
    //Unmodify
    modify::<FRODO>(ct, index_ij, Sign::Minus(amount))?;

    // We want to keep more than 75% of all values
    if recorder.len() < (iterations / 4) {
        warn!(
            "Recorded {} out of {} iterations!",
            recorder.len(),
            iterations
        );
    }
    Ok(recorder)
}
