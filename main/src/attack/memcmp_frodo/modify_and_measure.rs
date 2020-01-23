use super::MeasureSource;
use crate::utils::Recorder;
use liboqs_rs_bindings as oqs;
use log::{info, trace};
use log_derive::logfn_inputs;
use oqs::frodokem::{FrodoKem, KemBuf};
use std::convert::TryInto;

#[derive(Debug)]
pub enum Sign<T> {
    Plus(T),
    Minus(T),
}

pub fn max_mod<FRODO: FrodoKem>() -> u16 {
    let params = FRODO::params::<u32>();
    2u16.pow(params.PARAM_LOGQ - params.PARAM_B)
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
pub fn mod_measure<FRODO: FrodoKem, R: Recorder>(
    amount: u16,
    index_ij: usize,
    iterations: usize,
    measure_source: &MeasureSource,
    short_circuit_threshold: Option<u64>,
    ct: &mut FRODO::Ciphertext,
    ss: &mut FRODO::SharedSecret,
    sk: &mut FRODO::SecretKey,
    recorder: &mut R,
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
            recorder.record(time)?;
        };
    }
    //Unmodify
    modify::<FRODO>(ct, index_ij, Sign::Minus(amount))?;
    Ok(lowest)
}
