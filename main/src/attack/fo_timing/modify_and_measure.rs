use super::{DecapsCachePrepping, MeasureSource, NoCachePrepping};
use crate::utils::Rec;
use liboqs_rs_bindings as oqs;
use log::warn;
use log_derive::logfn_inputs;
use oqs::{InternalKemMeasurments, KemMeasure, Sign};
use std::{cell::RefCell, fmt::Debug};

#[logfn_inputs(Trace)]
#[allow(clippy::too_many_arguments)]
pub fn mod_measure<'a, KEM: KemMeasure, R: Rec<'a>>(
    amount: u16,
    index_ij: usize,
    iterations: u64,
    measure_source: &MeasureSource,
    ct: &mut KEM::Ciphertext,
    ss: &mut KEM::SharedSecret,
    sk: &mut KEM::SecretKey,
    mut recorder: R,
) -> Result<R, String> {
    //Modify
    KEM::modify(ct, index_ij, Sign::Plus(amount))?;
    for _ in 0..iterations {
        let m = measure_source.measure_decap::<KEM, DecapsCachePrepping>(ct, ss, sk)?;
        if let Some(time) = m {
            recorder.record(time)?;
        };
    }
    //Unmodify
    KEM::modify(ct, index_ij, Sign::Minus(amount))?;

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

#[derive(Debug)]
pub struct ModAmount<R>
where
    for<'a> R: Rec<'a>,
{
    amount: u16,
    recorders: Vec<RefCell<R>>,
}

impl<R: for<'a> Rec<'a>> ModAmount<R> {
    pub fn new(amount: u16, recorder: R) -> Self {
        Self {
            amount,
            recorders: vec![RefCell::new(recorder)],
        }
    }

    pub fn new_multipoint(amount: u16, recorders: Vec<RefCell<R>>) -> Self {
        Self { amount, recorders }
    }
}

#[logfn_inputs(Trace)]
pub fn mod_measure_interleaved<KEM: KemMeasure, R: for<'a> Rec<'a>>(
    mut modamounts: Vec<ModAmount<R>>,
    index_ij: usize,
    iterations: u64,
    measure_source: &MeasureSource,
    ct: &mut KEM::Ciphertext,
    ss: &mut KEM::SharedSecret,
    sk: &mut KEM::SecretKey,
) -> Result<Vec<R>, String> {
    let mut cycle = modamounts.iter().cycle();
    //iterations indicates the number of samples *per* modamount
    let iterations = iterations * modamounts.len() as u64;
    for _ in 0..iterations {
        measure_source.measure_decap::<KEM, NoCachePrepping>(ct, ss, sk)?;
        measure_source.measure_decap::<KEM, NoCachePrepping>(ct, ss, sk)?;
        let modamount = cycle.next().unwrap();
        //modify ciphertext
        KEM::modify(ct, index_ij, Sign::Plus(modamount.amount))?;
        //measure
        let m = measure_source.measure_decap::<KEM, NoCachePrepping>(ct, ss, sk)?;
        //undo modification
        KEM::modify(ct, index_ij, Sign::Minus(modamount.amount))?;
        //Store measurement
        if let Some(time) = m {
            modamount.recorders[0].borrow_mut().record(time)?;
        };
    }

    Ok(modamounts
        .drain(..)
        .inspect(|modamount| {
            // We want to keep more than 75% of all values
            let rec = modamount.recorders[0].borrow_mut();
            if rec.len() < (iterations / 4) {
                warn!(
                    "Recorded {} (nomod) out of {} iterations!",
                    rec.len(),
                    iterations
                );
            }
        })
        .map(|mut m| m.recorders.remove(0).into_inner())
        .collect())
}

#[logfn_inputs(Trace)]
pub fn mod_measure_multipoint_interleaved<KEM: KemMeasure, R: for<'a> Rec<'a>>(
    mut modamounts: Vec<ModAmount<R>>,
    index_ij: usize,
    iterations: u64,
    ct: &mut KEM::Ciphertext,
    ss: &mut KEM::SharedSecret,
    sk: &mut KEM::SecretKey,
) -> Result<Vec<Vec<R>>, String> {
    let mut cycle = modamounts.iter().cycle();
    //iterations indicates the number of samples *per* modamount
    let iterations = iterations * modamounts.len() as u64;
    for _ in 0..iterations {
        KEM::decaps_measure(ct, ss, sk)?;
        KEM::decaps_measure(ct, ss, sk)?;
        let modamount = cycle.next().unwrap();
        //modify ciphertext
        KEM::modify(ct, index_ij, Sign::Plus(modamount.amount))?;
        //measure
        let results = KEM::decaps_measure(ct, ss, sk)?;
        //undo modification
        KEM::modify(ct, index_ij, Sign::Minus(modamount.amount))?;
        //Store measurement
        if let Some(time) = results.result_internal() {
            modamount.recorders[0].borrow_mut().record(time)?;
        };
        for (rec, m) in modamount.recorders[1..]
            .iter()
            .zip(results.result_checkpoints().iter())
        {
            rec.borrow_mut().record(*m)?;
        }
    }

    Ok(modamounts
        .drain(..)
        .inspect(|modamount| {
            // We want to keep more than 75% of all values
            for rec in &modamount.recorders {
                let rec = rec.borrow_mut();
                if rec.len() < (iterations / 4) {
                    warn!(
                        "Recorded {} (nomod) out of {} iterations!",
                        rec.len(),
                        iterations
                    );
                }
            }
        })
        .map(|mut m| {
            m.recorders
                .drain(..)
                .map(RefCell::into_inner)
                .collect::<Vec<_>>()
        })
        .collect())
}
