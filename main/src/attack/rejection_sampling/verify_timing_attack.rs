use std::{io::Write, iter::once, path::PathBuf};

use crate::{
    attack::fo_timing::{MeasureSource, NoCachePrepping},
    utils::{
        pb_add, ClonableProgressManager, ProgressBars, Rec, Recorder, SaveAllRecorder, StrErr,
    },
};
use liboqs_rs_bindings as oqs;
use log::{debug, info};
use log_derive::logfn_inputs;
use oqs::{KemBuf, KemWithRejectionSampling};
use rand::{thread_rng, Fill};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
pub struct VerifyTimingAttackOptions {
    /// The number of random plaintext to search before selecting the best pair to compare.
    #[structopt(short("p"), long)]
    num_plaintexts: i32,
    /// The number of decapsulations to measure, for each of the selected plaintexts
    #[structopt(short("d"), long)]
    num_decaps: i32,
    /// Save all recordings to this file
    #[structopt(short("f"), long)]
    pub save: Option<PathBuf>,
}

#[logfn_inputs(Trace)]
#[allow(clippy::type_complexity)]
pub fn find_min_max_pt<KEM: KemWithRejectionSampling>(
    num_plaintexts: i32,
) -> Result<((usize, KEM::Plaintext), (usize, KEM::Plaintext)), String> {
    let mut total_pos: u64 = 0;
    let pm = ClonableProgressManager::<u8>::create();
    pm.add(
        0,
        num_plaintexts as u64,
        "Searching for best candidate",
        " {msg:30} {wide_bar} ETA [{eta_precise}] ",
    );
    pm.start([]);
    let mut rng = thread_rng();
    let mut pt = KEM::Plaintext::new();
    let mut max_rejection = 0;
    let mut max_rejection_pt = KEM::Plaintext::new();
    let mut min_rejection = usize::MAX;
    let mut min_rejection_pt = KEM::Plaintext::new();
    for i in 0..num_plaintexts {
        let i = i + 1;
        pt.as_mut_slice().try_fill(&mut rng).strerr()?;
        let num = KEM::num_rejections(&mut pt)? as usize;
        if num > max_rejection {
            debug!(
                "Unique plaintext number {}: New maximum number of iterations: {}",
                i, num
            );
            max_rejection = num;
            max_rejection_pt = pt.clone();
        }
        if num < min_rejection {
            debug!(
                "Unique plaintext number {}: New minumum number of iterations: {}",
                i, num
            );
            min_rejection = num;
            min_rejection_pt = pt.clone();
        }
        if i % 1000 == 0 {
            pb_add!(total_pos = pm[0].add(1000));
        }
    }
    pm.stop();
    Ok((
        (min_rejection, min_rejection_pt),
        (max_rejection, max_rejection_pt),
    ))
}

#[logfn_inputs(Trace)]
pub fn encapsulate_and_verify<KEM: KemWithRejectionSampling>(
    pk: &mut KEM::PublicKey,
    sk: &mut KEM::SecretKey,
    pt: &mut KEM::Plaintext,
) -> Result<KEM::Ciphertext, String> {
    let mut ssa = KEM::SharedSecret::new();
    let mut ssb = KEM::SharedSecret::new();
    let mut ct = KEM::Ciphertext::new();
    KEM::encaps_with_plaintext(&mut ct, &mut ssa, pk, pt)?;
    KEM::decaps(&mut ct, &mut ssb, sk)?;
    if ssa.as_slice() == ssb.as_slice() {
        Ok(ct)
    } else {
        Err("Shared secrets from encaps() <-> decaps() are not equal!".to_string())
    }
}

#[logfn_inputs(Trace)]
pub fn run<KEM, W>(
    opt: &VerifyTimingAttackOptions,
    save: &mut Option<csv::Writer<W>>,
) -> Result<[Recorder<SaveAllRecorder>; 2], String>
where
    KEM: KemWithRejectionSampling,
    W: Write + std::fmt::Debug,
{
    info!("Running with {}", KEM::NAME);
    //Find the best plaintext candidates for timing measurments
    let ((min, mut min_pt), (max, mut max_pt)) = find_min_max_pt::<KEM>(opt.num_plaintexts)?;

    // Make a keypair
    let (mut pk, mut sk) = KEM::keypair()?;

    //Verify that the encapsulation with specified plaintext works as it should!
    let mut min_ct = encapsulate_and_verify::<KEM>(&mut pk, &mut sk, &mut min_pt)?;
    let mut max_ct = encapsulate_and_verify::<KEM>(&mut pk, &mut sk, &mut max_pt)?;
    let mut ss = KEM::SharedSecret::new();

    let mut min_rec = Recorder::saveall(format!("{}#min", KEM::NAME), None);
    let mut max_rec = Recorder::saveall(format!("{}#max", KEM::NAME), None);
    info!("Starting {} measurments...", opt.num_decaps);
    for _ in 0..opt.num_decaps {
        if let Some(m) = MeasureSource::measure_decap_external::<KEM, NoCachePrepping>(
            &mut min_ct,
            &mut ss,
            &mut sk,
        )? {
            min_rec.record(m)?;
        }
        if let Some(m) = MeasureSource::measure_decap_external::<KEM, NoCachePrepping>(
            &mut max_ct,
            &mut ss,
            &mut sk,
        )? {
            max_rec.record(m)?;
        }
    }

    info!("min: {}", min_rec.aggregated_value()?);
    info!("max: {}", max_rec.aggregated_value()?);

    if let Some(w) = save {
        debug!("Saving to min-samples file...");
        let prefix = [KEM::NAME.to_string(), min.to_string()];
        for m in min_rec.iter() {
            w.write_record(prefix.iter().chain(once(&m.to_string())))
                .strerr()?;
        }
        debug!("Saving to max-samples file...");
        let prefix = [KEM::NAME.to_string(), max.to_string()];
        for m in max_rec.iter() {
            w.write_record(prefix.iter().chain(once(&m.to_string())))
                .strerr()?;
        }
    }

    Ok([min_rec, max_rec])
}
