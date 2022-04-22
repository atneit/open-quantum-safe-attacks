use std::convert::TryInto;

use liboqs_rs_bindings as oqs;

use log::{info, trace};
use log_derive::logfn_inputs;
use oqs::{Kem, KemBuf, KemWithRejectionSampling};
use rand::Rng;
use structopt::StructOpt;

use crate::{
    attack::{
        fo_timing::{MeasureSource, NoCachePrepping},
        rejection_sampling::verify_timing_attack::{encapsulate_and_verify, find_min_max_pt},
    },
    utils::{mutbit, Rec, Recorder},
};

#[logfn_inputs(Trace)]
pub fn get_keypair<KEM: Kem>() -> Result<(KEM::PublicKey, KEM::SecretKey), String> {
    info!("Generating a random {} keypair to crack...", KEM::NAME);
    KEM::keypair()
}

#[derive(StructOpt, Debug)]
pub struct SimulateAttackOptions {
    /// The number of random plaintext to search before selecting the best pair to compare.
    #[structopt(short("p"), long)]
    num_plaintexts: i32,
    /// The number of decapsulations to measure, for each of the selected plaintexts
    #[structopt(short("d"), long)]
    num_decaps: i32,
    /// The hamming weight of the extra noice that is applied to the ciphertext
    #[structopt(short("e"), long)]
    error_weight: i32,
}

pub fn modify_ct<KEM: KemWithRejectionSampling>(
    mut ct: KEM::Ciphertext,
    error_weight: i32,
) -> Result<KEM::Ciphertext, String> {
    let mut err = KEM::Ciphertext::new();
    let mut hamming_weight = 0;
    let es = err.as_mut_slice();
    loop {
        if hamming_weight >= error_weight {
            break;
        }
        let bitnum = rand::thread_rng().gen_range(0u64..KEM::Ciphertext::len().try_into().unwrap());
        let mut bit = mutbit(es, bitnum)?;
        if !bit.get() {
            bit.flip();
            hamming_weight += 1;
        }
    }
    let cs = ct.as_mut_slice();
    for i in 0..KEM::Ciphertext::len() {
        cs[i] ^= es[i]; //Apply the extra error
    }
    Ok(ct)
}

pub fn record_decaps_to<'a, KEM: KemWithRejectionSampling, R: Rec<'a>>(
    mut recorder: R,
    ct: &mut KEM::Ciphertext,
    sk: &mut KEM::SecretKey,
    num_decaps: i32,
) -> Result<R, String> {
    let mut ss = KEM::SharedSecret::new();
    for _ in 0..num_decaps {
        if let Some(m) =
            MeasureSource::measure_decap_external::<KEM, NoCachePrepping>(ct, &mut ss, sk)?
        {
            match recorder.record(m) {
                Ok(_) => {}
                Err(estr) => trace!("measurement {} ignored due to: {}", m, estr),
            }
        }
    }
    Ok(recorder)
}

#[logfn_inputs(Trace)]
pub fn run<KEM: KemWithRejectionSampling>(opt: SimulateAttackOptions) -> Result<(), String> {
    info!("Launching generic attack simulation on {}", KEM::NAME);

    info!(
        "Searching {} plaintexts for best candidate...",
        opt.num_plaintexts
    );
    let (_, (max, mut max_pt)) = find_min_max_pt::<KEM>(opt.num_plaintexts)?;
    info!(
        "Found candidate with {} iterations in the rejection sampling!",
        max
    );

    info!("Generating a random {} keypair to crack...", KEM::NAME);
    let (mut pk, mut sk) = KEM::keypair()?;

    //Verify that the encapsulation with specified plaintext works as it should!
    info!("Encapsulating the selected plaintext...");
    let mut ct_nomod = encapsulate_and_verify::<KEM>(&mut pk, &mut sk, &mut max_pt)?;

    info!(
        "Starting {} decapsulations of unmodified ciphertext...",
        opt.num_decaps
    );
    let rec_unmod = record_decaps_to::<KEM, _>(
        Recorder::minval("unmodified"),
        &mut ct_nomod,
        &mut sk,
        opt.num_decaps,
    )?;

    info!(
        "Adding extra error noice of weight {} to the ciphertext",
        opt.error_weight
    );

    let mut ct_mod = modify_ct::<KEM>(ct_nomod, opt.error_weight)?;

    info!(
        "Starting {} decapsulations of modified ciphertext...",
        opt.num_decaps
    );
    let rec_mod = record_decaps_to::<KEM, _>(
        Recorder::minval("modified"),
        &mut ct_mod,
        &mut sk,
        opt.num_decaps,
    )?;

    let mean_unmod = rec_unmod.aggregated_value()?;
    let mean_mod = rec_mod.aggregated_value()?;
    let mean_diff = mean_unmod as i64 - mean_mod as i64;
    info!(
        "unmodified mean: {}, modified mean: {}, diff: {}",
        mean_unmod, mean_mod, mean_diff
    );

    Ok(())
}
