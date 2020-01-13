use crate::utils::display_histogram;
use histogram::Histogram;
use liboqs_rs_bindings as oqs;
use log::{debug, info, warn};
use log_derive::logfn_inputs;
use oqs::frodokem::*;
use oqs::Result;
use std::arch::x86_64::__rdtscp;
use std::str::FromStr;
use structopt::StructOpt;

#[derive(Debug)]
enum ModificationType {
    Noop,
    Start,
    End,
    Uniform,
}

#[derive(StructOpt, Debug, Clone, Copy)]
#[structopt(name = "measure-source")]
pub enum MeasureSource {
    External,
    Internal,
    Oracle,
}

impl FromStr for MeasureSource {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<MeasureSource, String> {
        match s {
            "external" => Ok(MeasureSource::External),
            "internal" => Ok(MeasureSource::Internal),
            "oracle" => Ok(MeasureSource::Oracle),
            _ => Err(format!(
                "Could not parse {} into either external, internal or oracle.",
                s
            )),
        }
    }
}

fn iterate<FRODO: FrodoKem>(
    public_key: &mut FRODO::PublicKey,
    secret_key: &mut FRODO::SecretKey,
    ciphertext: &mut FRODO::Ciphertext,
    histogram: Option<&mut Histogram>,
    modification: ModificationType,
    measure: MeasureSource,
) -> Result {
    let mut shared_secret_e = FRODO::zerp_ss();
    let mut shared_secret_d = FRODO::zerp_ss();
    FRODO::encaps(ciphertext, &mut shared_secret_e, public_key)?;

    modify::<FRODO>(ciphertext, modification);

    let diff = match measure {
        MeasureSource::External => {
            let mut cpu_core_ident_start = 0u32;
            let mut cpu_core_ident_stop = 0u32;
            let start = unsafe { __rdtscp(&mut cpu_core_ident_start) };
            let _ = FRODO::decaps(ciphertext, &mut shared_secret_d, secret_key)?;
            let stop = unsafe { __rdtscp(&mut cpu_core_ident_stop) };
            if cpu_core_ident_start == cpu_core_ident_stop {
                Some(stop - start)
            } else {
                None
            }
        }
        MeasureSource::Internal => {
            let results = FRODO::decaps_measure(ciphertext, &mut shared_secret_d, secret_key)?;
            results.memcmp_timing
        }
        MeasureSource::Oracle => {
            let results = FRODO::decaps_measure(ciphertext, &mut shared_secret_d, secret_key)?;
            if let Some(memcmp1) = results.memcmp1 {
                //memcmp1 has executed
                let mut time = 100; //base timing
                if memcmp1 {
                    time += 50;
                    //first part was identical
                    if let Some(memcmp2) = results.memcmp2 {
                        if memcmp2 {
                            //last part was also identical
                            time += 100;
                        }
                    } else {
                        unreachable!("If memcmp1 is true then memcmp2 must have been executed!");
                    }
                }
                Some(time)
            } else {
                //Somehing happened, no comparison was executed at all
                None
            }
        }
    };
    if let Some(hist) = histogram {
        if let Some(d) = diff {
            debug!("Decapsulated shared secret in {} (rdtscp timestamps)", d);
            hist.increment(d)?;
        } else {
            warn!("RDTSCP instructin indicates cpu measurments were performed at different cores!");
        }
    }
    Ok(())
}

fn modify<FRODO: FrodoKem>(ciphertext: &mut FRODO::Ciphertext, modify: ModificationType) {
    let slice = FRODO::as_slice(ciphertext);
    match modify {
        ModificationType::Noop => {}
        ModificationType::Start => {
            //Flip all bits in first byte
            slice[0] ^= 255u8;
        }
        ModificationType::End => {
            //Flip all bits in last byte
            slice[slice.len() - 1] ^= 255u8;
        }
        ModificationType::Uniform => {
            for i in 0..slice.len() {
                if i % 100 == 0 {
                    // flipp every bit in every 100 bytes
                    slice[i] ^= 255;
                }
            }
        }
    }
}

#[logfn_inputs(Trace)]
pub fn baseline_memcmp_frodo<FRODO: FrodoKem>(
    samples: usize,
    warmup: usize,
    measure_source: MeasureSource,
) -> Result {
    info!("Launching the MEMCMP attack against FrodKEM640AES.");
    let mut public_key = FRODO::zero_pk();
    let mut secret_key = FRODO::zero_sk();
    let mut ciphertext = FRODO::zero_ct();

    info!("Generating keypair");
    FRODO::keypair(&mut public_key, &mut secret_key)?;

    // create a histogram with default config
    let mut hist_unmodified = Histogram::new();
    let mut hist_modified_start = Histogram::new();
    let mut hist_modified_end = Histogram::new();
    let mut hist_modified_uniform = Histogram::new();

    info!("Warming up with {} encap/decap iterations", warmup);
    for _ in 0..warmup {
        iterate::<FRODO>(
            &mut public_key,
            &mut secret_key,
            &mut ciphertext,
            Some(&mut hist_unmodified),
            ModificationType::Noop,
            measure_source,
        )?;
    }

    info!(
        "(NOOP) Sampling {} encap/decap iterations without modifications, using \"{:?}\" as source of measurment.",
        samples,
        measure_source
    );
    for _ in 0..samples {
        iterate::<FRODO>(
            &mut public_key,
            &mut secret_key,
            &mut ciphertext,
            Some(&mut hist_unmodified),
            ModificationType::Noop,
            measure_source,
        )?;
    }

    info!(
        "(START) Sampling {} encap/decap iterations, modifying first positions, using \"{:?}\" as source of measurment.",
        samples,
        measure_source
    );
    for _ in 0..samples {
        iterate::<FRODO>(
            &mut public_key,
            &mut secret_key,
            &mut ciphertext,
            Some(&mut hist_modified_start),
            ModificationType::Start,
            measure_source,
        )?;
    }

    info!(
        "(END) Sampling {} encap/decap iterations, modifying last positions, using \"{:?}\" as source of measurment.",
        samples,
        measure_source
    );
    for _ in 0..samples {
        iterate::<FRODO>(
            &mut public_key,
            &mut secret_key,
            &mut ciphertext,
            Some(&mut hist_modified_end),
            ModificationType::End,
            measure_source,
        )?;
    }

    info!(
        "(UNIF) Sampling {} encap/decap iterations, modifying uniformly, using \"{:?}\" as source of measurment.",
        samples,
        measure_source
    );
    for _ in 0..samples {
        iterate::<FRODO>(
            &mut public_key,
            &mut secret_key,
            &mut ciphertext,
            Some(&mut hist_modified_uniform),
            ModificationType::Uniform,
            measure_source,
        )?;
    }

    display_histogram("NOOP", hist_unmodified);
    display_histogram("START", hist_modified_start);
    display_histogram("END", hist_modified_end);
    display_histogram("UNIF", hist_modified_uniform);

    info!("Finished!");
    Ok(())
}
