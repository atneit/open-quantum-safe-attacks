use crate::attack::memcmp_frodo::MeasureSource;
use crate::utils::display_histogram;
use histogram::Histogram;
use liboqs_rs_bindings as oqs;
use log::{debug, info, warn};
use log_derive::logfn_inputs;
use oqs::frodokem::*;
use oqs::Result;

#[derive(Debug)]
enum ModificationType {
    Noop,
    Start,
    End,
    Uniform,
}

fn iterate<FRODO: FrodoKem>(
    public_key: &mut FRODO::PublicKey,
    secret_key: &mut FRODO::SecretKey,
    ciphertext: &mut FRODO::Ciphertext,
    histogram: Option<&mut Histogram>,
    modification: ModificationType,
    measure: MeasureSource,
) -> Result {
    let mut shared_secret_e = FRODO::zero_ss();
    let mut shared_secret_d = FRODO::zero_ss();
    FRODO::encaps(ciphertext, &mut shared_secret_e, public_key)?;

    modify::<FRODO>(ciphertext, modification);

    let diff =
        measure.measure(|| FRODO::decaps_measure(ciphertext, &mut shared_secret_d, secret_key))?;
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
    info!(
        "Launching the baseline routine against {} MEMCMP vulnerability.",
        FRODO::name()
    );
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
