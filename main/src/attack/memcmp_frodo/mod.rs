use crate::utils::display_histogram;
use histogram::Histogram;
use liboqs_rs_bindings as oqs;
use log::{debug, info, trace, warn};
use log_derive::logfn_inputs;
use oqs::{calloqs, Result};
use std::arch::x86_64::__rdtscp;

#[derive(Debug)]
enum ModificationType {
    Noop,
    Start,
    End,
    Uniform,
}

type PublicKey = [u8; oqs::OQS_KEM_frodokem_640_aes_length_public_key as usize];
type SecretKey = [u8; oqs::OQS_KEM_frodokem_640_aes_length_secret_key as usize];
type Ciphertext = [u8; oqs::OQS_KEM_frodokem_640_aes_length_ciphertext as usize];
//type SharedSecret = [u8; oqs::OQS_KEM_frodokem_640_aes_length_shared_secret as usize];

fn iterate(
    public_key_arr: &mut PublicKey,
    secret_key_arr: &mut SecretKey,
    ciphertext_arr: &mut Ciphertext,
    histogram: Option<&mut Histogram>,
    modification: ModificationType,
) -> Result {
    let mut shared_secret_e_arr =
        [0u8; oqs::OQS_KEM_frodokem_640_aes_length_shared_secret as usize];
    let mut shared_secret_d_arr =
        [0u8; oqs::OQS_KEM_frodokem_640_aes_length_shared_secret as usize];
    let public_key = public_key_arr.as_mut_ptr();
    let secret_key = secret_key_arr.as_mut_ptr();
    let ciphertext = ciphertext_arr.as_mut_ptr();
    let shared_secret_e = shared_secret_e_arr.as_mut_ptr();
    let shared_secret_d = shared_secret_d_arr.as_mut_ptr();
    calloqs!(OQS_KEM_frodokem_640_aes_encaps(
        ciphertext,
        shared_secret_e,
        public_key
    ))?;

    modify(ciphertext_arr, modification);

    let diff = {
        let mut cpu_core_ident_start = 0u32;
        let mut cpu_core_ident_stop = 0u32;
        let start = unsafe { __rdtscp(&mut cpu_core_ident_start) };

        calloqs!(OQS_KEM_frodokem_640_aes_decaps(
            shared_secret_d,
            ciphertext,
            secret_key
        ))?;

        let stop = unsafe { __rdtscp(&mut cpu_core_ident_stop) };
        if cpu_core_ident_start == cpu_core_ident_stop {
            Some(stop - start)
        } else {
            None
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

fn modify(ciphertext: &mut Ciphertext, modify: ModificationType) {
    match modify {
        ModificationType::Noop => {}
        ModificationType::Start => {
            //Flip all bits in first byte
            ciphertext[0] ^= 255u8;
        }
        ModificationType::End => {
            //Flip all bits in last byte
            ciphertext[ciphertext.len() - 1] ^= 255u8;
        }
        ModificationType::Uniform => {
            for i in 0..ciphertext.len() {
                if i % 100 == 0 {
                    // flipp every bit in every 100 bytes
                    ciphertext[i] ^= 255;
                }
            }
        }
    }
}

#[logfn_inputs(Trace)]
pub fn memcmp_frodo640aes(samples: usize, warmup: usize) -> Result {
    info!("Launching the MEMCMP attack against FrodKEM640AES.");
    let mut public_key = [0u8; oqs::OQS_KEM_frodokem_640_aes_length_public_key as usize];
    let mut secret_key = [0u8; oqs::OQS_KEM_frodokem_640_aes_length_secret_key as usize];
    let mut ciphertext = [0u8; oqs::OQS_KEM_frodokem_640_aes_length_ciphertext as usize];

    info!("Generating keypair");
    {
        let public_key = public_key.as_mut_ptr();
        let secret_key = secret_key.as_mut_ptr();
        calloqs!(OQS_KEM_frodokem_640_aes_keypair(public_key, secret_key))?;
    }

    // create a histogram with default config
    let mut hist_unmodified = Histogram::new();
    let mut hist_modified_start = Histogram::new();
    let mut hist_modified_end = Histogram::new();
    let mut hist_modified_uniform = Histogram::new();

    info!("Warming up with {} encap/decap iterations", warmup);
    for _ in 0..warmup {
        iterate(
            &mut public_key,
            &mut secret_key,
            &mut ciphertext,
            Some(&mut hist_unmodified),
            ModificationType::Noop,
        )?;
    }

    info!(
        "Sampling {} encap/decap iterations without modifications",
        samples
    );
    for _ in 0..samples {
        iterate(
            &mut public_key,
            &mut secret_key,
            &mut ciphertext,
            Some(&mut hist_unmodified),
            ModificationType::Noop,
        )?;
    }

    info!(
        "Sampling {} encap/decap iterations, modifying first positions",
        samples
    );
    for _ in 0..samples {
        iterate(
            &mut public_key,
            &mut secret_key,
            &mut ciphertext,
            Some(&mut hist_modified_start),
            ModificationType::Start,
        )?;
    }

    info!(
        "Sampling {} encap/decap iterations, modifying last positions",
        samples
    );
    for _ in 0..samples {
        iterate(
            &mut public_key,
            &mut secret_key,
            &mut ciphertext,
            Some(&mut hist_modified_end),
            ModificationType::End,
        )?;
    }

    info!(
        "Sampling {} encap/decap iterations, modifying uniformly",
        samples
    );
    for _ in 0..samples {
        iterate(
            &mut public_key,
            &mut secret_key,
            &mut ciphertext,
            Some(&mut hist_modified_uniform),
            ModificationType::Uniform,
        )?;
    }

    display_histogram("NOOP", hist_unmodified);
    display_histogram("START", hist_modified_start);
    display_histogram("END", hist_modified_end);
    display_histogram("UNIF", hist_modified_uniform);

    info!("Finished!");
    Ok(())
}
