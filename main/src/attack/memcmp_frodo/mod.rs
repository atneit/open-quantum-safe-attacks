use liboqs_rs_bindings as oqs;
use log::{debug, info, trace};
use log_derive::logfn_inputs;
use oqs::calloqs;

#[logfn_inputs(Trace)]
pub fn memcmp_frodo640aes() -> Result<(), String> {
    info!("Launching the MEMCMP attack against FrodKEM640AES.");
    let mut public_key_arr = [0u8; oqs::OQS_KEM_frodokem_640_aes_length_public_key as usize];
    let mut secret_key_arr = [0u8; oqs::OQS_KEM_frodokem_640_aes_length_secret_key as usize];
    let mut ciphertext_arr = [0u8; oqs::OQS_KEM_frodokem_640_aes_length_ciphertext as usize];
    let mut shared_secret_e_arr =
        [0u8; oqs::OQS_KEM_frodokem_640_aes_length_shared_secret as usize];
    let mut shared_secret_d_arr =
        [0u8; oqs::OQS_KEM_frodokem_640_aes_length_shared_secret as usize];
    let public_key = public_key_arr.as_mut_ptr();
    let secret_key = secret_key_arr.as_mut_ptr();
    let ciphertext = ciphertext_arr.as_mut_ptr();
    let shared_secret_e = shared_secret_e_arr.as_mut_ptr();
    let shared_secret_d = shared_secret_d_arr.as_mut_ptr();

    info!("Generating keypair...");
    calloqs!(OQS_KEM_frodokem_640_aes_keypair(public_key, secret_key))?;

    calloqs!(OQS_KEM_frodokem_640_aes_encaps(
        ciphertext,
        shared_secret_e,
        public_key
    ))?;
    debug!("Encapsulated shared secret: {:?}", shared_secret_e_arr);

    calloqs!(OQS_KEM_frodokem_640_aes_decaps(
        shared_secret_d,
        ciphertext,
        secret_key
    ))?;
    debug!("Decapsulated shared secret: {:?}", shared_secret_d_arr);

    info!("Done!");
    Ok(())
}
