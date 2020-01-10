use liboqs_rs_bindings as oqs;
use log::trace;
use log_derive::logfn_inputs;
use oqs::calloqs;

#[logfn_inputs(Trace)]
pub fn memcmp_frodo640aes() -> Result<(), String> {
    let public_key = [0u8; oqs::OQS_KEM_frodokem_640_aes_length_public_key as usize].as_mut_ptr();
    let secret_key = [0u8; oqs::OQS_KEM_frodokem_640_aes_length_secret_key as usize].as_mut_ptr();
    let ciphertext = [0u8; oqs::OQS_KEM_frodokem_640_aes_length_ciphertext as usize].as_mut_ptr();
    let shared_secret_e =
        [0u8; oqs::OQS_KEM_frodokem_640_aes_length_shared_secret as usize].as_mut_ptr();
    let shared_secret_d =
        [0u8; oqs::OQS_KEM_frodokem_640_aes_length_shared_secret as usize].as_mut_ptr();

    calloqs!(OQS_KEM_frodokem_640_aes_keypair(public_key, secret_key))?;
    calloqs!(OQS_KEM_frodokem_640_aes_encaps(
        ciphertext,
        shared_secret_e,
        public_key
    ))?;
    calloqs!(OQS_KEM_frodokem_640_aes_decaps(
        shared_secret_d,
        ciphertext,
        secret_key
    ))?;

    Ok(())
}
