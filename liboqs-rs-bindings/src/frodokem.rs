use crate as oqs;

struct InternalMeasureer {
    start: u64,
    stop: u64,
    cpu_start: u32,
    cpu_stop: u32,
    memcmp1: u8,
    memcmp2: u8,
}

impl InternalMeasureer {
    fn new() -> InternalMeasureer {
        InternalMeasureer {
            start: 0u64,
            stop: 0u64,
            cpu_start: 0u32,
            cpu_stop: 0u32,
            memcmp1: 0u8,
            memcmp2: 0u8,
        }
    }

    fn mut_ref(&mut self) -> (&mut u64, &mut u64, &mut u32, &mut u32, &mut u8, &mut u8) {
        (
            &mut self.start,
            &mut self.stop,
            &mut self.cpu_start,
            &mut self.cpu_stop,
            &mut self.memcmp1,
            &mut self.memcmp2,
        )
    }
}

pub struct InternalMeasurments {
    pub memcmp_timing: Option<u64>,
    pub memcmp1: Option<bool>,
    pub memcmp2: Option<bool>,
}

impl InternalMeasurments {
    fn new(m: InternalMeasureer) -> InternalMeasurments {
        let diff = if m.cpu_start == m.cpu_stop {
            Some(m.stop - m.start)
        } else {
            None
        };
        let memcmp1 = match m.memcmp1 {
            0 => Some(false),
            1 => Some(true),
            2 => None,
            _ => panic!("Value error on memcmp1"),
        };
        let memcmp2 = match m.memcmp2 {
            0 => Some(false),
            1 => Some(true),
            2 => None,
            _ => panic!("Value error on memcmp1"),
        };
        InternalMeasurments {
            memcmp_timing: diff,
            memcmp1,
            memcmp2,
        }
    }
}

pub trait FrodoKem {
    type PublicKey;
    type SecretKey;
    type Ciphertext;
    type SharedSecret;

    fn zero_pk() -> Self::PublicKey;
    fn zero_sk() -> Self::SecretKey;
    fn zero_ct() -> Self::Ciphertext;
    fn zerp_ss() -> Self::SharedSecret;

    fn as_slice(ct: &mut Self::Ciphertext) -> &mut [u8];

    fn keypair(pk: &mut Self::PublicKey, sk: &mut Self::SecretKey) -> oqs::Result;
    fn encaps(
        ct: &mut Self::Ciphertext,
        ss: &mut Self::SharedSecret,
        pk: &mut Self::PublicKey,
    ) -> oqs::Result;
    fn decaps(
        ct: &mut Self::Ciphertext,
        ss: &mut Self::SharedSecret,
        sk: &mut Self::SecretKey,
    ) -> oqs::Result;
    fn decaps_measure(
        ct: &mut Self::Ciphertext,
        ss: &mut Self::SharedSecret,
        sk: &mut Self::SecretKey,
    ) -> std::result::Result<InternalMeasurments, String>;
}

pub struct FrodoKem640aes;
pub struct FrodoKem1344aes;

impl FrodoKem for FrodoKem640aes {
    type PublicKey = [u8; oqs::OQS_KEM_frodokem_640_aes_length_public_key as usize];
    type SecretKey = [u8; oqs::OQS_KEM_frodokem_640_aes_length_secret_key as usize];
    type Ciphertext = [u8; oqs::OQS_KEM_frodokem_640_aes_length_ciphertext as usize];
    type SharedSecret = [u8; oqs::OQS_KEM_frodokem_640_aes_length_shared_secret as usize];

    fn zero_pk() -> Self::PublicKey {
        [0u8; oqs::OQS_KEM_frodokem_640_aes_length_public_key as usize]
    }
    fn zero_sk() -> Self::SecretKey {
        [0u8; oqs::OQS_KEM_frodokem_640_aes_length_secret_key as usize]
    }
    fn zero_ct() -> Self::Ciphertext {
        [0u8; oqs::OQS_KEM_frodokem_640_aes_length_ciphertext as usize]
    }
    fn zerp_ss() -> Self::SharedSecret {
        [0u8; oqs::OQS_KEM_frodokem_640_aes_length_shared_secret as usize]
    }

    fn as_slice(ct: &mut Self::Ciphertext) -> &mut [u8] {
        &mut ct[..]
    }

    fn keypair(pk: &mut Self::PublicKey, sk: &mut Self::SecretKey) -> oqs::Result {
        let pk = pk.as_mut_ptr();
        let sk = sk.as_mut_ptr();
        oqs::calloqs!(OQS_KEM_frodokem_640_aes_keypair(pk, sk))
    }

    fn encaps(
        ct: &mut Self::Ciphertext,
        ss: &mut Self::SharedSecret,
        pk: &mut Self::PublicKey,
    ) -> oqs::Result {
        let ct = ct.as_mut_ptr();
        let ss = ss.as_mut_ptr();
        let pk = pk.as_mut_ptr();
        oqs::calloqs!(OQS_KEM_frodokem_640_aes_encaps(ct, ss, pk))
    }

    fn decaps(
        ct: &mut Self::Ciphertext,
        ss: &mut Self::SharedSecret,
        sk: &mut Self::SecretKey,
    ) -> oqs::Result {
        let ct = ct.as_mut_ptr();
        let ss = ss.as_mut_ptr();
        let sk = sk.as_mut_ptr();
        oqs::calloqs!(OQS_KEM_frodokem_640_aes_decaps(ss, ct, sk))
    }

    fn decaps_measure(
        ct: &mut Self::Ciphertext,
        ss: &mut Self::SharedSecret,
        sk: &mut Self::SecretKey,
    ) -> std::result::Result<InternalMeasurments, String> {
        let ct = ct.as_mut_ptr();
        let ss = ss.as_mut_ptr();
        let sk = sk.as_mut_ptr();

        let mut measureer = InternalMeasureer::new();
        let (start, stop, cpu_start, cpu_stop, memcmp1, memcmp2) = measureer.mut_ref();
        oqs::calloqs!(OQS_KEM_frodokem_640_aes_decaps_measure(
            ss, ct, sk, start, stop, cpu_start, cpu_stop, memcmp1, memcmp2
        ))?;
        Ok(InternalMeasurments::new(measureer))
    }
}

impl FrodoKem for FrodoKem1344aes {
    type PublicKey = [u8; oqs::OQS_KEM_frodokem_1344_aes_length_public_key as usize];
    type SecretKey = [u8; oqs::OQS_KEM_frodokem_1344_aes_length_secret_key as usize];
    type Ciphertext = [u8; oqs::OQS_KEM_frodokem_1344_aes_length_ciphertext as usize];
    type SharedSecret = [u8; oqs::OQS_KEM_frodokem_1344_aes_length_shared_secret as usize];

    fn zero_pk() -> Self::PublicKey {
        [0u8; oqs::OQS_KEM_frodokem_1344_aes_length_public_key as usize]
    }
    fn zero_sk() -> Self::SecretKey {
        [0u8; oqs::OQS_KEM_frodokem_1344_aes_length_secret_key as usize]
    }
    fn zero_ct() -> Self::Ciphertext {
        [0u8; oqs::OQS_KEM_frodokem_1344_aes_length_ciphertext as usize]
    }
    fn zerp_ss() -> Self::SharedSecret {
        [0u8; oqs::OQS_KEM_frodokem_1344_aes_length_shared_secret as usize]
    }

    fn as_slice(ct: &mut Self::Ciphertext) -> &mut [u8] {
        &mut ct[..]
    }

    fn keypair(pk: &mut Self::PublicKey, sk: &mut Self::SecretKey) -> oqs::Result {
        let pk = pk.as_mut_ptr();
        let sk = sk.as_mut_ptr();
        oqs::calloqs!(OQS_KEM_frodokem_1344_aes_keypair(pk, sk))
    }

    fn encaps(
        ct: &mut Self::Ciphertext,
        ss: &mut Self::SharedSecret,
        pk: &mut Self::PublicKey,
    ) -> oqs::Result {
        let ct = ct.as_mut_ptr();
        let ss = ss.as_mut_ptr();
        let pk = pk.as_mut_ptr();
        oqs::calloqs!(OQS_KEM_frodokem_1344_aes_encaps(ct, ss, pk))
    }

    fn decaps(
        ct: &mut Self::Ciphertext,
        ss: &mut Self::SharedSecret,
        sk: &mut Self::SecretKey,
    ) -> oqs::Result {
        let ct = ct.as_mut_ptr();
        let ss = ss.as_mut_ptr();
        let sk = sk.as_mut_ptr();
        oqs::calloqs!(OQS_KEM_frodokem_1344_aes_decaps(ss, ct, sk))
    }

    fn decaps_measure(
        ct: &mut Self::Ciphertext,
        ss: &mut Self::SharedSecret,
        sk: &mut Self::SecretKey,
    ) -> std::result::Result<InternalMeasurments, String> {
        let ct = ct.as_mut_ptr();
        let ss = ss.as_mut_ptr();
        let sk = sk.as_mut_ptr();

        let mut measureer = InternalMeasureer::new();
        let (start, stop, cpu_start, cpu_stop, memcmp1, memcmp2) = measureer.mut_ref();
        oqs::calloqs!(OQS_KEM_frodokem_1344_aes_decaps_measure(
            ss, ct, sk, start, stop, cpu_start, cpu_stop, memcmp1, memcmp2
        ))?;
        Ok(InternalMeasurments::new(measureer))
    }
}
