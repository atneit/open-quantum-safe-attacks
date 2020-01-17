#![allow(non_snake_case)]
use crate as oqs;

pub struct InternalMeasurments {
    pub memcmp_timing: Option<u64>,
    pub memcmp1: Option<bool>,
    pub memcmp2: Option<bool>,
}

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
    type Bp;
    type C;

    fn name() -> &'static str;

    fn zero_pk() -> Self::PublicKey;
    fn zero_sk() -> Self::SecretKey;
    fn zero_ct() -> Self::Ciphertext;
    fn zero_ss() -> Self::SharedSecret;

    fn ct_as_slice(ct: &mut Self::Ciphertext) -> &mut [u8];
    fn Bp_as_slice(ct: &mut Self::Bp) -> &mut [u16];
    fn C_as_slice(ct: &mut Self::C) -> &mut [u16];

    fn qmax() -> u16;

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
    fn unpack(ct: &mut Self::Ciphertext) -> std::result::Result<(Self::Bp, Self::C), String>;
    fn pack(bp: Self::Bp, c: Self::C, into: &mut Self::Ciphertext) -> oqs::Result;
}

pub struct FrodoKem640aes;
pub struct FrodoKem1344aes;

const PARAMS_NBAR: usize = 8;
const PARAMS_640_N: usize = 640;
const PARAMS_640_LOGQ: usize = 15;
const PARAMS_640_QMAX: u16 = 32767;
const PARAMS_1344_N: usize = 1344;
const PARAMS_1344_LOGQ: usize = 16;
const PARAMS_1344_QMAX: u16 = 65535;

impl FrodoKem for FrodoKem640aes {
    type PublicKey = [u8; oqs::OQS_KEM_frodokem_640_aes_length_public_key as usize];
    type SecretKey = [u8; oqs::OQS_KEM_frodokem_640_aes_length_secret_key as usize];
    type Ciphertext = [u8; oqs::OQS_KEM_frodokem_640_aes_length_ciphertext as usize];
    type SharedSecret = [u8; oqs::OQS_KEM_frodokem_640_aes_length_shared_secret as usize];
    type Bp = [u16; PARAMS_640_N * PARAMS_NBAR];
    type C = [u16; PARAMS_NBAR * PARAMS_NBAR];

    fn name() -> &'static str {
        "FrodoKem640aes"
    }

    fn zero_pk() -> Self::PublicKey {
        [0u8; oqs::OQS_KEM_frodokem_640_aes_length_public_key as usize]
    }
    fn zero_sk() -> Self::SecretKey {
        [0u8; oqs::OQS_KEM_frodokem_640_aes_length_secret_key as usize]
    }
    fn zero_ct() -> Self::Ciphertext {
        [0u8; oqs::OQS_KEM_frodokem_640_aes_length_ciphertext as usize]
    }
    fn zero_ss() -> Self::SharedSecret {
        [0u8; oqs::OQS_KEM_frodokem_640_aes_length_shared_secret as usize]
    }

    fn ct_as_slice(ct: &mut Self::Ciphertext) -> &mut [u8] {
        &mut ct[..]
    }
    fn Bp_as_slice(bp: &mut Self::Bp) -> &mut [u16] {
        &mut bp[..]
    }
    fn C_as_slice(c: &mut Self::C) -> &mut [u16] {
        &mut c[..]
    }

    fn qmax() -> u16 {
        PARAMS_640_QMAX
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

    fn unpack(ct: &mut Self::Ciphertext) -> std::result::Result<(Self::Bp, Self::C), String> {
        let mut bp: Self::Bp = [0; PARAMS_640_N * PARAMS_NBAR];
        let bp_out = bp.as_mut_ptr();
        let bp_outlen = bp.len();
        // Bits neccessary to represent the matrix, divided by number of bits per byte
        let bp_inlen = (PARAMS_640_LOGQ * PARAMS_640_N * PARAMS_NBAR) / 8;
        let bp_input = ct[0..bp_inlen].as_mut_ptr();
        let lsb = PARAMS_640_LOGQ as u8;
        // frodo_unpack(Bp, PARAMS_N*PARAMS_NBAR, ct_c1, (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8, PARAMS_LOGQ);
        calloqs!(oqs_kem_frodokem_640_aes_unpack(
            bp_out, bp_outlen, bp_input, bp_inlen, lsb
        ))?;
        let mut c: Self::C = [0; PARAMS_NBAR * PARAMS_NBAR];
        let c_out = c.as_mut_ptr();
        let c_outlen = c.len();
        // Bits neccessary to represent the matrix, divided by number of bits per byte
        let c_inlen = (PARAMS_640_LOGQ * PARAMS_NBAR * PARAMS_NBAR) / 8;
        let c_input = ct[bp_inlen..bp_inlen + c_inlen].as_mut_ptr();
        // frodo_unpack(C, PARAMS_NBAR*PARAMS_NBAR, ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, PARAMS_LOGQ);
        calloqs!(oqs_kem_frodokem_640_aes_unpack(
            c_out, c_outlen, c_input, c_inlen, lsb
        ))?;
        Ok((bp, c))
    }

    fn pack(mut bp: Self::Bp, mut c: Self::C, ct: &mut Self::Ciphertext) -> oqs::Result {
        let c1_outlen = (PARAMS_640_LOGQ * PARAMS_640_N * PARAMS_NBAR) / 8;
        let c1 = ct[0..c1_outlen].as_mut_ptr();
        let bp_input = bp.as_mut_ptr();
        let bp_inlen = bp.len();
        let lsb = PARAMS_640_LOGQ as u8;
        //frodo_pack(ct_c1, (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8, Bp, PARAMS_N*PARAMS_NBAR, PARAMS_LOGQ);
        calloqs!(oqs_kem_frodokem_640_aes_pack(
            c1, c1_outlen, bp_input, bp_inlen, lsb
        ))?;

        let c2_outlen = (PARAMS_640_LOGQ * PARAMS_NBAR * PARAMS_NBAR) / 8;
        let c2 = ct[c1_outlen..c1_outlen + c2_outlen].as_mut_ptr();
        let c_input = c.as_mut_ptr();
        let c_inlen = c.len();
        let lsb = PARAMS_640_LOGQ as u8;
        //frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
        calloqs!(oqs_kem_frodokem_640_aes_pack(
            c2, c2_outlen, c_input, c_inlen, lsb
        ))?;
        Ok(())
    }
}

impl FrodoKem for FrodoKem1344aes {
    type PublicKey = [u8; oqs::OQS_KEM_frodokem_1344_aes_length_public_key as usize];
    type SecretKey = [u8; oqs::OQS_KEM_frodokem_1344_aes_length_secret_key as usize];
    type Ciphertext = [u8; oqs::OQS_KEM_frodokem_1344_aes_length_ciphertext as usize];
    type SharedSecret = [u8; oqs::OQS_KEM_frodokem_1344_aes_length_shared_secret as usize];
    type Bp = [u16; PARAMS_1344_N * PARAMS_NBAR];
    type C = [u16; PARAMS_NBAR * PARAMS_NBAR];

    fn name() -> &'static str {
        "FrodoKem1344aes"
    }

    fn zero_pk() -> Self::PublicKey {
        [0u8; oqs::OQS_KEM_frodokem_1344_aes_length_public_key as usize]
    }
    fn zero_sk() -> Self::SecretKey {
        [0u8; oqs::OQS_KEM_frodokem_1344_aes_length_secret_key as usize]
    }
    fn zero_ct() -> Self::Ciphertext {
        [0u8; oqs::OQS_KEM_frodokem_1344_aes_length_ciphertext as usize]
    }
    fn zero_ss() -> Self::SharedSecret {
        [0u8; oqs::OQS_KEM_frodokem_1344_aes_length_shared_secret as usize]
    }

    fn ct_as_slice(ct: &mut Self::Ciphertext) -> &mut [u8] {
        &mut ct[..]
    }
    fn Bp_as_slice(bp: &mut Self::Bp) -> &mut [u16] {
        &mut bp[..]
    }
    fn C_as_slice(c: &mut Self::C) -> &mut [u16] {
        &mut c[..]
    }

    fn qmax() -> u16 {
        PARAMS_1344_QMAX
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

    fn unpack(ct: &mut Self::Ciphertext) -> std::result::Result<(Self::Bp, Self::C), String> {
        let mut bp: Self::Bp = [0; PARAMS_1344_N * PARAMS_NBAR];
        let bp_out = bp.as_mut_ptr();
        let bp_outlen = bp.len();
        // Bits neccessary to represent the matrix, divided by number of bits per byte
        let bp_inlen = (PARAMS_1344_LOGQ * PARAMS_1344_N * PARAMS_NBAR) / 8;
        let bp_input = ct[0..bp_inlen].as_mut_ptr();
        let lsb = PARAMS_1344_LOGQ as u8;
        // frodo_unpack(Bp, PARAMS_N*PARAMS_NBAR, ct_c1, (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8, PARAMS_LOGQ);
        calloqs!(oqs_kem_frodokem_1344_aes_unpack(
            bp_out, bp_outlen, bp_input, bp_inlen, lsb
        ))?;
        let mut c: Self::C = [0; PARAMS_NBAR * PARAMS_NBAR];
        let c_out = c.as_mut_ptr();
        let c_outlen = c.len();
        // Bits neccessary to represent the matrix, divided by number of bits per byte
        let c_inlen = (PARAMS_1344_LOGQ * PARAMS_NBAR * PARAMS_NBAR) / 8;
        let c_input = ct[bp_inlen..bp_inlen + c_inlen].as_mut_ptr();
        // frodo_unpack(C, PARAMS_NBAR*PARAMS_NBAR, ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, PARAMS_LOGQ);
        calloqs!(oqs_kem_frodokem_1344_aes_unpack(
            c_out, c_outlen, c_input, c_inlen, lsb
        ))?;
        Ok((bp, c))
    }

    fn pack(mut bp: Self::Bp, mut c: Self::C, ct: &mut Self::Ciphertext) -> oqs::Result {
        let c1_outlen = (PARAMS_1344_LOGQ * PARAMS_1344_N * PARAMS_NBAR) / 8;
        let c1 = ct[0..c1_outlen].as_mut_ptr();
        let bp_input = bp.as_mut_ptr();
        let bp_inlen = bp.len();
        let lsb = PARAMS_1344_LOGQ as u8;
        //frodo_pack(ct_c1, (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8, Bp, PARAMS_N*PARAMS_NBAR, PARAMS_LOGQ);
        calloqs!(oqs_kem_frodokem_1344_aes_pack(
            c1, c1_outlen, bp_input, bp_inlen, lsb
        ))?;

        let c2_outlen = (PARAMS_1344_LOGQ * PARAMS_NBAR * PARAMS_NBAR) / 8;
        let c2 = ct[c1_outlen..c1_outlen + c2_outlen].as_mut_ptr();
        let c_input = c.as_mut_ptr();
        let c_inlen = c.len();
        let lsb = PARAMS_1344_LOGQ as u8;
        //frodo_pack(ct_c2, (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8, C, PARAMS_NBAR*PARAMS_NBAR, PARAMS_LOGQ);
        calloqs!(oqs_kem_frodokem_1344_aes_pack(
            c2, c2_outlen, c_input, c_inlen, lsb
        ))?;
        Ok(())
    }
}
