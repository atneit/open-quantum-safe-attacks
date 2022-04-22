use crate as oqs;
use log::trace;
use num::{Integer, NumCast};
use oqs::{Kem, KemBuf, KemWithRejectionSampling, Result};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::fmt::Display;

pub struct BikeParams<T> {
    pub PARAM_N: T,
    pub PARAM_R: T,
    pub PARAM_T: T,
    pub PARAM_SK_OFFSET: T,
}

pub trait Bike: KemWithRejectionSampling {
    fn params<T: Integer + NumCast>() -> BikeParams<T>;

    /// Encapsulate with provided plaintext and provided error pattern.
    /// Error pattern 'ep' is a sparse slice indicating which bit positions
    /// in the error vector shall be set to 1.
    fn encaps_with_plaintext_and_error_pattern(
        ct: &mut Self::Ciphertext,
        ss: &mut Self::SharedSecret,
        pk: &mut Self::PublicKey,
        pt: &Self::Plaintext,
        ep: &[u32],
    ) -> self::Result<()>;

    fn decaps_intermediaries(
        ct: &mut Self::Ciphertext,
        ss: &mut Self::SharedSecret,
        sk: &mut Self::SecretKey,
    ) -> self::Result<(u32, bool)>;
}

macro_rules! bind_bike {
    ($($name:ident : {
        PARAM_R: $PARAM_R:expr,
        PARAM_N: $PARAM_N:expr,
        PARAM_T: $PARAM_T:expr,
        PARAM_D: $PARAM_D:expr,
        PublicKey: $PK:ident[$PKlen:expr],
        SecretKey : $SK:ident[$SKlen:expr],
        Ciphertext : $CT:ident[$CTlen:expr],
        SharedSecret : $SS:ident[$SSlen:expr],
        Plaintext: $PT:ident[$PTlen:expr],
        keypair: $keypair:ident,
        encaps: $encaps:ident,
        encaps_with_plaintext: $encaps_with_plaintext:ident,
        decaps: $decaps:ident,
        decaps_intermediaries: $decaps_intermediaries:ident,
        numrejections: $numrejections:ident,
    }),+) => {$(

        bind_kem!(
            $name: {
                PublicKey: $PK[$PKlen],
                SecretKey: $SK[$SKlen],
                Ciphertext: $CT[$CTlen],
                SharedSecret: $SS[$SSlen],
                keypair: $keypair,
                encaps: $encaps,
                decaps: $decaps,
            }
        );

        pub struct $PT([u8; $PTlen as usize]);
        impl_kembuf!($PT; u8;$PTlen);

        impl KemWithRejectionSampling for $name {
            type Plaintext = $PT;

            fn num_rejections(pt: &mut Self::Plaintext) -> Result<u64>
            {
                let pt = pt.as_mut_ptr();
                let mut rejections = 0i32;
                let r_ptr = (&mut rejections) as *mut i32;
                oqs::calloqs!($numrejections(r_ptr, pt))?;
                Ok(rejections as u64)
            }

            fn encaps_with_plaintext(
                ct: &mut Self::Ciphertext,
                ss: &mut Self::SharedSecret,
                pk: &mut Self::PublicKey,
                pt: &mut Self::Plaintext,
            ) -> self::Result<()>
            {
                let ct = ct.as_mut_ptr();
                let ss = ss.as_mut_ptr();
                let pk = pk.as_mut_ptr();
                let pt = pt.as_mut_ptr();
                let e = std::ptr::null();
                oqs::calloqs!($encaps_with_plaintext(ct, ss, pk, pt, e, 0))
            }
        }

        impl Bike for $name {
            fn params<T: Integer + NumCast>() -> BikeParams<T> {
                BikeParams {
                    PARAM_N: NumCast::from($PARAM_N).unwrap(),
                    PARAM_R: NumCast::from($PARAM_R).unwrap(),
                    PARAM_T: NumCast::from($PARAM_T).unwrap(),
                    PARAM_SK_OFFSET: NumCast::from(
                        2 * // compressed_idx_d_ar_t
                        $PARAM_D * // compressed_idx_d_t
                        std::mem::size_of::<u32>() // idx_t
                    ).unwrap()
                }
            }

            fn encaps_with_plaintext_and_error_pattern(
                ct: &mut Self::Ciphertext,
                ss: &mut Self::SharedSecret,
                pk: &mut Self::PublicKey,
                pt: &Self::Plaintext,
                ep: &[u32],
            ) -> self::Result<()>{
                let ct = ct.as_mut_ptr();
                let ss = ss.as_mut_ptr();
                let pk = pk.as_mut_ptr();
                let pt = pt.as_ptr();
                let eplen = ep.len() as i32;
                let ep = ep.as_ptr();
                oqs::calloqs!($encaps_with_plaintext(ct, ss, pk, pt, ep, eplen))
            }

            fn decaps_intermediaries(
                ct: &mut Self::Ciphertext,
                ss: &mut Self::SharedSecret,
                sk: &mut Self::SecretKey,
            ) -> self::Result<(u32, bool)>{
                let ct = ct.as_mut_ptr();
                let ss = ss.as_mut_ptr();
                let sk = sk.as_mut_ptr();
                let mut rejections = 0i32;
                let r_ptr = (&mut rejections) as *mut i32;
                oqs::calloqs!($decaps_intermediaries(r_ptr, ss, ct, sk))?;
                let success = (rejections / 1_000_000) > 0;
                rejections %= 1_000_000;

                Ok((rejections as u32, success))
            }
        }
    )*}
}

bind_bike! (
    BikeL1: {
        PARAM_R: 12323,
        PARAM_N: 12323*2,
        PARAM_T: 134,
        PARAM_D: 71,
        PublicKey: BikeL1PublicKey[oqs::OQS_KEM_bike_l1_length_public_key as usize],
        SecretKey : BikeL1SecretKey[oqs::OQS_KEM_bike_l1_length_secret_key as usize],
        Ciphertext : BikeL1Ciphertext[oqs::OQS_KEM_bike_l1_length_ciphertext as usize],
        SharedSecret : BikeL1SharedSecret[oqs::OQS_KEM_bike_l1_length_shared_secret as usize],
        Plaintext : BikeL1Plaintext[oqs::OQS_KEM_bike_l1_length_shared_secret as usize],
        keypair: OQS_KEM_bike_l1_keypair,
        encaps: OQS_KEM_bike_l1_encaps,
        encaps_with_plaintext: OQS_KEM_bike_l1_encaps_with_m_e,
        decaps: OQS_KEM_bike_l1_decaps,
        decaps_intermediaries: OQS_KEM_bike_l1_decaps_intermediaries,
        numrejections: OQS_KEM_bike_l1_numrejections,
    },
    BikeL3: {
        PARAM_R: 24659,
        PARAM_N: 24659*2,
        PARAM_T: 199,
        PARAM_D: 71,
        PublicKey: BikeL3PublicKey[oqs::OQS_KEM_bike_l3_length_public_key as usize],
        SecretKey : BikeL3SecretKey[oqs::OQS_KEM_bike_l3_length_secret_key as usize],
        Ciphertext : BikeL3Ciphertext[oqs::OQS_KEM_bike_l3_length_ciphertext as usize],
        SharedSecret : BikeL3SharedSecret[oqs::OQS_KEM_bike_l3_length_shared_secret as usize],
        Plaintext : BikeL3Plaintext[oqs::OQS_KEM_bike_l1_length_shared_secret as usize],
        keypair: OQS_KEM_bike_l3_keypair,
        encaps: OQS_KEM_bike_l3_encaps,
        encaps_with_plaintext: OQS_KEM_bike_l3_encaps_with_m_e,
        decaps: OQS_KEM_bike_l3_decaps,
        decaps_intermediaries: OQS_KEM_bike_l3_decaps_intermediaries,
        numrejections: OQS_KEM_bike_l3_numrejections,
    }
);
