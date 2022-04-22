use crate as oqs;
use log::trace;
use num::{Integer, NumCast};
use oqs::{
    Address, InspectionTarget, InternalKemMeasurments, Kem, KemBuf, KemMeasure, Result, Sign,
};
use serde::{Deserialize, Serialize};
use std::ffi::CStr;
use std::fmt::{Debug, Display};

pub struct InternalKyberMeasurments {
    rdtscp_start_stop: Option<(u64, u64)>,
    checkpoints: Vec<(&'static CStr, u64)>,
    fail: bool,
}

impl InternalKemMeasurments for InternalKyberMeasurments {
    fn result_internal(&self) -> Option<u64> {
        self.rdtscp_start_stop.map(|(start, stop)| stop - start)
    }

    fn result_oracle(&self) -> Option<u64> {
        if self.fail {
            Some(50)
        } else {
            Some(100)
        }
    }

    fn result_checkpoints(&self) -> Vec<u64> {
        if let Some((_, stop)) = self.rdtscp_start_stop {
            let mut res: Vec<_> = self
                .checkpoints
                .windows(2)
                .map(|window| window[1].1 - window[0].1)
                .collect();
            if let Some(last) = self.checkpoints.last() {
                res.push(stop - last.1);
            }
            res
        } else {
            vec![]
        }
    }

    fn checkpoint_names(&self) -> Vec<String> {
        self.checkpoints
            .iter()
            .map(|(l, _)| l.to_string_lossy().to_string())
            .collect()
    }
}

struct InternalKyberMeasurmentsBuilder {
    checkpoints: [u64; 100],
    labels: [*const u8; 100],
    fail: i32,
}

impl InternalKyberMeasurmentsBuilder {
    fn new() -> InternalKyberMeasurmentsBuilder {
        let r#static = "".as_ptr();
        InternalKyberMeasurmentsBuilder {
            checkpoints: [0; 100],
            labels: [r#static; 100],
            fail: 0,
        }
    }

    fn mut_ref(&mut self) -> (*mut u64, *mut *const u8, &mut i32) {
        //
        (
            self.checkpoints.as_mut_ptr(),
            self.labels.as_mut_ptr(),
            &mut self.fail,
        )
    }

    fn build(self) -> InternalKyberMeasurments {
        let mut checkpoints = self
            .checkpoints
            .iter()
            .zip(&self.labels)
            .take_while(|(m, _)| **m > 0)
            .map(|(m, l)| {
                let l = unsafe { CStr::from_ptr((*l) as *const i8) };
                (l, *m)
            });

        let first = checkpoints.next();
        let mut checkpoints: Vec<_> = checkpoints.collect();
        let last = checkpoints.pop();
        let rdtscp_start_stop = if let (Some(first), Some(last)) = (first, last) {
            Some((first.1, last.1))
        } else {
            None
        };
        InternalKyberMeasurments {
            rdtscp_start_stop,
            checkpoints,
            fail: self.fail != 0,
        }
    }
}

pub struct KyberParams<T> {
    pub PARAM_N: T,
    pub PARAM_Q: T,
    pub PARAM_K: T,
}

pub trait Kyber: KemMeasure {
    type bp: KemBuf<T = i16>;
    type v: KemBuf<T = i16>;

    fn params<T: Integer + NumCast>() -> KyberParams<T>;
    fn unpack(ct: &mut Self::Ciphertext) -> Result<(Self::bp, Self::v)>;
    fn pack(bp: Self::bp, v: Self::v, into: &mut Self::Ciphertext) -> Result<()>;
}

macro_rules! bind_kyber {
    ($($name:ident : {
        PARAMS_N: $N:expr,
        PARAMS_Q: $Q:expr,
        PARAMS_K: $K:expr,
        PublicKey: $PK:ident[$PKlen:expr],
        SecretKey : $SK:ident[$SKlen:expr],
        Ciphertext : $CT:ident[$CTlen:expr],
        SharedSecret : $SS:ident[$SSlen:expr],
        keypair: $keypair:ident,
        encaps: $encaps:ident,
        decaps: $decaps:ident,
        decaps_measured: $decaps_measured:ident,
        bp: $bp:ident,
        v: $v:ident,
        pack: $pack:ident,
        unpack: $unpack:ident,
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

        pub struct $bp([i16; $K * $N]);
        pub struct $v([i16; $N]);
        impl_kembuf!($bp; i16; $K * $N);
        impl_kembuf!($v; i16; $N);

        impl KemMeasure for $name {
            type InternalMeasurments = InternalKyberMeasurments;

            fn decaps_measure(
                ct: &mut Self::Ciphertext,
                ss: &mut Self::SharedSecret,
                sk: &mut Self::SecretKey,
            ) -> Result<InternalKyberMeasurments> {
                let ct = ct.as_mut_ptr();
                let ss = ss.as_mut_ptr();
                let sk = sk.as_mut_ptr();

                let mut measurments = InternalKyberMeasurmentsBuilder::new();
                let (rdtscp_buffer, rdtscp_labels, fail) = measurments.mut_ref();
                crate::calloqs!($decaps_measured(ss, ct, sk, rdtscp_buffer, rdtscp_labels, fail))?;
                Ok(measurments.build())
            }

            fn modify(ct: &mut Self::Ciphertext, index: usize, amount: Sign<u16>) -> Result<()>
            {
                trace!("Entering {}(.., .., {:?})", function_name!(), amount);
                match amount {
                    Sign::Plus(0) | Sign::Minus(0)  => {
                        return Ok(());
                    }
                    _ => {},
                }

                let (mut bp, mut v) = Self::unpack(ct)?;

                let target = if <Self as Kyber>::bp::len() <= index {
                    &mut v.as_mut_slice()[index - <Self as Kyber>::bp::len()]
                } else {
                    &mut bp.as_mut_slice()[index]
                };

                match amount {
                    Sign::Plus(a) => *target += a as i16,
                    Sign::Minus(a) => *target -= a as i16,
                }

                Self::pack(bp, v, ct)?;

                Ok(())
            }

            fn error_correction_limit() -> u16 {
                trace!("Entering {}", function_name!());
                todo!();
            }

            fn inspect_address(target: InspectionTarget) -> Address{
                match target {
                    InspectionTarget::Decaps => $crate::$decaps as *const u8
                }
            }

            fn inspect_symbolname(target: InspectionTarget) -> &'static str {
                match target {
                    InspectionTarget::Decaps => stringify!($decaps)
                }
            }
        }

        impl Kyber for $name {
            type bp = $bp;
            type v = $v;

            fn params<T: Integer + NumCast>() -> KyberParams<T>
            {
                KyberParams {
                    PARAM_N: NumCast::from($N).unwrap(),
                    PARAM_Q: NumCast::from($Q).unwrap(),
                    PARAM_K: NumCast::from($K).unwrap(),
                }
            }
            fn unpack(ct: &mut Self::Ciphertext) -> Result<(Self::bp, Self::v)>
            {
                let mut bp = Self::bp::new();
                let mut v = Self::v::new();
                {
                    let ct = ct.as_mut_ptr();
                    let bp = bp.as_mut_ptr();
                    let v = v.as_mut_ptr();
                    crate::calloqs!($unpack(bp, v, ct))?;
                }
                Ok((bp, v))
            }
            fn pack(mut bp: Self::bp, mut v: Self::v, into: &mut Self::Ciphertext) -> Result<()>
            {
                let ct = into.as_mut_ptr();
                let bp = bp.as_mut_ptr();
                let v = v.as_mut_ptr();
                crate::calloqs!($pack(ct, bp, v))?;
                Ok(())
            }
        }
    )*}
}

bind_kyber! (
    Kyber512: {
        PARAMS_N: 256,
        PARAMS_Q: 3329,
        PARAMS_K: 2_usize,
        PublicKey: Kyber512PublicKey[crate::OQS_KEM_kyber_512_length_public_key as usize],
        SecretKey : Kyber512SecretKey[crate::OQS_KEM_kyber_512_length_secret_key as usize],
        Ciphertext : Kyber512Ciphertext[crate::OQS_KEM_kyber_512_length_ciphertext as usize],
        SharedSecret : Kyber512SharedSecret[crate::OQS_KEM_kyber_512_length_shared_secret as usize],
        keypair: OQS_KEM_kyber_512_keypair,
        encaps: OQS_KEM_kyber_512_encaps,
        decaps: OQS_KEM_kyber_512_decaps,
        decaps_measured: OQS_KEM_kyber_512_decaps_measure,
        bp: Kyber512bp,
        v: Kyber512v,
        pack: pqcrystals_kyber512_ref_pack_ciphertext,
        unpack: pqcrystals_kyber512_ref_unpack_ciphertext,
    },
    Kyber512_90S: {
        PARAMS_N: 256,
        PARAMS_Q: 3329,
        PARAMS_K: 2_usize,
        PublicKey: Kyber512_90SPublicKey[crate::OQS_KEM_kyber_512_90s_length_public_key as usize],
        SecretKey : Kyber512_90SSecretKey[crate::OQS_KEM_kyber_512_90s_length_secret_key as usize],
        Ciphertext : Kyber512_90SCiphertext[crate::OQS_KEM_kyber_512_90s_length_ciphertext as usize],
        SharedSecret : Kyber512_90SSharedSecret[crate::OQS_KEM_kyber_512_90s_length_shared_secret as usize],
        keypair: OQS_KEM_kyber_512_90s_keypair,
        encaps: OQS_KEM_kyber_512_90s_encaps,
        decaps: OQS_KEM_kyber_512_90s_decaps,
        decaps_measured: OQS_KEM_kyber_512_90s_decaps_measure,
        bp: Kyber512_90Sbp,
        v: Kyber512_90Sv,
        pack: pqcrystals_kyber512_90s_ref_pack_ciphertext,
        unpack: pqcrystals_kyber512_90s_ref_unpack_ciphertext,
    },
    Kyber768: {
        PARAMS_N: 256,
        PARAMS_Q: 3329,
        PARAMS_K: 3_usize,
        PublicKey: Kyber768PublicKey[crate::OQS_KEM_kyber_768_length_public_key as usize],
        SecretKey : Kyber768SecretKey[crate::OQS_KEM_kyber_768_length_secret_key as usize],
        Ciphertext : Kyber768Ciphertext[crate::OQS_KEM_kyber_768_length_ciphertext as usize],
        SharedSecret : Kyber768SharedSecret[crate::OQS_KEM_kyber_768_length_shared_secret as usize],
        keypair: OQS_KEM_kyber_768_keypair,
        encaps: OQS_KEM_kyber_768_encaps,
        decaps: OQS_KEM_kyber_768_decaps,
        decaps_measured: OQS_KEM_kyber_768_decaps_measure,
        bp: Kyber768bp,
        v: Kyber768v,
        pack: pqcrystals_kyber768_ref_pack_ciphertext,
        unpack: pqcrystals_kyber768_ref_unpack_ciphertext,
    },
    Kyber768_90S: {
        PARAMS_N: 256,
        PARAMS_Q: 3329,
        PARAMS_K: 3_usize,
        PublicKey: Kyber768_90SPublicKey[crate::OQS_KEM_kyber_768_90s_length_public_key as usize],
        SecretKey : Kyber768_90SSecretKey[crate::OQS_KEM_kyber_768_90s_length_secret_key as usize],
        Ciphertext : Kyber768_90SCiphertext[crate::OQS_KEM_kyber_768_90s_length_ciphertext as usize],
        SharedSecret : Kyber768_90SSharedSecret[crate::OQS_KEM_kyber_768_90s_length_shared_secret as usize],
        keypair: OQS_KEM_kyber_768_90s_keypair,
        encaps: OQS_KEM_kyber_768_90s_encaps,
        decaps: OQS_KEM_kyber_768_90s_decaps,
        decaps_measured: OQS_KEM_kyber_768_90s_decaps_measure,
        bp: Kyber768_90Sbp,
        v: Kyber768_90Sv,
        pack: pqcrystals_kyber768_90s_ref_pack_ciphertext,
        unpack: pqcrystals_kyber768_90s_ref_unpack_ciphertext,
    },
    Kyber1024: {
        PARAMS_N: 256,
        PARAMS_Q: 3329,
        PARAMS_K: 4_usize,
        PublicKey: Kyber1024PublicKey[crate::OQS_KEM_kyber_1024_length_public_key as usize],
        SecretKey : Kyber1024SecretKey[crate::OQS_KEM_kyber_1024_length_secret_key as usize],
        Ciphertext : Kyber1024Ciphertext[crate::OQS_KEM_kyber_1024_length_ciphertext as usize],
        SharedSecret : Kyber1024SharedSecret[crate::OQS_KEM_kyber_1024_length_shared_secret as usize],
        keypair: OQS_KEM_kyber_1024_keypair,
        encaps: OQS_KEM_kyber_1024_encaps,
        decaps: OQS_KEM_kyber_1024_decaps,
        decaps_measured: OQS_KEM_kyber_1024_decaps_measure,
        bp: Kyber1024bp,
        v: Kyber1024v,
        pack: pqcrystals_kyber1024_ref_pack_ciphertext,
        unpack: pqcrystals_kyber1024_ref_unpack_ciphertext,
    },
    Kyber1024_90S: {
        PARAMS_N: 256,
        PARAMS_Q: 3329,
        PARAMS_K: 4_usize,
        PublicKey: Kyber1024_90SPublicKey[crate::OQS_KEM_kyber_1024_90s_length_public_key as usize],
        SecretKey : Kyber1024_90SSecretKey[crate::OQS_KEM_kyber_1024_90s_length_secret_key as usize],
        Ciphertext : Kyber1024_90SCiphertext[crate::OQS_KEM_kyber_1024_90s_length_ciphertext as usize],
        SharedSecret : Kyber1024_90SSharedSecret[crate::OQS_KEM_kyber_1024_90s_length_shared_secret as usize],
        keypair: OQS_KEM_kyber_1024_90s_keypair,
        encaps: OQS_KEM_kyber_1024_90s_encaps,
        decaps: OQS_KEM_kyber_1024_90s_decaps,
        decaps_measured: OQS_KEM_kyber_1024_90s_decaps_measure,
        bp: Kyber1024_90Sbp,
        v: Kyber1024_90Sv,
        pack: pqcrystals_kyber1024_90s_ref_pack_ciphertext,
        unpack: pqcrystals_kyber1024_90s_ref_unpack_ciphertext,
    }
);
