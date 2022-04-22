#![allow(non_snake_case)]
use crate as oqs;
use log::trace;
use num::{Integer, NumCast};
use oqs::{
    Address, InspectionTarget, InternalKemMeasurments, Kem, KemBuf, KemMeasure, Result, Sign,
};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fmt::Debug;
use std::fmt::Display;

pub struct InternalFrodoMeasurments {
    pub memcmp_timing: Option<u64>,
    pub memcmp1: Option<bool>,
    pub memcmp2: Option<bool>,
}

struct Measurments {
    start: u64,
    stop: u64,
    cpu_start: u32,
    cpu_stop: u32,
    memcmp1: u8,
    memcmp2: u8,
}

impl Measurments {
    fn new() -> Measurments {
        Measurments {
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

impl InternalFrodoMeasurments {
    fn new(m: Measurments) -> InternalFrodoMeasurments {
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
        InternalFrodoMeasurments {
            memcmp_timing: diff,
            memcmp1,
            memcmp2,
        }
    }
}

impl InternalKemMeasurments for InternalFrodoMeasurments {
    fn result_internal(&self) -> Option<u64> {
        self.memcmp_timing
    }
    fn result_oracle(&self) -> Option<u64> {
        if let Some(memcmp1) = self.memcmp1 {
            //memcmp1 has executed
            let mut time = 100; //base timing
            if memcmp1 {
                time += 50;
                //first part was identical
                if let Some(memcmp2) = self.memcmp2 {
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
    fn result_checkpoints(&self) -> Vec<u64> {
        unimplemented!();
    }

    fn checkpoint_names(&self) -> Vec<String> {
        unimplemented!()
    }
}

pub struct FrodoKemParams<T> {
    pub PARAM_N: T,
    pub PARAM_NBAR: T,
    pub PARAM_B: T,
    pub PARAM_LOGQ: T,
    pub PARAM_QMAX: T,
}

pub trait FrodoKem: KemMeasure {
    type Bp: KemBuf<T = u16>;
    type C: KemBuf<T = u16>;
    type Eppp: KemBuf<T = u16>;

    fn params<T: Integer + NumCast>() -> FrodoKemParams<T>;
    fn unpack(ct: &mut Self::Ciphertext) -> Result<(Self::Bp, Self::C)>;
    fn pack(bp: Self::Bp, c: Self::C, into: &mut Self::Ciphertext) -> Result<()>;
    fn calculate_Eppp(ct: &mut Self::Ciphertext, sk: &mut Self::SecretKey) -> Result<Self::Eppp>;
}

macro_rules! bind_frodokems {
    ($($name:ident : {
        PARAMS_N: $N:expr,
        PARAMS_NBAR: $NBAR:expr,
        PARAMS_B: $B:expr,
        PARAMS_LOGQ: $LOGQ:expr,
        PARAMS_QMAX: $QMAX:expr,
        PublicKey: $PK:ident[$PKlen:expr],
        SecretKey : $SK:ident[$SKlen:expr],
        Ciphertext : $CT:ident[$CTlen:expr],
        SharedSecret : $SS:ident[$SSlen:expr],
        Bp : $Bp:ident,
        C : $C:ident,
        Eppp: $Eppp:ident,
        keypair: $keypair:ident,
        encaps: $encaps:ident,
        decaps: $decaps:ident,
        decaps_measure: $decaps_measure:ident,
        calculate_Eppp: $calculate_Eppp:ident,
        unpack: $unpack:ident,
        pack: $pack:ident,
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

        pub struct $Bp([u16; $N * $NBAR]);
        pub struct $C([u16; $NBAR *$NBAR]);
        pub struct $Eppp([u16; $NBAR *$NBAR]);
        impl_kembuf!($Bp; u16; $N * $NBAR);
        impl_kembuf!($C; u16; $NBAR *$NBAR);
        impl_kembuf!($Eppp; u16; $NBAR *$NBAR);

        impl KemMeasure for $name {
            type InternalMeasurments = InternalFrodoMeasurments;

            fn decaps_measure(
                ct: &mut Self::Ciphertext,
                ss: &mut Self::SharedSecret,
                sk: &mut Self::SecretKey,
            ) -> Result<InternalFrodoMeasurments> {
                let ct = ct.as_mut_ptr();
                let ss = ss.as_mut_ptr();
                let sk = sk.as_mut_ptr();

                let mut measurments = Measurments::new();
                let (start, stop, cpu_start, cpu_stop, memcmp1, memcmp2) = measurments.mut_ref();
                oqs::calloqs!($decaps_measure(
                    ss, ct, sk, start, stop, cpu_start, cpu_stop, memcmp1, memcmp2
                ))?;
                Ok(InternalFrodoMeasurments::new(measurments))
            }

            fn modify(ct: &mut Self::Ciphertext, index_ij: usize, amount: Sign<u16>) -> Result<()>
            {
                #![allow(non_snake_case)]
                trace!("Entering {}", function_name!());
                //Unpack the buffer into a pair of matrices encoded as a vector
                let (Bp, mut C) = Self::unpack(ct)?;
                let Cslice = C.as_mut_slice();

                let tomod = Cslice[index_ij] as u32;

                let qmax: u32 = Self::params().PARAM_QMAX;

                let newval = match amount {
                    Sign::Plus(a) => (tomod + a as u32) % qmax,
                    Sign::Minus(a) => {
                        //add qmax to prevent negative wrapping
                        (tomod + qmax - a as u32) % qmax
                    }
                };

                Cslice[index_ij] = newval.try_into().unwrap();

                //Repack the matrices into the buffer
                Self::pack(Bp, C, ct)?;

                Ok(())
            }

            fn error_correction_limit() -> u16 {
                trace!("Entering {}", function_name!());
                let params = Self::params::<u32>();
                2u16.pow(params.PARAM_LOGQ - params.PARAM_B - 1)
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

        impl FrodoKem for $name {
            type Bp = $Bp;
            type C = $C;
            type Eppp = $Eppp;

            fn params<T: Integer+NumCast>() -> FrodoKemParams<T> {
                FrodoKemParams {
                    PARAM_N: NumCast::from($N).unwrap(),
                    PARAM_NBAR: NumCast::from($NBAR).unwrap(),
                    PARAM_B: NumCast::from($B).unwrap(),
                    PARAM_LOGQ: NumCast::from($LOGQ).unwrap(),
                    PARAM_QMAX: NumCast::from($QMAX).unwrap(),
                }
            }

            fn unpack(
                ct: &mut Self::Ciphertext,
            ) -> Result<(Self::Bp, Self::C)> {
                let mut bp = Self::Bp::new();
                let bp_out = bp.as_mut_ptr();
                let bp_outlen = Self::Bp::len() as u64;
                // Bits neccessary to represent the matrix, divided by number of bits per byte
                let bp_inlen = ($LOGQ * $N * $NBAR) / 8 ;
                let bp_input = ct.as_mut_slice()[0..bp_inlen].as_mut_ptr();
                let lsb = $LOGQ as u8;
                // frodo_unpack(Bp, PARAMS_N*$NBAR, ct_c1, (PARAMS_LOGQ*PARAMS_N*$NBAR)/8, PARAMS_LOGQ);
                calloqs!($unpack(bp_out, bp_outlen, bp_input, (bp_inlen as u64), lsb))?;
                let mut c = Self::C::new();
                let c_out = c.as_mut_ptr();
                let c_outlen = Self::C::len() as u64;
                // Bits neccessary to represent the matrix, divided by number of bits per byte
                let c_inlen = ($LOGQ * $NBAR * $NBAR) / 8;
                let c_input = ct.as_mut_slice()[bp_inlen..bp_inlen + c_inlen].as_mut_ptr();
                // frodo_unpack(C, $NBAR*$NBAR, ct_c2, (PARAMS_LOGQ*$NBAR*$NBAR)/8, PARAMS_LOGQ);
                calloqs!($unpack(c_out, c_outlen, c_input, (c_inlen as u64), lsb))?;
                Ok((bp, c))
            }

            fn pack(mut bp: Self::Bp, mut c: Self::C, ct: &mut Self::Ciphertext) -> Result<()> {
                let c1_outlen = ($LOGQ * $N * $NBAR) / 8;
                let c1 = ct.as_mut_slice()[0..c1_outlen].as_mut_ptr();
                let bp_input = bp.as_mut_ptr();
                let bp_inlen = Self::Bp::len() as u64;
                let lsb = $LOGQ as u8;
                //frodo_pack(ct_c1, (PARAMS_LOGQ*PARAMS_N*$NBAR)/8, Bp, PARAMS_N*$NBAR, PARAMS_LOGQ);
                calloqs!($pack(c1, (c1_outlen as u64), bp_input, bp_inlen, lsb))?;

                let c2_outlen = ($LOGQ * $NBAR * $NBAR) / 8;
                let c2 = ct.as_mut_slice()[c1_outlen..c1_outlen + c2_outlen].as_mut_ptr();
                let c_input = c.as_mut_ptr();
                let c_inlen = Self::C::len() as u64;
                let lsb = $LOGQ as u8;
                //frodo_pack(ct_c2, (PARAMS_LOGQ*$NBAR*$NBAR)/8, C, $NBAR*$NBAR, PARAMS_LOGQ);
                calloqs!($pack(c2, (c2_outlen as u64), c_input, c_inlen, lsb))?;
                Ok(())
            }

            fn calculate_Eppp(ct: &mut Self::Ciphertext, sk: &mut Self::SecretKey) -> Result<Self::Eppp> {
                let mut Eppp = Self::Eppp::new();
                let ct = ct.as_mut_ptr();
                let sk = sk.as_mut_ptr();
                let eppp = Eppp.as_mut_ptr();
                oqs::calloqs!($calculate_Eppp(ct, sk, eppp))?;
                Ok(Eppp)
            }
        }
    )*}
}

bind_frodokems! (
    FrodoKem640aes: {
        PARAMS_N: 640,
        PARAMS_NBAR: 8,
        PARAMS_B: 2,
        PARAMS_LOGQ: 15,
        PARAMS_QMAX: 32768,
        PublicKey: FrodoKem640AesPublicKey[oqs::OQS_KEM_frodokem_640_aes_length_public_key as usize],
        SecretKey : FrodoKem640AesSecretKey[oqs::OQS_KEM_frodokem_640_aes_length_secret_key as usize],
        Ciphertext : FrodoKem640AesCiphertext[oqs::OQS_KEM_frodokem_640_aes_length_ciphertext as usize],
        SharedSecret : FrodoKem640AesSharedSecret[oqs::OQS_KEM_frodokem_640_aes_length_shared_secret as usize],
        Bp : FrodoKem640AesBp,
        C : FrodoKem640AesC,
        Eppp : FrodoKem640AesEppp,
        keypair: OQS_KEM_frodokem_640_aes_keypair,
        encaps: OQS_KEM_frodokem_640_aes_encaps,
        decaps: OQS_KEM_frodokem_640_aes_decaps,
        decaps_measure: OQS_KEM_frodokem_640_aes_decaps_measure,
        calculate_Eppp: OQS_KEM_frodokem_640_aes_get_Eppp,
        unpack: oqs_kem_frodokem_640_aes_unpack,
        pack: oqs_kem_frodokem_640_aes_pack,
    },
    FrodoKem1344aes: {
        PARAMS_N: 1344,
        PARAMS_NBAR: 8,
        PARAMS_B: 4,
        PARAMS_LOGQ: 16,
        PARAMS_QMAX: 65536,
        PublicKey: FrodoKem1344AesPublicKey[oqs::OQS_KEM_frodokem_1344_aes_length_public_key as usize],
        SecretKey : FrodoKem1344AesSecretKey[oqs::OQS_KEM_frodokem_1344_aes_length_secret_key as usize],
        Ciphertext : FrodoKem1344AesCiphertext[oqs::OQS_KEM_frodokem_1344_aes_length_ciphertext as usize],
        SharedSecret : FrodoKem1344AesSharedSecret[oqs::OQS_KEM_frodokem_1344_aes_length_shared_secret as usize],
        Bp : FrodoKem1344AesBp,
        C : FrodoKem1344AesC,
        Eppp : FrodoKem1344AesEppp,
        keypair: OQS_KEM_frodokem_1344_aes_keypair,
        encaps: OQS_KEM_frodokem_1344_aes_encaps,
        decaps: OQS_KEM_frodokem_1344_aes_decaps,
        decaps_measure: OQS_KEM_frodokem_1344_aes_decaps_measure,
        calculate_Eppp: OQS_KEM_frodokem_1344_aes_get_Eppp,
        unpack: oqs_kem_frodokem_1344_aes_unpack,
        pack: oqs_kem_frodokem_1344_aes_pack,
    }
);
