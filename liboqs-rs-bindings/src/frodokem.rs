#![allow(non_snake_case)]
use crate as oqs;
use num::{Integer, NumCast};
use std::fmt::Debug;
use std::fmt::Display;

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

pub trait KemBuf: Debug {
    type T: Display + Copy + Default;
    fn new() -> Self;
    fn as_mut_ptr(&mut self) -> *mut Self::T;
    fn len() -> usize;
    fn as_slice(&self) -> &[Self::T];
    fn as_mut_slice(&mut self) -> &mut [Self::T];
}

pub struct FrodoKemParams<T> {
    pub PARAM_N: T,
    pub PARAM_NBAR: T,
    pub PARAM_B: T,
    pub PARAM_LOGQ: T,
    pub PARAM_QMAX: T,
}

pub trait FrodoKem {
    type PublicKey: KemBuf<T = u8>;
    type SecretKey: KemBuf<T = u8>;
    type Ciphertext: KemBuf<T = u8>;
    type SharedSecret: KemBuf<T = u8>;
    type Bp: KemBuf<T = u16>;
    type C: KemBuf<T = u16>;
    type Eppp: KemBuf<T = u16>;

    fn name() -> &'static str;

    fn params<T: Integer + NumCast>() -> FrodoKemParams<T>;

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
    fn calculate_Eppp(ct: &mut Self::Ciphertext, sk: &mut Self::SecretKey) -> Result<Self::Eppp, String>;
}

macro_rules! impl_kembuf {
    ($name:ident; $t:ty; $size:expr) => {
        impl KemBuf for $name {
            type T = $t;
            fn new() -> Self {
                Self([<Self::T as Default>::default(); $size as usize])
            }
            fn as_mut_ptr(&mut self) -> *mut $t {
                self.0.as_mut_ptr()
            }
            fn len() -> usize {
                $size
            }
            fn as_slice(&self) -> &[$t] {
                &self.0[..]
            }
            fn as_mut_slice(&mut self) -> &mut [$t] {
                &mut self.0[..]
            }
        }
        impl Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let s = self.as_slice();
                write!(f, "[(len: {})", s.len())?;
                if s.len() > 0 {
                    write!(f, " {}", s[0])?;
                    if s.len() > 5 {
                        for i in 0..5 {
                            write!(f, ", {}", s[i])?;
                        }
                        write!(f, ", ...")?;
                        let endrange = std::cmp::max(5, s.len() - 5);
                        for i in endrange..s.len() {
                            write!(f, ", {}", s[i])?;
                        }
                    } else {
                        for i in 0..s.len() {
                            write!(f, ", {}", s[i])?;
                        }
                    }
                }
                write!(f, "]")
            }
        }
    };
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
        pub struct $name;
        pub struct $PK([u8; $PKlen as usize]);
        pub struct $SK([u8; $SKlen as usize]);
        pub struct $CT([u8; $CTlen as usize]);
        pub struct $SS([u8; $SSlen as usize]);
        pub struct $Bp([u16; $N * $NBAR]);
        pub struct $C([u16; $NBAR *$NBAR]);
        pub struct $Eppp([u16; $NBAR *$NBAR]);
        impl_kembuf!($PK; u8;$PKlen);
        impl_kembuf!($SK; u8; $SKlen);
        impl_kembuf!($CT; u8; $CTlen);
        impl_kembuf!($SS; u8; $SSlen);
        impl_kembuf!($Bp; u16; $N * $NBAR);
        impl_kembuf!($C; u16; $NBAR *$NBAR);
        impl_kembuf!($Eppp; u16; $NBAR *$NBAR);

        impl FrodoKem for $name {
            type PublicKey = $PK;
            type SecretKey = $SK;
            type Ciphertext = $CT;
            type SharedSecret = $SS;
            type Bp = $Bp;
            type C = $C;
            type Eppp = $Eppp;

            fn name() -> &'static str {
                stringify!($name)
            }

            fn params<T: Integer+NumCast>() -> FrodoKemParams<T> {
                FrodoKemParams {
                    PARAM_N: NumCast::from($N).unwrap(),
                    PARAM_NBAR: NumCast::from($NBAR).unwrap(),
                    PARAM_B: NumCast::from($B).unwrap(),
                    PARAM_LOGQ: NumCast::from($LOGQ).unwrap(),
                    PARAM_QMAX: NumCast::from($QMAX).unwrap(),
                }
            }

            fn keypair(pk: &mut Self::PublicKey, sk: &mut Self::SecretKey) -> oqs::Result {
                let pk = pk.as_mut_ptr();
                let sk = sk.as_mut_ptr();
                oqs::calloqs!($keypair(pk, sk))
            }

            fn encaps(
                ct: &mut Self::Ciphertext,
                ss: &mut Self::SharedSecret,
                pk: &mut Self::PublicKey,
            ) -> oqs::Result {
                let ct = ct.as_mut_ptr();
                let ss = ss.as_mut_ptr();
                let pk = pk.as_mut_ptr();
                oqs::calloqs!($encaps(ct, ss, pk))
            }

            fn decaps(
                ct: &mut Self::Ciphertext,
                ss: &mut Self::SharedSecret,
                sk: &mut Self::SecretKey,
            ) -> oqs::Result {
                let ct = ct.as_mut_ptr();
                let ss = ss.as_mut_ptr();
                let sk = sk.as_mut_ptr();
                oqs::calloqs!($decaps(ss, ct, sk))
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
                oqs::calloqs!($decaps_measure(
                    ss, ct, sk, start, stop, cpu_start, cpu_stop, memcmp1, memcmp2
                ))?;
                Ok(InternalMeasurments::new(measureer))
            }

            fn unpack(
                ct: &mut Self::Ciphertext,
            ) -> std::result::Result<(Self::Bp, Self::C), String> {
                let mut bp = Self::Bp::new();
                let bp_out = bp.as_mut_ptr();
                let bp_outlen = Self::Bp::len();
                // Bits neccessary to represent the matrix, divided by number of bits per byte
                let bp_inlen = ($LOGQ * $N * $NBAR) / 8;
                let bp_input = ct.as_mut_slice()[0..bp_inlen].as_mut_ptr();
                let lsb = $LOGQ as u8;
                // frodo_unpack(Bp, PARAMS_N*$NBAR, ct_c1, (PARAMS_LOGQ*PARAMS_N*$NBAR)/8, PARAMS_LOGQ);
                calloqs!($unpack(bp_out, bp_outlen, bp_input, bp_inlen, lsb))?;
                let mut c = Self::C::new();
                let c_out = c.as_mut_ptr();
                let c_outlen = Self::C::len();
                // Bits neccessary to represent the matrix, divided by number of bits per byte
                let c_inlen = ($LOGQ * $NBAR * $NBAR) / 8;
                let c_input = ct.as_mut_slice()[bp_inlen..bp_inlen + c_inlen].as_mut_ptr();
                // frodo_unpack(C, $NBAR*$NBAR, ct_c2, (PARAMS_LOGQ*$NBAR*$NBAR)/8, PARAMS_LOGQ);
                calloqs!($unpack(c_out, c_outlen, c_input, c_inlen, lsb))?;
                Ok((bp, c))
            }

            fn pack(mut bp: Self::Bp, mut c: Self::C, ct: &mut Self::Ciphertext) -> oqs::Result {
                let c1_outlen = ($LOGQ * $N * $NBAR) / 8;
                let c1 = ct.as_mut_slice()[0..c1_outlen].as_mut_ptr();
                let bp_input = bp.as_mut_ptr();
                let bp_inlen = Self::Bp::len();
                let lsb = $LOGQ as u8;
                //frodo_pack(ct_c1, (PARAMS_LOGQ*PARAMS_N*$NBAR)/8, Bp, PARAMS_N*$NBAR, PARAMS_LOGQ);
                calloqs!($pack(c1, c1_outlen, bp_input, bp_inlen, lsb))?;

                let c2_outlen = ($LOGQ * $NBAR * $NBAR) / 8;
                let c2 = ct.as_mut_slice()[c1_outlen..c1_outlen + c2_outlen].as_mut_ptr();
                let c_input = c.as_mut_ptr();
                let c_inlen = Self::C::len();
                let lsb = $LOGQ as u8;
                //frodo_pack(ct_c2, (PARAMS_LOGQ*$NBAR*$NBAR)/8, C, $NBAR*$NBAR, PARAMS_LOGQ);
                calloqs!($pack(c2, c2_outlen, c_input, c_inlen, lsb))?;
                Ok(())
            }

            fn calculate_Eppp(ct: &mut Self::Ciphertext, sk: &mut Self::SecretKey) -> Result<Self::Eppp, String> {
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
        PARAMS_QMAX: 32767,
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
        PARAMS_QMAX: 65535,
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
