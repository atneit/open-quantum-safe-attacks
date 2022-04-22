#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(deref_nullptr)] //TODO: this is due to rust-lang/rust-bindgen#1651, remove when solved

use ::serde::{Deserialize, Serialize};
use log::trace;
use std::fmt::{Debug, Display};

#[allow(clippy::all, dead_code)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
use bindings::*;

#[derive(Debug)]
pub enum OqsStatus {
    OqsError,
    OqsSuccess,
    OqsExternalLibErrorOpenssl,
}

impl From<OQS_STATUS> for OqsStatus {
    fn from(status: OQS_STATUS) -> Self {
        match status {
            0 => OqsStatus::OqsSuccess,
            50 => OqsStatus::OqsExternalLibErrorOpenssl,
            _ => OqsStatus::OqsError,
        }
    }
}

impl From<()> for OqsStatus {
    fn from(_: ()) -> Self {
        OqsStatus::OqsSuccess
    }
}

pub type Result<T> = std::result::Result<T, String>;

impl From<OqsStatus> for Result<()> {
    fn from(status: OqsStatus) -> Self {
        match status {
            OqsStatus::OqsSuccess => Ok(()),
            OqsStatus::OqsExternalLibErrorOpenssl => Err(String::from("External error in openssl")),
            OqsStatus::OqsError => Err(String::from("Error in liboqs")),
        }
    }
}

#[macro_export]
macro_rules! calloqs {
    ($funcname:ident($($args:tt),*)) => {{
        use log::trace;
        trace!("liboqs function {} executing.", stringify!($funcname));
        let ret: $crate::OqsStatus = unsafe { $crate::$funcname($($args,)+) }.into();
        trace!("liboqs function {} returned {:?}", stringify!($funcname), ret);
        $crate::Result::from(ret)
    }};
}

#[macro_export]
macro_rules! function_name {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        &name[..name.len() - 3]
    }};
}

pub trait KemBuf:
    Display + Debug + Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>
{
    type T: Display + Copy + Default;
    fn new() -> Self;
    fn as_mut_ptr(&mut self) -> *mut Self::T;
    fn as_ptr(&self) -> *const Self::T;
    fn len() -> usize;
    fn as_slice(&self) -> &[Self::T];
    fn as_mut_slice(&mut self) -> &mut [Self::T];
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
            fn as_ptr(&self) -> *const $t {
                self.0.as_ptr()
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
        impl Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let s = self.as_slice();
                write!(f, "[(len: {})", s.len())?;
                if s.len() > 0 {
                    write!(f, " {}", s[0])?;
                    for i in 0..s.len() {
                        write!(f, ", {}", s[i])?;
                    }
                }
                write!(f, "]")
            }
        }
        impl Clone for $name {
            fn clone(&self) -> Self {
                let mut new = Self([<<Self as KemBuf>::T as Default>::default(); $size as usize]);
                new.0.copy_from_slice(self.as_slice());
                new
            }
        }
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::ser::Serializer,
            {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some($size))?;
                for e in &self.0 {
                    seq.serialize_element(e)?;
                }
                seq.end()
            }
        }

        impl<'de> serde::de::Visitor<'de> for $name {
            type Value = [<Self as KemBuf>::T; $size as usize];

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a sequence of {} numbers", $size)
            }

            /// The input contains a sequence of elements.
            ///
            /// The default implementation fails with a type error.
            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                use ::std::mem::{transmute, MaybeUninit};
                trace!("{} called!", function_name!());

                if let Some(size) = seq.size_hint() {
                    if size != $size {
                        return Err(serde::de::Error::invalid_length(size, &self));
                    }
                }

                //Create an uninitialized array
                let mut array: [MaybeUninit<<Self as KemBuf>::T>; $size] =
                    unsafe { MaybeUninit::uninit().assume_init() };

                let newvalue = std::iter::from_fn(move || seq.next_element().unwrap());

                let mut last = 0;
                for (index, (dest, source)) in (&mut array[..]).iter_mut().zip(newvalue).enumerate()
                {
                    *dest = MaybeUninit::new(source);
                    last = index;
                }

                if last + 1 != $size {
                    return Err(serde::de::Error::invalid_length(last + 1, &self));
                }

                //Transform it to an initialized array
                Ok(unsafe { transmute::<_, [<Self as KemBuf>::T; $size]>(array) })
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::de::Deserializer<'de>,
            {
                let t = Self::new();
                let arr = deserializer.deserialize_seq(t)?;
                Ok(Self(arr))
            }
        }
    };
}

struct SHA512Buf([u8; 64]);
impl_kembuf!(SHA512Buf; u8;64);

#[derive(Debug)]
pub enum Sign<T> {
    Plus(T),
    Minus(T),
}

pub trait InternalKemMeasurments {
    fn result_internal(&self) -> Option<u64>;
    fn result_oracle(&self) -> Option<u64>;
    fn checkpoint_names(&self) -> Vec<String>;
    fn result_checkpoints(&self) -> Vec<u64>;
}

pub enum InspectionTarget {
    Decaps,
}

pub type Address = *const u8;

pub trait Kem: Debug + Clone + Serialize + for<'de> Deserialize<'de> {
    type PublicKey: KemBuf<T = u8>;
    type SecretKey: KemBuf<T = u8>;
    type Ciphertext: KemBuf<T = u8>;
    type SharedSecret: KemBuf<T = u8>;

    const NAME: &'static str;

    fn keypair() -> Result<(Self::PublicKey, Self::SecretKey)>;
    fn encaps(
        ct: &mut Self::Ciphertext,
        ss: &mut Self::SharedSecret,
        pk: &mut Self::PublicKey,
    ) -> self::Result<()>;
    fn decaps(
        ct: &mut Self::Ciphertext,
        ss: &mut Self::SharedSecret,
        sk: &mut Self::SecretKey,
    ) -> self::Result<()>;
}

pub trait KemMeasure: Kem {
    type InternalMeasurments: InternalKemMeasurments;

    fn decaps_measure(
        ct: &mut Self::Ciphertext,
        ss: &mut Self::SharedSecret,
        sk: &mut Self::SecretKey,
    ) -> std::result::Result<Self::InternalMeasurments, String>;

    fn modify(ct: &mut Self::Ciphertext, index_ij: usize, amount: Sign<u16>) -> self::Result<()>;

    fn error_correction_limit() -> u16;

    fn inspect_address(target: InspectionTarget) -> Address;
    fn inspect_symbolname(target: InspectionTarget) -> &'static str;
}

pub trait KemWithRejectionSampling: Kem {
    type Plaintext: KemBuf<T = u8>;

    fn num_rejections(pt: &mut Self::Plaintext) -> Result<u64>;

    fn encaps_with_plaintext(
        ct: &mut Self::Ciphertext,
        ss: &mut Self::SharedSecret,
        pk: &mut Self::PublicKey,
        pt: &mut Self::Plaintext,
    ) -> self::Result<()>;
}

macro_rules! bind_kem {
    ($($name:ident : {
        PublicKey: $PK:ident[$PKlen:expr],
        SecretKey : $SK:ident[$SKlen:expr],
        Ciphertext : $CT:ident[$CTlen:expr],
        SharedSecret : $SS:ident[$SSlen:expr],
        keypair: $keypair:ident,
        encaps: $encaps:ident,
        decaps: $decaps:ident,
    }),+) => {$(

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct $name;
        pub struct $PK([u8; $PKlen as usize]);
        pub struct $SK([u8; $SKlen as usize]);
        pub struct $CT([u8; $CTlen as usize]);
        pub struct $SS([u8; $SSlen as usize]);
        impl_kembuf!($PK; u8;$PKlen);
        impl_kembuf!($SK; u8; $SKlen);
        impl_kembuf!($CT; u8; $CTlen);
        impl_kembuf!($SS; u8; $SSlen);

        impl Kem for $name {
            type PublicKey = $PK;
            type SecretKey = $SK;
            type Ciphertext = $CT;
            type SharedSecret = $SS;

            const NAME: &'static str = stringify!($name);

            fn keypair() -> std::result::Result<(Self::PublicKey, Self::SecretKey), String> {
                let mut pk = Self::PublicKey::new();
                let mut sk= Self::SecretKey::new();
                {
                    let pk = pk.as_mut_ptr();
                    let sk = sk.as_mut_ptr();
                    oqs::calloqs!($keypair(pk, sk))?;
                }
                Ok((pk, sk))
            }

            fn encaps(
                ct: &mut Self::Ciphertext,
                ss: &mut Self::SharedSecret,
                pk: &mut Self::PublicKey,
            ) -> oqs::Result<()> {
                let ct = ct.as_mut_ptr();
                let ss = ss.as_mut_ptr();
                let pk = pk.as_mut_ptr();
                oqs::calloqs!($encaps(ct, ss, pk))
            }

            fn decaps(
                ct: &mut Self::Ciphertext,
                ss: &mut Self::SharedSecret,
                sk: &mut Self::SecretKey,
            ) -> oqs::Result<()> {
                let ct = ct.as_mut_ptr();
                let ss = ss.as_mut_ptr();
                let sk = sk.as_mut_ptr();
                oqs::calloqs!($decaps(ss, ct, sk))
            }
        }
    )*}
}

pub mod bike;
pub mod frodokem;
pub mod hqc;
pub mod kyber;

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn it_works() {
        let a = unsafe { OQS_KEM_alg_count() };
        assert_eq!(42, a);
    }
}
