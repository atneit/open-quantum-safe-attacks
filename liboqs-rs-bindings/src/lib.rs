#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

use std::fmt::{Debug, Display};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

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

pub type Result = std::result::Result<(), String>;

impl From<OqsStatus> for Result {
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

pub trait KemBuf: Display + Debug {
    type T: Display + Copy + Default;
    fn new() -> Self;
    fn as_mut_ptr(&mut self) -> *mut Self::T;
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
    };
}

pub mod frodokem;

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn it_works() {
        let a = unsafe { OQS_KEM_alg_count() };
        assert_eq!(42, a);
    }
}
