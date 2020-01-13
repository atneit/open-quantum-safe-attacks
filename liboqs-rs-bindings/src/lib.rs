#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

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
