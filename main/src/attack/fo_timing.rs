use liboqs_rs_bindings as oqs;
use log::{info, warn};
use oqs::{InternalKemMeasurments, Kem, KemBuf, KemMeasure};
use std::arch::x86_64::{__get_cpuid_max, __rdtscp};
use std::str::FromStr;
use structopt::StructOpt;

mod baseline;
pub use baseline::*;

mod frodo_crack_s;
pub use frodo_crack_s::*;

mod modify_and_measure;
pub use modify_and_measure::*;

mod profile;
pub use profile::*;

#[derive(StructOpt, Debug, Clone, Copy)]
pub enum MeasureSource {
    External,
    Internal,
    Oracle,
}

pub trait CachePrepper<KEM: Kem> {
    fn prep_cache(
        ct: &mut KEM::Ciphertext,
        ss: &mut KEM::SharedSecret,
        sk: &mut KEM::SecretKey,
    ) -> oqs::Result<()>;
}

pub struct NoCachePrepping;

impl<KEM: Kem> CachePrepper<KEM> for NoCachePrepping {
    #[inline]
    fn prep_cache(
        _ct: &mut KEM::Ciphertext,
        _ss: &mut KEM::SharedSecret,
        _sk: &mut KEM::SecretKey,
    ) -> oqs::Result<()> {
        Ok(())
    }
}

pub struct DecapsCachePrepping;

impl<KEM: Kem> CachePrepper<KEM> for DecapsCachePrepping {
    #[inline]
    fn prep_cache(
        ct: &mut KEM::Ciphertext,
        ss: &mut KEM::SharedSecret,
        sk: &mut KEM::SecretKey,
    ) -> oqs::Result<()> {
        KEM::decaps(ct, ss, sk)
    }
}

struct ClFlushCachePrepping;

impl<KEM: Kem> CachePrepper<KEM> for ClFlushCachePrepping {
    #[inline]
    fn prep_cache(
        ct: &mut KEM::Ciphertext,
        ss: &mut KEM::SharedSecret,
        sk: &mut KEM::SecretKey,
    ) -> oqs::Result<()> {
        let toflush: Vec<&[u8]> = vec![ct.as_slice(), ss.as_slice(), sk.as_slice()];
        toflush.iter().for_each(|slice| {
            // Step by 64 since we assume a 64 byte cache line size
            slice.iter().step_by(64).for_each(|el| {
                use core::arch::x86_64::_mm_clflush;
                unsafe { _mm_clflush(el) };
            })
        });
        Ok(())
    }
}

impl FromStr for MeasureSource {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<MeasureSource, String> {
        match s {
            "external" => Ok(MeasureSource::External),
            "internal" => Ok(MeasureSource::Internal),
            "oracle" => Ok(MeasureSource::Oracle),
            _ => Err(format!(
                "Could not parse {} into either external, internal or oracle.",
                s
            )),
        }
    }
}

impl MeasureSource {
    pub fn prep_thread(&self) -> Result<(), String> {
        match self {
            MeasureSource::Oracle => {}
            _ => {
                let mut last_cores =
                    core_affinity::get_core_ids().ok_or("Failed to get CPU core ids.")?;
                last_cores.sort_by_key(|id| id.id);
                let last_core = last_cores.pop().ok_or("CPU id list is empty.")?;
                info!(
                    "Setting CPU affinity to core: {:?}, other candidates were: {:?}",
                    last_core, last_cores
                );
                core_affinity::set_for_current(last_core);
            }
        }

        Ok(())
    }

    pub fn measure_decap<KEM: KemMeasure, C: CachePrepper<KEM>>(
        &self,
        ct: &mut KEM::Ciphertext,
        ss: &mut KEM::SharedSecret,
        sk: &mut KEM::SecretKey,
    ) -> Result<Option<u64>, String> {
        match self {
            MeasureSource::External => Self::measure_decap_external::<KEM, C>(ct, ss, sk),
            MeasureSource::Internal => {
                let results = KEM::decaps_measure(ct, ss, sk)?;
                Ok(results.result_internal())
            }
            MeasureSource::Oracle => {
                let results = KEM::decaps_measure(ct, ss, sk)?;
                Ok(results.result_oracle())
            }
        }
    }

    pub fn measure_decap_external<KEM: Kem, C: CachePrepper<KEM>>(
        ct: &mut KEM::Ciphertext,
        ss: &mut KEM::SharedSecret,
        sk: &mut KEM::SecretKey,
    ) -> Result<Option<u64>, String> {
        // Attempt manual brute-force memory alignment of the code (see script/set-code-alignment.sh)
        memshift!();
        C::prep_cache(ct, ss, sk)?; //Prepare the cache as per choosen strategy
        let mut cpu_core_ident_start = 0u32;
        let mut cpu_core_ident_stop = 0u32;
        let _ = unsafe { __get_cpuid_max(0) }; //Serializing instruction
        let start = unsafe { __rdtscp(&mut cpu_core_ident_start) };
        let _ = KEM::decaps(ct, ss, sk); // ignore decapsulation errors
        let stop = unsafe { __rdtscp(&mut cpu_core_ident_stop) };
        let _ = unsafe { __get_cpuid_max(0) }; //Serializing instruction
        if cpu_core_ident_start == cpu_core_ident_stop {
            Ok(Some(stop - start))
        } else {
            warn!("no measurment, the kernel probably induced a context switch");
            Ok(None)
        }
    }
}
