use liboqs_rs_bindings as oqs;
use log::{info, warn};
use oqs::frodokem::InternalMeasurments;
use std::arch::x86_64::__rdtscp;
use std::str::FromStr;
use std::sync::atomic::{fence, Ordering};
use structopt::StructOpt;

mod baseline;
pub use baseline::*;

mod crack_s;
pub use crack_s::*;

mod modify_and_measure;
pub use modify_and_measure::*;

mod profile;
pub use profile::*;

#[derive(StructOpt, Debug, Clone, Copy)]
#[structopt(name = "measure-source")]
pub enum MeasureSource {
    External,
    Internal,
    Oracle,
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
                let last_core = core_affinity::get_core_ids()
                    .ok_or("Failed to get CPU core ids.")?
                    .pop()
                    .ok_or("CPU id list is empty.")?;
                info!("Setting CPU affinity to core: {:?}", last_core);
                core_affinity::set_for_current(last_core);
            }
        }

        Ok(())
    }

    pub fn clflush_inputs(toflush: Vec<&[u8]>) {
        toflush.iter().for_each(|slice| {
            // Step by 64 since we assume a 64 byte cache line size
            slice.iter().step_by(64).for_each(|el| {
                use core::arch::x86_64::_mm_clflush;
                unsafe { _mm_clflush(el) };
            })
        });
    }

    pub fn measure<F: FnMut() -> Result<InternalMeasurments, String>>(
        &self,
        mut to_measure: F,
    ) -> Result<Option<u64>, String> {
        match self {
            MeasureSource::External => {
                let mut cpu_core_ident_start = 0u32;
                let mut cpu_core_ident_stop = 0u32;
                fence(Ordering::SeqCst);
                let start = unsafe { __rdtscp(&mut cpu_core_ident_start) };
                fence(Ordering::SeqCst);
                let _ = to_measure()?;
                fence(Ordering::SeqCst);
                let stop = unsafe { __rdtscp(&mut cpu_core_ident_stop) };
                fence(Ordering::SeqCst);
                if cpu_core_ident_start == cpu_core_ident_stop {
                    Ok(Some(stop - start))
                } else {
                    warn!("no measurment, the kernel probably induced a context switch");
                    Ok(None)
                }
            }
            MeasureSource::Internal => {
                let results = to_measure()?;
                Ok(results.memcmp_timing)
            }
            MeasureSource::Oracle => {
                let results = to_measure()?;
                if let Some(memcmp1) = results.memcmp1 {
                    //memcmp1 has executed
                    let mut time = 100; //base timing
                    if memcmp1 {
                        time += 50;
                        //first part was identical
                        if let Some(memcmp2) = results.memcmp2 {
                            if memcmp2 {
                                //last part was also identical
                                time += 100;
                            }
                        } else {
                            unreachable!(
                                "If memcmp1 is true then memcmp2 must have been executed!"
                            );
                        }
                    }
                    Ok(Some(time))
                } else {
                    //Somehing happened, no comparison was executed at all
                    Ok(None)
                }
            }
        }
    }
}
