use liboqs_rs_bindings as oqs;
use oqs::frodokem::InternalMeasurments;
use std::arch::x86_64::__rdtscp;
use std::str::FromStr;
use structopt::StructOpt;

mod baseline;
pub use baseline::*;

mod find_e;
pub use find_e::*;

mod modify_and_measure;

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
    pub fn measure<F: FnMut() -> Result<InternalMeasurments, String>>(
        &self,
        mut to_measure: F,
    ) -> Result<Option<u64>, String> {
        match self {
            MeasureSource::External => {
                let mut cpu_core_ident_start = 0u32;
                let mut cpu_core_ident_stop = 0u32;
                let start = unsafe { __rdtscp(&mut cpu_core_ident_start) };
                let _ = to_measure()?;
                let stop = unsafe { __rdtscp(&mut cpu_core_ident_stop) };
                if cpu_core_ident_start == cpu_core_ident_stop {
                    Ok(Some(stop - start))
                } else {
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
