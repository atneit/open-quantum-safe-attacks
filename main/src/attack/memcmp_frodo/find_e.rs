use crate::attack::memcmp_frodo::MeasureSource;
use liboqs_rs_bindings::frodokem::FrodoKem;
use log_derive::logfn_inputs;

#[logfn_inputs(Trace)]
pub fn find_e<FRODO: FrodoKem>(_measure_source: MeasureSource) -> Result<(), String> {
    Ok(())
}
