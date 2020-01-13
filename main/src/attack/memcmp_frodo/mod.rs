use std::str::FromStr;
use structopt::StructOpt;

mod baseline;
pub use baseline::*;

mod find_e;
pub use find_e::*;

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
