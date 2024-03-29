use liboqs_rs_bindings as oqs;
use log::info;
use log_derive::logfn_inputs;
use oqs::{bike::Bike, KemBuf};
use std::{fs::File, io::BufWriter, path::PathBuf};
use structopt::StructOpt;

use crate::{
    attack::rejection_sampling::bike_attack::{read_keypair, write_ds},
    utils::{mutbit, StrErr},
};

#[derive(Debug, StructOpt)]
pub struct BikeDistanceSpectrumOptions {
    /// Create new keypair if the specifed keyfile is missing
    #[structopt(short("c"), long)]
    pub create_key_if_missing: bool,
    /// Location of serialized key pair file.
    #[structopt(short("k"), long)]
    pub key_file: PathBuf,
    /// Where to write the resulting CSV file, e.g. "bike-ds.csv"
    /// containing the distance spectrum of the secret key in the specified key-file
    #[structopt(short("f"), long)]
    pub destination: PathBuf,
}

#[logfn_inputs(Trace)]
pub fn run<BIKE: 'static + Bike + std::marker::Send>(
    opt: BikeDistanceSpectrumOptions,
) -> Result<(), String> {
    let (_, mut sk) = read_keypair::<BIKE>(&opt.key_file, opt.create_key_if_missing)?;
    let params = BIKE::params::<usize>();
    let max_distance = (params.PARAM_R + 1 )/ 2; // div_ceil
    let mut distances = vec![0; max_distance + 1];
    let r_bytes = (params.PARAM_R + 7 )/ 8; // div_ceil
    let sk_offset = params.PARAM_SK_OFFSET + r_bytes; // first or second parity check matrix
    let sk_len = r_bytes;
    let range = sk_offset..sk_offset + sk_len;

    let sk_bytes = &mut sk.as_mut_slice()[range];

    for i in 0..params.PARAM_R {
        let ib = mutbit(sk_bytes, i as u64)?;
        if ib.get() {
            for j in (i + 1)..params.PARAM_R {
                let jb = mutbit(sk_bytes, j as u64)?;
                if jb.get() {
                    let dist = i.abs_diff(j);
                    let dist = std::cmp::min(dist, params.PARAM_R - dist);
                    distances[dist] += 1;
                }
            }
        }
    }

    info!("Opening target file: {:?}", opt.destination);
    let mut writer =
        csv::Writer::from_writer(BufWriter::new(File::create(&opt.destination).strerr()?));
    writer
        .write_record(&["list", "distance", "count"])
        .strerr()?;

    write_ds(distances, "DS(h1)", &mut writer);

    Ok(())
}
