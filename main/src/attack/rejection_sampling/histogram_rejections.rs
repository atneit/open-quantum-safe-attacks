use crate::utils::StrErr;
use liboqs_rs_bindings as oqs;
use log::info;
use log_derive::logfn_inputs;
use oqs::{KemBuf, KemWithRejectionSampling};
use rand::{thread_rng, Fill};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
pub struct HistogramRejectionsOptions {
    /// The number of different ciphertexts to test
    num_plaintexts: usize,
}

#[logfn_inputs(Debug)]
pub fn run<KEM: KemWithRejectionSampling>(opt: HistogramRejectionsOptions) -> Result<(), String> {
    let mut rng = thread_rng();
    let mut plaintext = KEM::Plaintext::new();
    let mut rejections = Vec::new();
    let mut modified = false;
    for i in 0..opt.num_plaintexts {
        let i = i + 1;
        modified = true;
        plaintext.as_mut_slice().try_fill(&mut rng).strerr()?;
        let num = KEM::num_rejections(&mut plaintext)? as usize;
        if num >= rejections.len() {
            rejections.extend((rejections.len()..num + 1).map(|_| 0));
        }
        rejections[num] += 1;
        if i % 10000 == 0 {
            info!(
                "<== {}% ==>",
                (i as f64 / opt.num_plaintexts as f64) * 100f64
            );
            print_results(&rejections);
            modified = false;
        }
    }
    if modified {
        info!("<== {}% ==>", 100.0);
        print_results(&rejections);
    }
    Ok(())
}

#[logfn_inputs(Trace)]
fn print_results(rejections: &[i32]) {
    let mut do_print = false;
    (0..rejections.len()).for_each(|i| {
        if rejections[i] != 0 {
            do_print = true;
        }
        if do_print {
            info!("{}: {}", i, rejections[i]);
        }
    });
}
