use std::{fs::File, io::BufWriter, path::PathBuf};

use libflate::finish::AutoFinishUnchecked;
use liboqs_rs_bindings as oqs;

use log::{info, warn};
use log_derive::logfn_inputs;
use oqs::{KemBuf, KemWithRejectionSampling};
use structopt::StructOpt;

use crate::{
    attack::{
        fo_timing::{MeasureSource, NoCachePrepping},
        rejection_sampling::plaintexts::PlaintextDb,
    },
    utils::{BarSelector, ClonableProgressManager, ProgressBars, StrErr},
};

#[derive(Debug, StructOpt)]
pub struct IterationTimingsOptions {
    /// Number of measurments to perform, to the extent possible they are spread out over all applicable plaintexts in the db.
    #[structopt(short, long, default_value("10000"))]
    measurments: u32,

    /// Only measure plaintexts with the specified iteration counts
    #[structopt(short, long)]
    include: Vec<u64>,

    /// Path to plaintext database
    #[structopt(short, long)]
    db: PathBuf,

    /// Path to save results (GZIP compressed CSV file), e.g. timings.csv.gz
    #[structopt(short("t"), long)]
    destination: PathBuf,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
enum IteratorTimingsProgressbars {
    PerIterator,
    Total,
}

impl BarSelector for IteratorTimingsProgressbars {}

#[logfn_inputs(Trace)]
pub fn run<KEM: KemWithRejectionSampling + std::marker::Send + std::marker::Sync>(
    opt: IterationTimingsOptions,
) -> Result<(), String> {
    info!("Iteration timings routine has started!");

    let mut ptdb = PlaintextDb::<KEM>::new(&opt.db, 0)?;
    let mut ct = KEM::Ciphertext::new();
    let mut ss = KEM::SharedSecret::new();

    if let Some(counts) = ptdb.iter_saved_counts()? {
        let counts: Vec<_> = counts
            .iter()
            .filter_map(|(iter, saved_count)| {
                if opt.include.is_empty() || opt.include.contains(iter) {
                    Some((*iter as u32, *saved_count as u32))
                } else {
                    None
                }
            })
            .collect();

        info!("Opening destination file: {:?}", opt.destination);
        let mut writer = csv::Writer::from_writer(AutoFinishUnchecked::new(
            libflate::gzip::Encoder::new(BufWriter::new(File::create(&opt.destination).strerr()?))
                .strerr()?,
        ));
        writer
            .write_record(&["alg", "seedexpanders", "iterations", "cycles"])
            .strerr()?;

        let pb = ClonableProgressManager::create();
        pb.add(
            IteratorTimingsProgressbars::PerIterator,
            opt.measurments as u64,
            "",
            " {msg:30} {wide_bar} {pos:>7}/{len:7}",
        );
        pb.add(
            IteratorTimingsProgressbars::Total,
            opt.measurments as u64 * counts.len() as u64,
            "Total progress",
            " {msg:30} {wide_bar}     [{eta_precise}] ",
        );

        for (p, (iter, count)) in counts.iter().enumerate() {
            let iter = *iter as u32;
            let count = *count as u32;
            pb.start([IteratorTimingsProgressbars::PerIterator]);
            info!(
                "Starting {} measurments of {} plaintexts with {} iterations form the DB.",
                opt.measurments, count, iter
            );

            let reused = opt.measurments.div_ceil(count);
            if reused > 1 {
                warn!("Plaintexts will be reused up to {} times each", reused);
            }

            pb.set_message(
                IteratorTimingsProgressbars::PerIterator,
                format!("Plaintexts (iter == {})", iter),
            );
            pb.tick();

            let mut measurments = 0;
            while measurments < opt.measurments as u64 {
                pb.set_position(
                    IteratorTimingsProgressbars::Total,
                    (p as u64 * opt.measurments as u64) + measurments,
                );
                pb.set_position(IteratorTimingsProgressbars::PerIterator, measurments);
                pb.tick();
                let (_, mut pt) = if let Some(res) = ptdb.get_next_iter(iter, false)? {
                    res
                } else {
                    // Reset the current position and start over
                    ptdb.get_next_iter(iter, true)?.unwrap()
                };

                // New key pair
                let (mut pk, mut sk) = KEM::keypair()?;

                // encapsulate message
                KEM::encaps_with_plaintext(&mut ct, &mut ss, &mut pk, &mut pt)?;

                // measure the decapsulation of the ciphertext
                if let Some(m) = MeasureSource::measure_decap_external::<KEM, NoCachePrepping>(
                    &mut ct, &mut ss, &mut sk,
                )? {
                    writer
                        .write_record([
                            KEM::NAME,
                            &(iter / 1000).to_string(),
                            &(iter % 1000).to_string(),
                            &m.to_string(),
                        ])
                        .strerr()?;
                    measurments += 1;
                }
            }

            pb.stop();
        }
    }

    Ok(())
}
