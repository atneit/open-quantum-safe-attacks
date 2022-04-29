use chrono::Utc;
use std::sync::Mutex;
use rayon::prelude::*;
use rayon::iter::repeatn;
use std::io::Write;
use std::fs::File;
use gather_data_lib::{Statistic, run_attack};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let binary = std::env::args().nth(1).expect("expected attack binary as first argument");
    let trials = std::env::args().nth(2).expect("expected number of trials as second argument").parse().expect("expected numerical number of trials as second argument");
    let threads = rayon::current_num_threads();
    println!("Starting {} trials on {} threads", trials, threads);

    let now = Utc::now();
    let mut f = File::create(format!("results_{}.csv", now.to_rfc3339()))?;
    writeln!(f, "id,success,oracle_calls,wrong_bits")?;

    struct ProgressInfo {
        success: u64,
        done: u64,
        f: File,
    }
    let pi = ProgressInfo {
        success: 0,
        done: 0,
        f: f,
    };
    let pi = Mutex::new(pi);

    let iter = repeatn((), trials);
    iter
        .map(|_| {
            run_attack(&binary).unwrap()
        })
        .map(|(last_lines, v)| {
            let mut pi = pi.lock().unwrap();
            pi.done += 1;
            pi.success += v.success;
            let id = pi.done;
            let m = &v.measurements[0];
            writeln!(pi.f, "{},{},{},{}", id,m.success, m.oracle_calls, m.wrong_bits).unwrap();
            let mut f = File::create(format!("last_lines/{}_{}_{}.txt", "last_lines", now.to_rfc3339(), pi.done)).unwrap();
            for line in last_lines {
                writeln!(f, "{}", line).unwrap();
            }
            println!(
                "Progress: {}/{} ({:.2}%) with success {}/{} ({:.2}%)",
                pi.done,
                trials,
                pi.done as f64 / trials as f64 * 100.,
                pi.success,
                pi.done,
                pi.success as f64 / pi.done as f64 * 100.,
            );
            v
        })
        .reduce(Statistic::identity, |a, b| a.combine(&b));


    Ok(())
}
