use chrono::Utc;
use regex::Regex;
use std::{error::Error, io::{BufRead, BufReader, Write}};
use std::process::{Command, Stdio};
use std::collections::VecDeque;

#[macro_use]
extern crate lazy_static;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Measurement {
    pub success: bool,
    pub oracle_calls: u64,
    pub wrong_bits: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Statistic {
    pub success: u64,
    pub measurements: Vec<Measurement>,
    pub trials: u64,
}

impl Statistic {
    pub fn identity() -> Self {
        Self {
            success: 0,
            measurements: vec![],
            trials: 0,
        }
    }

    pub fn combine(&self, other: &Self) -> Self {
        Self {
            success: self.success + other.success,
            measurements: {
                let mut v = self.measurements.clone();
                v.extend(other.measurements.iter().cloned());
                v
            },
            trials: self.trials + other.trials,
        }
    }

    pub fn serialize(self, fname: &str) -> Result<(), Box<dyn Error>> {
        println!(
            "{}/{} successes ({}%)",
            self.success,
            self.trials,
            self.success as f64 / self.trials as f64 * 100.
        );

        let now = Utc::now();
        let mut f = std::fs::File::create(format!("{}_{}.csv", fname, now.to_rfc3339()))?;
        writeln!(f, "success,oracle_calls,wrong_bits")?;
        for m in self.measurements {
            writeln!(f, "{},{},{}", m.success, m.oracle_calls, m.wrong_bits)?;
        }
        
        Ok(())
    }
}

pub fn run_attack(binary: &str) -> Result<(VecDeque<String>, Statistic), Box<dyn std::error::Error>> {
    lazy_static! {
        static ref RE_SUCCESS: Regex = Regex::new(r"^Success\? ([0,1])").unwrap();
        static ref RE_ORACLES: Regex = Regex::new(r"^Decryption oracle calls: ([0-9]*)$").unwrap();
        static ref RE_BITS_WRONG: Regex = Regex::new(r"^Final classification: ([0-9]*) ").unwrap();
    }

    let mut cmd = Command::new(binary);

    // Specify that we want the command's standard output piped back to us.
    // By default, standard input/output/error will be inherited from the
    // current process (for example, this means that standard input will
    // come from the keyboard and standard output/error will go directly to
    // the terminal if this process is invoked from the command line).
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());

    let mut last_lines: VecDeque<String> = VecDeque::new();

    let mut child = cmd.spawn().expect("failed to spawn command");

    let stdout = child
        .stdout
        .take()
        .expect("child did not have a handle to stdout");

    let reader = BufReader::new(stdout).lines();

    let mut success = None;
    let mut oracle_calls = None;
    let mut bits_wrong = None;
    for line in reader {
        let line = line.unwrap();
        if last_lines.len() >= 30000 {
            last_lines.pop_front();
        }
        last_lines.push_back(line.clone());
        for cap in RE_SUCCESS.captures_iter(&line) {
            // println!("Line: {} with capture: \"{}\"", line, &cap[1]);
            if &cap[1] == "1" {
                success = Some(true);
            } else {
                assert!(&cap[1] == "0", "Line: {}", line);
                success = Some(false);
            }
        }
        for cap in RE_ORACLES.captures_iter(&line) {
            oracle_calls = Some(cap[1].parse::<u64>().unwrap());
        }
        for cap in RE_BITS_WRONG.captures_iter(&line) {
            bits_wrong = Some(cap[1].parse::<u64>().unwrap());
        }
    }

    child.wait()?;

    if success.is_none() {
        println!("Could not find success message in program output");
    }

    Ok(
        (
            last_lines,
            Statistic {
                success: success.unwrap_or(false) as u64,
                measurements: vec![Measurement {
                    oracle_calls: oracle_calls.unwrap_or(10000000),
                    success: success.unwrap_or(false),
                    wrong_bits: bits_wrong.unwrap_or(10000000),
                }],
                trials: 1,
            }
        )
    )
}
