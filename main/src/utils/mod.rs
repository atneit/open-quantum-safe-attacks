use hdrhistogram::Histogram;
use log::{log, Level};
use std::collections::BTreeMap;
use std::fmt::Debug;

pub trait Recorder: Debug {
    fn record(&mut self, value: u64) -> Result<(), String>;
    fn log(&self, lvl: Level, prefix: &str);
}

#[derive(Debug)]
pub struct SaveAllRecorder {
    store: BTreeMap<u64, u16>,
}

#[derive(Debug)]
pub struct DevNull;

impl Recorder for Histogram<u64> {
    fn record(&mut self, value: u64) -> Result<(), String> {
        self.record(value).map_err(stringify)
    }

    fn log(&self, lvl: Level, prefix: &str) {
        // print percentiles from the histogram
        for v in self.iter_recorded() {
            log!(
                lvl,
                "({}) {}'th percentile of data is {} with {} samples",
                prefix,
                v.percentile(),
                v.value_iterated_to(),
                v.count_at_value()
            );
        }
    }
}

impl Recorder for DevNull {
    fn record(&mut self, _value: u64) -> Result<(), String> {
        Ok(())
    }
    fn log(&self, _lvl: Level, _prefix: &str) {}
}

impl Recorder for SaveAllRecorder {
    fn record(&mut self, value: u64) -> Result<(), String> {
        let counter = self.store.entry(value).or_insert(0);
        *counter += 1;
        Ok(())
    }
    fn log(&self, lvl: Level, prefix: &str) {
        for (key, value) in &self.store {
            log!(lvl, "({}) {}\t: {}", prefix, key, value);
        }
    }
}

pub fn stringify<T: Debug>(t: T) -> String {
    format!("{:?}", t)
}
