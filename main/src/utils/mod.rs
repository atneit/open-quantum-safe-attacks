use csv;
use hdrhistogram::Histogram;
use log::{log, Level};
use medianheap;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::path::Path;

#[derive(Debug)]
pub struct Recorder<R: RecorderBackend> {
    name: String,
    bknd: R,
    counter: u64,
    min: u64,
    cutoff: Option<u64>,
}

impl Recorder<MinVal> {
    pub fn minval() -> Recorder<MinVal> {
        Recorder {
            name: String::new(),
            bknd: MinVal,
            counter: 0,
            min: u64::max_value(),
            cutoff: None,
        }
    }
}

impl Recorder<Histogram<u64>> {
    #[allow(dead_code)]
    pub fn histogram<S: ToString>(
        name: S,
        minimal_value: Option<u64>,
        cutoff: Option<u64>,
    ) -> Result<Recorder<Histogram<u64>>, String> {
        let bknd = if let Some(cutoff) = cutoff {
            if let Some(minimal_value) = minimal_value {
                Histogram::new_with_bounds(minimal_value, cutoff, 5)
                    .map_err(|e| format!("{:?}", e))?
            } else {
                Histogram::new_with_max(cutoff, 5).map_err(|e| format!("{:?}", e))?
            }
        } else {
            Histogram::new(5).map_err(|e| format!("{:?}", e))?
        };
        Ok(Recorder {
            name: name.to_string(),
            bknd,
            counter: 0,
            min: u64::max_value(),
            cutoff,
        })
    }
}

impl Recorder<SaveAllRecorder> {
    pub fn saveall<S: ToString>(name: S, cutoff: Option<u64>) -> Recorder<SaveAllRecorder> {
        Recorder {
            name: name.to_string(),
            bknd: SaveAllRecorder::new(),
            counter: 0,
            min: u64::max_value(),
            cutoff,
        }
    }
}

impl Recorder<medianheap::MedianHeap<u64>> {
    #[allow(dead_code)]
    pub fn medianval<S: ToString>(
        name: S,
        cutoff: Option<u64>,
    ) -> Recorder<medianheap::MedianHeap<u64>> {
        Recorder {
            name: name.to_string(),
            bknd: medianheap::MedianHeap::new(),
            counter: 0,
            min: u64::max_value(),
            cutoff,
        }
    }
}

pub struct RecIterSaveAll<'a> {
    inner: std::collections::btree_map::Iter<'a, u64, u16>,
    current: Option<(u64, u16)>,
}

pub struct RecMinValIter;

pub trait Rec<'a>: Debug {
    type Iter: Iterator<Item = u64>;
    fn record(&mut self, value: u64) -> Result<(), String>;
    fn log(&self, lvl: Level);
    fn name(&self) -> &str;
    fn iter(&'a self) -> Self::Iter;
    fn len(&self) -> u64;
    fn min(&self) -> Result<u64, String>;
    fn aggregated_value(&self) -> Result<u64, String>;
    fn percentage_lte(&self, below: u64) -> f64;
    fn nth_lowest_value(&self, nth: u64) -> Option<u64>;
}

pub trait RecorderBackend: Debug {}

#[derive(Debug)]
pub struct SaveAllRecorder {
    store: BTreeMap<u64, u16>,
    sum: u128,
}

#[derive(Debug)]
pub struct MinVal;

impl RecorderBackend for Histogram<u64> {}
impl RecorderBackend for MinVal {}
impl RecorderBackend for SaveAllRecorder {}
impl RecorderBackend for medianheap::MedianHeap<u64> {}

impl<'a> Rec<'a> for Recorder<Histogram<u64>> {
    type Iter = RecMinValIter;

    fn record(&mut self, value: u64) -> Result<(), String> {
        if value < self.min {
            self.min = value;
        }
        if let Some(cutoff) = self.cutoff {
            if value < cutoff {
                self.counter += 1;
                self.bknd.record(value).map_err(stringify)
            } else {
                Ok(())
            }
        } else {
            self.counter += 1;
            self.bknd.record(value).map_err(stringify)
        }
    }

    fn log(&self, lvl: Level) {
        // print percentiles from the histogram
        for v in self.bknd.iter_recorded() {
            log!(
                lvl,
                "({}) {}'th percentile of data is {} with {} samples",
                self.name,
                v.percentile(),
                v.value_iterated_to(),
                v.count_at_value()
            );
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn iter(&'a self) -> Self::Iter {
        unimplemented!();
    }

    fn len(&self) -> u64 {
        self.counter
    }

    fn min(&self) -> Result<u64, String> {
        if self.counter > 0 {
            Ok(self.min)
        } else {
            Err(String::from("min() called without any recorded values!"))
        }
    }

    fn aggregated_value(&self) -> Result<u64, String> {
        Ok(self.bknd.mean() as u64)
    }

    fn percentage_lte(&self, _below: u64) -> f64 {
        // we don't need this right now, but should be easy to implement
        unimplemented!();
    }

    fn nth_lowest_value(&self, _nth: u64) -> Option<u64> {
        // we don't need this right now, but should be easy to implement
        unimplemented!();
    }
}

impl SaveAllRecorder {
    pub fn new() -> SaveAllRecorder {
        SaveAllRecorder {
            store: BTreeMap::new(),
            sum: 0,
        }
    }
}

impl<'a> Rec<'a> for Recorder<MinVal> {
    type Iter = RecMinValIter;
    fn record(&mut self, value: u64) -> Result<(), String> {
        self.counter += 1;
        if value < self.min {
            self.min = value;
        }
        Ok(())
    }
    fn log(&self, _lvl: Level) {}

    fn name(&self) -> &str {
        &self.name
    }

    fn iter(&'a self) -> Self::Iter {
        unimplemented!();
    }

    fn len(&self) -> u64 {
        self.counter
    }

    fn min(&self) -> Result<u64, String> {
        if self.counter > 0 {
            Ok(self.min)
        } else {
            Err(String::from("min() called without any recorded values!"))
        }
    }

    fn aggregated_value(&self) -> Result<u64, String> {
        if self.counter > 0 {
            Ok(self.min)
        } else {
            Err(String::from(
                "aggregated_value() called without any recorded values!",
            ))
        }
    }

    fn percentage_lte(&self, below: u64) -> f64 {
        if self.counter > 0 && self.min < below {
            return 100.0;
        }
        0.0
    }

    fn nth_lowest_value(&self, _nth: u64) -> Option<u64> {
        // we don't need this right now, but should be easy to implement
        unimplemented!();
    }
}

impl<'a> Rec<'a> for Recorder<SaveAllRecorder> {
    type Iter = RecIterSaveAll<'a>;

    fn record(&mut self, value: u64) -> Result<(), String> {
        if value < self.min {
            self.min = value;
        }
        if let Some(cutoff) = self.cutoff {
            if value < cutoff {
                self.counter += 1;
                let valcnt = self.bknd.store.entry(value).or_insert(0);
                *valcnt += 1;
                self.bknd.sum += value as u128;
            }
        } else {
            self.counter += 1;
            let valcnt = self.bknd.store.entry(value).or_insert(0);
            *valcnt += 1;
            self.bknd.sum += value as u128;
        }
        Ok(())
    }
    fn log(&self, lvl: Level) {
        for (key, value) in &self.bknd.store {
            log!(lvl, "({}) {}\t: {}", self.name, key, value);
        }
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn iter(&'a self) -> RecIterSaveAll<'a> {
        RecIterSaveAll {
            inner: self.bknd.store.iter(),
            current: None,
        }
    }

    fn len(&self) -> u64 {
        self.counter
    }

    fn min(&self) -> Result<u64, String> {
        if self.counter > 0 {
            Ok(self.min)
        } else {
            Err(String::from("min() called without any recorded values!"))
        }
    }

    fn aggregated_value(&self) -> Result<u64, String> {
        if self.counter == 0 {
            return Err(String::from(
                "aggregated_value() called without any recorded values!",
            ));
        }

        let mean = (self.bknd.sum / self.counter as u128) as u64;
        Ok(mean)
    }

    fn percentage_lte(&self, below: u64) -> f64 {
        let count = self.iter().take_while(|v| v <= &below).count() as f64;
        count / self.counter as f64 * 100.0
    }

    fn nth_lowest_value(&self, nth: u64) -> Option<u64> {
        self.iter().skip((nth - 1) as usize).next()
    }
}

impl<'a> Rec<'a> for Recorder<medianheap::MedianHeap<u64>> {
    type Iter = RecMinValIter;
    fn record(&mut self, value: u64) -> Result<(), String> {
        if value < self.min {
            self.min = value;
        }
        if let Some(cutoff) = self.cutoff {
            if value < cutoff {
                self.counter += 1;
                self.bknd.push(value);
            }
        } else {
            self.counter += 1;
            self.bknd.push(value);
        }

        Ok(())
    }
    fn log(&self, lvl: Level) {
        log!(
            lvl,
            "({}) median: {}",
            self.name,
            self.bknd.median().unwrap()
        );
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn iter(&'a self) -> Self::Iter {
        unimplemented!();
    }

    fn len(&self) -> u64 {
        self.counter
    }

    fn min(&self) -> Result<u64, String> {
        if self.counter > 0 {
            Ok(self.min)
        } else {
            Err(String::from("min() called without any recorded values!"))
        }
    }

    fn aggregated_value(&self) -> Result<u64, String> {
        self.bknd.median().ok_or(String::from(
            "aggregated_value called without any recorded values!",
        ))
    }

    fn percentage_lte(&self, _below: u64) -> f64 {
        // we don't need this right now, but should be easy to implement
        unimplemented!();
    }

    fn nth_lowest_value(&self, _nth: u64) -> Option<u64> {
        // we don't need this right now, but should be easy to implement
        unimplemented!();
    }
}

/// Iterator that iterates through all recorded values.
/// In this case it will always yield None.
impl Iterator for RecMinValIter {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl<'a> Iterator for RecIterSaveAll<'a> {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        let mut to_ret = None;
        let next = self
            .current
            .as_ref()
            .map(|(v, c)| (*v, *c))
            .or_else(|| self.inner.next().map(|(v, c)| (*v, *c)));
        if let Some((value, mut counter)) = next {
            to_ret.replace(value);
            counter -= 1;
            if counter > 0 {
                self.current = Some((value, counter))
            } else {
                self.current = None;
            }
        }

        to_ret
    }
}

struct RecordTableIterator<I: Iterator<Item = u64>> {
    inners: Vec<I>,
}

impl<'a, I: Iterator<Item = u64>> RecordTableIterator<I> {
    pub fn from<R: Rec<'a, Iter = I>>(recorders: &'a Vec<R>) -> RecordTableIterator<I> {
        RecordTableIterator {
            inners: recorders.iter().map(|r| r.iter()).collect(),
        }
    }
}

impl<I: Iterator<Item = u64>> Iterator for RecordTableIterator<I> {
    type Item = Vec<Option<u64>>;

    fn next(&mut self) -> Option<Self::Item> {
        let v: Vec<_> = self.inners.iter_mut().map(|rec| rec.next()).collect();
        if v.iter().any(Option::is_some) {
            Some(v)
        } else {
            None
        }
    }
}

pub fn save_to_csv<'a, R: Rec<'a>>(path: &Path, recorders: &'a Vec<R>) -> Result<(), String> {
    let mut wtr = csv::Writer::from_path(path).map_err(stringify)?;

    //Write headers
    wtr.write_record(recorders.iter().map(|r| r.name()))
        .map_err(stringify)?;

    let tableiter = RecordTableIterator::from(recorders);

    //Write values
    for row in tableiter {
        wtr.write_record(row.iter().map(|v| match v {
            Some(value) => value.to_string(),
            None => String::from(""),
        }))
        .map_err(stringify)?;
    }

    Ok(())
}

pub fn stringify<T: Debug>(t: T) -> String {
    format!("{:?}", t)
}

#[test]
fn name() {
    use std::convert::TryInto;
    let mut vr = vec![];
    for i in 0..3 {
        vr.push(Recorder::saveall(format!("test {}", i), None));
    }

    for i in 0..3 {
        for v in 0..3 {
            vr[i].record((v % (i + 1)).try_into().unwrap()).unwrap();
        }
    }
    vr[0].record(10).unwrap();

    let tableiter = RecordTableIterator::from(&vr);

    for row in tableiter {
        println!("{:?}", row);
    }

    let tableiter = RecordTableIterator::from(&vr);
    let mut it = tableiter.flatten();

    assert_eq!(Some(Some(0)), it.next()); //row 0
    assert_eq!(Some(Some(0)), it.next()); //row 0
    assert_eq!(Some(Some(0)), it.next()); //row 0
    assert_eq!(Some(Some(0)), it.next()); //row 1
    assert_eq!(Some(Some(0)), it.next()); //row 1
    assert_eq!(Some(Some(1)), it.next()); //row 1
    assert_eq!(Some(Some(0)), it.next()); //row 2
    assert_eq!(Some(Some(1)), it.next()); //row 2
    assert_eq!(Some(Some(2)), it.next()); //row 2
    assert_eq!(Some(Some(10)), it.next()); //row 3
    assert_eq!(Some(None), it.next()); //row 3
    assert_eq!(Some(None), it.next()); //row 3
    assert_eq!(None, it.next()); //iterator empty
}
