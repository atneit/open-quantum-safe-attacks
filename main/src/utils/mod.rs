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
}

pub struct RecIterSaveAll<'a> {
    inner: std::collections::btree_map::Iter<'a, u64, u16>,
    current: Option<(u64, u16)>,
}

pub struct RecMinValIter;

impl Recorder<MinVal> {
    pub fn minval() -> Recorder<MinVal> {
        Recorder {
            name: String::new(),
            bknd: MinVal(u64::max_value()),
        }
    }
}

impl Recorder<Histogram<u64>> {
    #[allow(dead_code)]
    pub fn histogram<S: ToString>(name: S, hist: Histogram<u64>) -> Recorder<Histogram<u64>> {
        Recorder {
            name: name.to_string(),
            bknd: hist,
        }
    }
}

impl Recorder<SaveAllRecorder> {
    pub fn saveall<S: ToString>(name: S) -> Recorder<SaveAllRecorder> {
        Recorder {
            name: name.to_string(),
            bknd: SaveAllRecorder::new(),
        }
    }
}

impl Recorder<medianheap::MedianHeap<u64>> {
    pub fn medianval<S: ToString>(name: S) -> Recorder<medianheap::MedianHeap<u64>> {
        Recorder {
            name: name.to_string(),
            bknd: medianheap::MedianHeap::new(),
        }
    }
}

pub trait Rec<'a>: Debug {
    type Iter: Iterator<Item = u64>;
    fn record(&mut self, value: u64) -> Result<(), String>;
    fn log(&self, lvl: Level, prefix: &str);
    fn name(&self) -> &str;
    fn iter(&'a self) -> Self::Iter;
    fn aggregated_value(&self) -> u64;
}

pub trait RecorderBackend: Debug {}

#[derive(Debug)]
pub struct SaveAllRecorder {
    store: BTreeMap<u64, u16>,
}

#[derive(Debug)]
pub struct MinVal(u64);

impl RecorderBackend for Histogram<u64> {}
impl RecorderBackend for MinVal {}
impl RecorderBackend for SaveAllRecorder {}
impl RecorderBackend for medianheap::MedianHeap<u64> {}

impl<'a> Rec<'a> for Recorder<Histogram<u64>> {
    type Iter = RecMinValIter;

    fn record(&mut self, value: u64) -> Result<(), String> {
        self.bknd.record(value).map_err(stringify)
    }

    fn log(&self, lvl: Level, prefix: &str) {
        // print percentiles from the histogram
        for v in self.bknd.iter_recorded() {
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

    fn name(&self) -> &str {
        &self.name
    }

    fn iter(&'a self) -> Self::Iter {
        unimplemented!();
    }

    fn aggregated_value(&self) -> u64 {
        self.bknd.mean() as u64
    }
}

impl SaveAllRecorder {
    pub fn new() -> SaveAllRecorder {
        SaveAllRecorder {
            store: BTreeMap::new(),
        }
    }
}

impl<'a> Rec<'a> for Recorder<MinVal> {
    type Iter = RecMinValIter;
    fn record(&mut self, value: u64) -> Result<(), String> {
        if value < self.bknd.0 {
            self.bknd.0 = value;
        }
        Ok(())
    }
    fn log(&self, _lvl: Level, _prefix: &str) {}

    fn name(&self) -> &str {
        &self.name
    }

    fn iter(&'a self) -> Self::Iter {
        unimplemented!();
    }

    fn aggregated_value(&self) -> u64 {
        0
    }
}

impl<'a> Rec<'a> for Recorder<SaveAllRecorder> {
    type Iter = RecIterSaveAll<'a>;

    fn record(&mut self, value: u64) -> Result<(), String> {
        let counter = self.bknd.store.entry(value).or_insert(0);
        *counter += 1;
        Ok(())
    }
    fn log(&self, lvl: Level, prefix: &str) {
        for (key, value) in &self.bknd.store {
            log!(lvl, "({}) {}\t: {}", prefix, key, value);
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

    fn aggregated_value(&self) -> u64 {
        unimplemented!();
    }
}

impl<'a> Rec<'a> for Recorder<medianheap::MedianHeap<u64>> {
    type Iter = RecMinValIter;
    fn record(&mut self, value: u64) -> Result<(), String> {
        self.bknd.push(value);
        Ok(())
    }
    fn log(&self, lvl: Level, prefix: &str) {
        log!(lvl, "({}) median: {}", prefix, self.bknd.median().unwrap());
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn iter(&'a self) -> Self::Iter {
        unimplemented!();
    }

    fn aggregated_value(&self) -> u64 {
        self.bknd.median().unwrap()
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

pub fn save_to_file<'a, R: Rec<'a>>(path: &Path, recorders: &'a Vec<R>) -> Result<(), String> {
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
        vr.push(Recorder::saveall(format!("test {}", i)));
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
