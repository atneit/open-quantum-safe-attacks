use anyhow::{anyhow, Context, Result};
use csv::{Writer, WriterBuilder};
use flate2::{write::GzEncoder, Compression};
use itertools::Itertools;
use linya::Progress;
use ndarray::prelude::*;
use rayon::prelude::*;
use std::{
    cmp::{max, min},
    collections::{hash_map::DefaultHasher, HashMap},
    fs::{self, File},
    hash::Hasher,
    io::{BufRead, BufReader, BufWriter},
    iter::{FromIterator, Peekable},
    ops::Deref,
    path::{Path, PathBuf},
    sync::{
        mpsc::{sync_channel, Receiver, SyncSender},
        Arc, Mutex, RwLock,
    },
    thread::{spawn, JoinHandle},
    usize,
};

pub type Integer = usize;
pub type Float = f64;

#[derive(Debug)]
pub struct Hist2D {
    hist2d: Array2<Integer>,
    minx: Integer,
    maxx: Integer,
    miny: Float,
    maxy: Float,
    binx_size: Integer,
    biny_size: Float,
}

impl Hist2D {
    fn new(minx: Integer, maxx: Integer, miny: Float, maxy: Float, bins: Integer) -> Self {
        let maxx = maxx + 1; // MAx upperbound inclusive
        let mut binsx = bins;
        let binsy = bins;
        let binx_size = if (maxx - minx) > bins {
            (maxx - minx) / bins
        } else {
            binsx = maxx - minx;
            1
        };
        let biny_size = (maxy - miny) / (bins as Float);

        Self {
            hist2d: Array2::zeros([binsx, binsy]),
            minx,
            maxx,
            miny,
            maxy,
            binx_size,
            biny_size,
        }
    }

    fn increment(&mut self, x: Integer, y: Float) {
        // println!(
        //     "x: {}, y: {}, binx_size: {}, biny_size: {}",
        //     x, y, self.binx_size, self.biny_size
        // );
        if y >= self.miny && y <= self.maxy && x >= self.minx && x <= self.maxx {
            let binx = x.saturating_sub(self.minx) / self.binx_size;
            let biny = ((y - self.miny) / self.biny_size) as Integer;
            if let Some(el) = self.hist2d.get_mut((binx, biny)) {
                *el += 1;
            }
        }
    }

    fn add(&self, rhs: &Hist2D) -> Hist2D {
        Hist2D {
            hist2d: &self.hist2d + &rhs.hist2d,
            minx: min(self.minx, rhs.minx),
            maxx: max(self.maxx, rhs.maxx),
            miny: self.miny.min(rhs.miny),
            maxy: self.maxy.max(rhs.maxy),
            binx_size: self.binx_size,
            biny_size: self.biny_size,
        }
    }
}

#[derive(Debug)]
struct Measurment {
    time: Integer,
    power: Float,
}

#[derive(Debug)]
struct Row<'a> {
    source: &'a str,
    phase: &'a str,
    modified: u16,
    repeat: Integer,
    measurment: Measurment,
}
#[derive(Debug)]
struct RowOwned {
    source: String,
    phase: String,
    modified: u16,
    repeat: Integer,
    measurment: Measurment,
}

impl<'a> Row<'a> {
    fn parse(line: &'a str) -> Result<Row<'a>> {
        let mut splitted = line.split(',');
        Ok(Row {
            source: splitted
                .next()
                .ok_or_else(|| anyhow!("missing source field"))?,
            phase: splitted
                .next()
                .ok_or_else(|| anyhow!("missing phase field"))?,
            modified: splitted
                .next()
                .ok_or_else(|| anyhow!("missing modified field"))?
                .parse()
                .context("modified")?,
            repeat: splitted
                .next()
                .ok_or_else(|| anyhow!("missing repeat field"))?
                .parse()
                .context("repeat")?,
            measurment: Measurment {
                time: splitted
                    .next()
                    .ok_or_else(|| anyhow!("missing time field"))?
                    .parse()
                    .context("time")?,
                power: splitted
                    .next()
                    .ok_or_else(|| anyhow!("missing power field"))?
                    .parse()
                    .context("power")?,
            },
        })
    }

    fn hash_of_trace_identity(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        hasher.write(self.source.as_bytes());
        hasher.write(self.phase.as_bytes());
        hasher.write_u16(self.modified);
        hasher.write_usize(self.repeat);
        hasher.finish()
    }
}

impl RowOwned {
    fn parse(line: &str) -> Result<RowOwned> {
        let parsed = Row::parse(line)?;
        Ok(RowOwned {
            source: parsed.source.to_owned(),
            phase: parsed.phase.to_owned(),
            modified: parsed.modified,
            repeat: parsed.repeat,
            measurment: parsed.measurment,
        })
    }
}

#[derive(Debug)]
struct Trace {
    source: String,
    phase: String,
    modified: u16,
    repeat: Integer,
    measurments: Vec<Measurment>,
}

impl Trace {
    fn new(row: RowOwned) -> Trace {
        Trace {
            source: row.source,
            phase: row.phase,
            modified: row.modified,
            repeat: row.repeat,
            measurments: vec![row.measurment],
        }
    }

    fn identity_matches(&self, row: &RowOwned) -> bool {
        self.source == row.source
            && self.phase == row.phase
            && self.modified == row.modified
            && self.repeat == row.repeat
    }

    fn add_unchecked(&mut self, row: RowOwned) {
        self.measurments.push(row.measurment);
    }
}

pub fn handle_file_meta(
    min_time: Integer,
    max_time: Integer,
    min_samples: Integer,
    max_samples: Integer,
    bins: Integer,
    path: PathBuf,
    progress: Arc<Mutex<Progress>>,
) -> Result<Hist2D> {
    let file = File::open(&path)?;
    let size = fs::metadata(&path).context("metadata")?.len() as Integer;
    let bar = progress
        .lock()
        .unwrap()
        .bar(size, format!("Reading {:?}", path));

    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut meta = Hist2D::new(
        min_samples,
        max_samples,
        min_time as Float,
        max_time as Float,
        bins,
    );
    if let Some(firstline) = lines.next() {
        let mut inc_tot = firstline.context("firstline")?.len() + 1; //Header, skip it, but save the length (+1 for line ending)
        let mut previous_trace_id_hash = 0;
        let mut num_samples = 0;
        let mut previous_time = 0;
        for line in lines {
            let line = line.context("read line")?;
            inc_tot += line.len() + 1; // (+1 for line ending)

            let row = Row::parse(&line).context("Row::parse")?;
            let trace_id_hash = row.hash_of_trace_identity();

            if trace_id_hash != previous_trace_id_hash {
                if num_samples > 0 {
                    meta.increment(num_samples, previous_time as Float);
                }
                num_samples = 0;
            }

            num_samples += 1;
            previous_trace_id_hash = trace_id_hash;
            previous_time = row.measurment.time;

            if inc_tot > 1024 * 1024 {
                progress.lock().unwrap().inc_and_draw(&bar, inc_tot);
                inc_tot = 0;
            }
        }
        meta.increment(num_samples, previous_time as Float);
        progress.lock().unwrap().inc_and_draw(&bar, inc_tot);
    }

    Ok(meta)
}

pub fn aggregate_meta(
    min_time: Integer,
    max_time: Integer,
    min_samples: Integer,
    max_samples: Integer,
    bins: Integer,
    paths: Vec<PathBuf>,
    destination: PathBuf,
) -> Result<()> {
    // io heavy work, so we double the number of threads
    // rayon::ThreadPoolBuilder::new()
    //     .num_threads(num_cpus::get() * 2)
    //     .build_global()
    //     .unwrap();
    let progress = Arc::new(Mutex::new(Progress::new()));
    let meta = paths
        .into_par_iter()
        .map(|path| {
            let progress = progress.clone();
            handle_file_meta(
                min_time,
                max_time,
                min_samples,
                max_samples,
                bins,
                path,
                progress,
            )
            .expect("Handle file")
        })
        .fold(
            || None,
            |res, new| {
                if let Some(res) = res {
                    return Some(new.add(&res));
                }
                Some(new)
            },
        )
        .reduce(
            || None,
            |res, new| {
                if let Some(res) = res {
                    if let Some(new) = new {
                        return Some(res.add(&new));
                    }
                }
                new
            },
        );

    if let Some(meta) = meta {
        println!("writing {} traces to {:?}", meta.hist2d.sum(), destination);

        let mut writer = WriterBuilder::new().from_path(destination)?;

        writer.write_record(["x", "y", "weight"])?;

        for (x, row) in meta.hist2d.rows().into_iter().enumerate() {
            let x = x * meta.binx_size + meta.minx;
            for (y, weight) in row.into_iter().enumerate() {
                let y = (y as Float) * meta.biny_size + meta.miny + (meta.biny_size / 2f64);
                writer.write_record(&[x.to_string(), y.to_string(), weight.to_string()])?;
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn handle_file_selection(
    min_time: Integer,
    max_time: Integer,
    min_power: Float,
    max_power: Float,
    min_samples: Integer,
    max_samples: Integer,
    bins: Integer,
    path: PathBuf,
    progress: Arc<Mutex<Progress>>,
) -> Result<Hist2D> {
    let mut selection = Hist2D::new(0, max_time, min_power, max_power, bins);

    let file = File::open(&path)?;
    let size = fs::metadata(&path).context("metadata")?.len() as Integer;
    let bar = progress
        .lock()
        .unwrap()
        .bar(size, format!("Reading {:?}", path));

    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    if let Some(firstline) = lines.next() {
        let mut inc_tot = firstline.context("firstline")?.len() + 1; //Header, skip it, but save the length (+1 for line ending)
        let mut previous_trace_id_hash = 0;
        let mut trace: Vec<Measurment> = vec![];
        for line in lines {
            let line = line.context("read line")?;
            inc_tot += line.len() + 1; // (+1 for line ending)

            let row = Row::parse(&line).context("Row::parse")?;
            let trace_id_hash = row.hash_of_trace_identity();

            if trace_id_hash != previous_trace_id_hash {
                // new trace
                if let Some(last_measurement) = trace.last() {
                    if min_samples <= trace.len()
                        && trace.len() <= max_samples
                        && min_time <= last_measurement.time
                        && last_measurement.time <= max_time
                    {
                        for m in &trace {
                            selection.increment(m.time, m.power);
                        }
                    }
                }

                trace.clear();
            }

            // Add measurment to the current trace
            trace.push(row.measurment);

            previous_trace_id_hash = trace_id_hash;

            if inc_tot > 1024 * 1024 {
                progress.lock().unwrap().inc_and_draw(&bar, inc_tot);
                inc_tot = 0;
            }
        }
        // last trace
        if let Some(last_measurement) = trace.last() {
            if min_samples <= trace.len()
                && trace.len() <= max_samples
                && min_time <= last_measurement.time
                && last_measurement.time <= max_time
            {
                for m in &trace {
                    selection.increment(m.time, m.power);
                }
            }
        }
        progress.lock().unwrap().inc_and_draw(&bar, inc_tot);
    }

    Ok(selection)
}

#[allow(clippy::too_many_arguments)]
pub fn aggregate_selection(
    min_time: Integer,
    max_time: Integer,
    min_power: Float,
    max_power: Float,
    min_samples: Integer,
    max_samples: Integer,
    bins: Integer,
    paths: Vec<PathBuf>,
    destination: PathBuf,
) -> Result<()> {
    let progress = Arc::new(Mutex::new(Progress::new()));
    let selection = paths
        .into_par_iter()
        .map(|path| {
            let progress = progress.clone();
            handle_file_selection(
                min_time,
                max_time,
                min_power,
                max_power,
                min_samples,
                max_samples,
                bins,
                path,
                progress,
            )
            .expect("Handle file")
        })
        .fold(
            || None,
            |res, new| {
                if let Some(res) = res {
                    return Some(new.add(&res));
                }
                Some(new)
            },
        )
        .reduce(
            || None,
            |res, new| {
                if let Some(res) = res {
                    if let Some(new) = new {
                        return Some(res.add(&new));
                    }
                }
                new
            },
        );

    if let Some(selection) = selection {
        println!(
            "writing {} measurments to {:?}",
            selection.hist2d.sum(),
            destination
        );

        let mut writer = WriterBuilder::new().from_path(destination)?;

        writer.write_record(["x", "y", "weight"])?;

        for (x, row) in selection.hist2d.rows().into_iter().enumerate() {
            let x = x * selection.binx_size + selection.minx;
            for (y, weight) in row.into_iter().enumerate() {
                let y = (y as Float) * selection.biny_size
                    + selection.miny
                    + (selection.biny_size / 2f64);
                writer.write_record(&[x.to_string(), y.to_string(), weight.to_string()])?;
            }
        }
    }

    Ok(())
}

fn batch_to_trace<I: Iterator<Item = RowOwned>>(iter: &mut Peekable<I>) -> Option<Trace> {
    let mut trace = if let Some(first) = iter.next() {
        Trace::new(first)
    } else {
        return None;
    };

    loop {
        let compat = match iter.peek() {
            Some(row) => trace.identity_matches(row),
            None => return None,
        };

        if !compat {
            return Some(trace);
        }
        trace.add_unchecked(iter.next().expect("iterator next"))
    }
}

pub(crate) type Weight = u8;

#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
enum DataSet {
    Train,
    Test,
    Validate,
}

impl DataSet {
    fn choose(train: Weight, test: Weight, validate: Weight) -> DataSet {
        use rand::prelude::*;
        use DataSet::*;
        [(Train, train), (Test, test), (Validate, validate)]
            .choose_weighted(&mut thread_rng(), |w| w.1)
            .unwrap()
            .0
    }
}

impl AsRef<Path> for DataSet {
    fn as_ref(&self) -> &Path {
        match self {
            DataSet::Train => Path::new("train"),
            DataSet::Test => Path::new("test"),
            DataSet::Validate => Path::new("validate"),
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct WriteDestination {
    source: String,
    phase: String,
    dataset: DataSet,
}

impl WriteDestination {
    fn from_trace(trace: &Trace, dataset: DataSet) -> Self {
        Self {
            source: trace.source.clone(),
            phase: trace.phase.clone(),
            dataset,
        }
    }
}

#[derive(Debug)]
struct TraceRouter {
    write_workers: Arc<RwLock<HashMap<WriteDestination, WriteWorker>>>,
    base_dir: PathBuf,
    weight_train: Weight,
    weight_test: Weight,
    weight_validate: Weight,
    max_samples: Integer,
    batch_size: usize,
}

impl TraceRouter {
    fn new(
        destination_folder: PathBuf,
        weight_train: Weight,
        weight_test: Weight,
        weight_validate: Weight,
        max_samples: Integer,
        batch_size: usize,
    ) -> Self {
        TraceRouter {
            write_workers: Arc::new(RwLock::new(HashMap::new())),
            base_dir: destination_folder,
            weight_train,
            weight_test,
            weight_validate,
            max_samples,
            batch_size,
        }
    }

    fn route(&self, trace: Trace) -> Result<()> {
        let workers = self.write_workers.read().unwrap();
        let dest = WriteDestination::from_trace(
            &trace,
            DataSet::choose(self.weight_train, self.weight_test, self.weight_validate),
        );
        let worker_res = workers.get(&dest);
        match worker_res {
            Some(worker) => {
                worker.send(trace)?;
            }
            None => {
                let worker =
                    WriteWorker::new(&self.base_dir, &dest, self.max_samples, self.batch_size)?;
                worker.send(trace)?;

                drop(workers);
                let mut workers = self.write_workers.write().unwrap();
                workers.insert(dest, worker);
            }
        }

        Ok(())
    }

    fn stop(&mut self) -> Result<Vec<WorkerResult>> {
        let mut results = Vec::new();

        let mut lock = self.write_workers.write().unwrap();
        let drain_it = lock.drain();
        for (_, worker) in drain_it {
            drop(worker.sender);
            let result = match worker.join_handle.join() {
                Ok(result) => result,
                Err(err) => match err.downcast::<anyhow::Error>() {
                    Ok(err) => return Err(*err),
                    Err(err) => return Err(anyhow!("{:?}", err)),
                },
            };

            results.push(result)
        }

        Ok(results)
    }
}

struct WorkerResult {
    basedir: String,
    files: Vec<(String, usize)>,
}

#[derive(Debug)]
struct WriteWorker {
    join_handle: JoinHandle<WorkerResult>,
    sender: SyncSender<Trace>,
}

impl WriteWorker {
    fn new(
        base_dir: &Path,
        dest: &WriteDestination,
        max_samples: usize,
        batch_size: usize,
    ) -> Result<Self> {
        let mut destination = base_dir.join(dest.dataset);
        std::fs::create_dir_all(&destination)?;
        destination.push(format!("{}@{}", dest.phase, dest.source));
        let (sender, receiver) = sync_channel(1000);
        let join_handle = spawn_write_worker(&destination, receiver, max_samples, batch_size);
        Ok(Self {
            join_handle,
            sender,
        })
    }

    fn send(&self, trace: Trace) -> Result<()> {
        Ok(self.sender.send(trace)?)
    }
}

fn create_csvwriter(
    destination: &Path,
    num: usize,
    max_samples: Integer,
) -> Result<(Writer<GzEncoder<BufWriter<File>>>, PathBuf)> {
    let final_path = destination.with_file_name(format!(
        "{}_{:04}.csv.gz",
        destination.file_name().unwrap().to_string_lossy(),
        num
    ));
    let mut csvwriter = WriterBuilder::new().from_writer(GzEncoder::new(
        BufWriter::new(File::create(&final_path).context(format!("{:?}", final_path))?),
        Compression::fast(),
    ));

    let mut headers = Vec::from_iter(["modified"].iter().map(Deref::deref).map(String::from));
    headers.extend((0..max_samples).into_iter().map(|i| format!("power {}", i)));

    csvwriter
        .write_record(headers)
        .context("Write csv header")?;

    Ok((csvwriter, final_path))
}

fn write_worker(
    destination: PathBuf,
    receiver: Receiver<Trace>,
    max_samples: Integer,
    batch_size: usize,
) -> Result<WorkerResult> {
    // csvwriter that is both compressed and buffered
    let (mut csvwriter, mut filename) = create_csvwriter(&destination, 0, max_samples)?;

    let mut trace_count = 0usize;

    let mut files = vec![];

    for trace in receiver.iter() {
        trace_count += 1;

        let modified = if trace.modified == 0 {
            String::from("0")
        } else {
            String::from("1")
        };

        let first_fields = [modified];

        csvwriter.write_record(
            first_fields.iter().cloned().chain(
                trace
                    .measurments
                    .iter()
                    .map(|m| &m.power)
                    .map(ToString::to_string),
            ),
        )?;

        if trace_count >= batch_size {
            files.push((filename.to_string_lossy().to_string(), trace_count));
            trace_count = 0;
            let tuple = create_csvwriter(&destination, files.len(), max_samples)?;
            csvwriter = tuple.0;
            filename = tuple.1;
        }
    }

    files.push((filename.to_string_lossy().to_string(), trace_count));

    Ok(WorkerResult {
        files,
        basedir: destination.parent().unwrap().to_string_lossy().to_string(),
    })
}

fn spawn_write_worker(
    destination: &Path,
    receiver: Receiver<Trace>,
    max_samples: Integer,
    batch_size: usize,
) -> JoinHandle<WorkerResult> {
    let destination = destination.to_path_buf();
    spawn(move || write_worker(destination, receiver, max_samples, batch_size).unwrap())
}

#[allow(clippy::too_many_arguments)]
pub fn extract_selection(
    destination_folder: PathBuf,
    weight_train: Weight,
    weight_test: Weight,
    weight_validate: Weight,
    batch_size: usize,
    min_time: Integer,
    max_time: Integer,
    min_samples: Integer,
    max_samples: Integer,
    paths: Vec<PathBuf>,
) -> Result<()> {
    let mut router = TraceRouter::new(
        destination_folder,
        weight_train,
        weight_test,
        weight_validate,
        max_samples,
        batch_size,
    );

    let progress = Arc::new(Mutex::new(Progress::new()));

    let trace_count: usize = paths
        .into_par_iter()
        .map(|path| {
            let file = crate::utils::ProgressRead::from_path(&path, progress.clone())
                .expect("Open file for reading");
            let reader = BufReader::new(file);
            let skip = 1; //one row for header
            let mut linenum = skip;
            reader
                .lines()
                .map(Result::unwrap)
                .skip(skip) //We skip the header row
                .map(|line| {
                    linenum += 1;

                    RowOwned::parse(&line)
                        .context(format!("{:?} (line {}): \"{}\"", path, linenum, line))
                        .expect("Parse row")
                })
                .peekable()
                .batching(batch_to_trace)
                .filter(|trace: &Trace| {
                    let last = trace.measurments.last().unwrap();
                    let samples = trace.measurments.len();
                    min_time <= last.time
                        && last.time <= max_time
                        && min_samples <= samples
                        && samples <= max_samples
                })
                .map(|trace: Trace| router.route(trace).expect("send trace to"))
                .count()
        })
        .sum();

    println!(
        "Filtered out {} traces, waiting for the final writes...",
        trace_count
    );

    let mut allresults = router.stop()?;

    allresults.sort_by(|a, b| a.basedir.cmp(&b.basedir));

    let mut total = 0;
    for res in allresults {
        let traces: usize = res.files.iter().map(|f| f.1).sum();
        total += traces;
        println!(
            "{} \t traces saved in {} ({} batches)",
            traces,
            res.basedir,
            res.files.len()
        );
    }

    if trace_count != total {
        return Err(anyhow!(
            "written {} traces (expected {}).",
            total,
            trace_count
        ));
    }

    Ok(())
}
