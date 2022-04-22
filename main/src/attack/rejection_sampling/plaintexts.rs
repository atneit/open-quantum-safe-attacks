use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, TryLockError,
    },
    time::Duration,
};

use liboqs_rs_bindings as oqs;
use log::{error, info};
use log_derive::logfn_inputs;
use ms_converter::ms_into_time;
use oqs::{KemBuf, KemWithRejectionSampling};
use rand::{thread_rng, Fill};
use rusqlite::{params, params_from_iter, Connection, Params, Row, ToSql};
use signal_hook::{consts::TERM_SIGNALS, flag};
use structopt::StructOpt;

use crate::utils::{BarSelector, ClonableProgressManager, ProgressBars, StrErr};

const UPDATE_RATE_HZ: u64 = 1;
const UPDATE_RATE_MS: Duration = Duration::from_millis(1000 / UPDATE_RATE_HZ);

#[derive(StructOpt, Debug, Clone)]
pub struct CollectPlaintextsOptions {
    /// Path to sqlite db to store the plaintexts
    #[structopt(short, long)]
    destination: PathBuf,

    /// Maximum number of plaintexts to store, per iteration count
    #[structopt(short("l"), long("limit"), default_value("1000"))]
    pt_limit_per_iter: u32,

    /// Clear the database before starting
    #[structopt(short("c"), long)]
    clear: bool,

    /// The number of worker threads to start
    #[structopt(short("t"), long, default_value("4"))]
    threads: u8,

    /// How often to save count statistics, in seconds
    #[structopt(short("s"), long, parse(try_from_str=ms_into_time))]
    save_interval: Option<Duration>,

    /// Do not report on progress, except through normal logging
    #[structopt(short, long)]
    quiet: bool,

    /// Stop after specified amount of time has elapsed
    #[structopt(short("a"), long, parse(try_from_str=ms_into_time))]
    stop_after: Option<Duration>,

    /// Walks through each plaintext in the database and recheks the iteration count
    #[structopt(short, long)]
    reindex_plaintexts: bool,
}

struct DbConnection {
    conn: Mutex<Connection>,
    #[allow(clippy::type_complexity)]
    queue: Mutex<VecDeque<(String, Vec<Box<dyn ToSql + Send>>)>>,
}

impl std::fmt::Debug for DbConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbConnection")
            .field("conn", &self.conn)
            .finish()
    }
}

impl BarSelector for u8 {}

#[derive(Debug, Clone)]
pub struct PlaintextDb<KEM: KemWithRejectionSampling> {
    db: Arc<DbConnection>,
    add_limit: u32,
    count_below_cache: Vec<bool>,
    count_plaintexts: Vec<u64>,
    last_get_next_max_id: Option<u32>,
    last_get_next_iter_id: Option<u32>,
    last_get_next_iter_iter: Option<u32>,
    _kem: PhantomData<KEM>,
}

macro_rules! sql_pt {
    ($sql:literal, $kem:tt) => {{
        sql!($sql, $kem, "_plaintexts")
    }};
}
macro_rules! sql_cnt {
    ($sql:literal, $kem:tt) => {{
        sql!($sql, $kem, "_plaintext_count")
    }};
}
macro_rules! sql {
    ($sql:literal, $kem:tt, $table_name:literal) => {{
        format!($sql, kem = $kem::NAME, table = $table_name)
    }};
}

const MAX_QUEUE_LENGTH: usize = 100;

impl<KEM: KemWithRejectionSampling> PlaintextDb<KEM> {
    pub fn new(dest: impl AsRef<Path>, add_limit: u32) -> Result<Self, String> {
        let conn = Connection::open(dest).strerr()?;
        conn.busy_handler(Some(|_i| true)).strerr()?; // Ignore busy errors
        Self::new_shared(
            Arc::new(DbConnection {
                conn: Mutex::new(conn),
                queue: Mutex::new(VecDeque::with_capacity(MAX_QUEUE_LENGTH)),
            }),
            add_limit,
        )
    }

    fn new_shared(db: Arc<DbConnection>, add_limit: u32) -> Result<Self, String> {
        let ptdb = Self {
            db,
            add_limit,
            count_below_cache: vec![],
            count_plaintexts: vec![],
            last_get_next_max_id: None,
            last_get_next_iter_id: None,
            last_get_next_iter_iter: None,
            _kem: PhantomData,
        };
        ptdb.modify(
            sql_cnt!(
                "CREATE TABLE IF NOT EXISTS {kem}{table} (
                id          INTEGER PRIMARY KEY,
                iter        INTEGER,
                count       INTEGER)",
                KEM
            ),
            vec![],
        )?;
        ptdb.modify(
            sql_pt!(
                "CREATE TABLE IF NOT EXISTS {kem}{table}(
                id          INTEGER PRIMARY KEY,
                iter        INTEGER,
                plaintext   BLOB)",
                KEM
            ),
            vec![],
        )?;
        ptdb.modify(
            sql_pt!(
                "CREATE INDEX IF NOT EXISTS {kem}_iter_index ON {kem}{table} (iter)",
                KEM
            ),
            vec![],
        )?;

        Ok(ptdb)
    }

    fn modify(&self, sql: String, params: Vec<Box<dyn ToSql + Send>>) -> Result<(), String> {
        let mut block = false;
        'restart: loop {
            let lock = if block {
                match self.db.conn.lock() {
                    Ok(conn) => Ok(Some(conn)),
                    Err(err) => Err(err.to_string()),
                }
            } else {
                match self.db.conn.try_lock() {
                    Ok(conn) => Ok(Some(conn)),
                    Err(TryLockError::WouldBlock) => Ok(None),
                    Err(err) => Err(err.to_string()),
                }
            };
            break match lock {
                Ok(Some(mut conn)) => {
                    let tx = conn.transaction().strerr()?;
                    let mut queue = self.db.queue.lock().strerr()?;
                    for (sql, params) in queue.drain(..) {
                        tx.execute(&sql, params_from_iter(params)).strerr()?;
                    }
                    tx.execute(&sql, params_from_iter(params)).strerr()?;
                    tx.commit().strerr()
                }
                Ok(None) => {
                    let mut queue = self.db.queue.lock().strerr()?;
                    if queue.len() >= MAX_QUEUE_LENGTH {
                        block = true;
                        continue 'restart;
                    }
                    queue.push_back((sql, params));
                    Ok(())
                }
                Err(err) => Err(err),
            };
        }
    }

    fn query_row<T, P, F>(&self, sql: String, params: P, f: F, or_else: T) -> Result<T, String>
    where
        P: Params,
        F: FnOnce(&Row<'_>) -> rusqlite::Result<T>,
    {
        self.db
            .conn
            .lock()
            .strerr()?
            .query_row(&sql, params, f)
            .or_else(|err| match err {
                rusqlite::Error::QueryReturnedNoRows => Ok(or_else),
                err => Err(err),
            })
            .strerr()
    }

    pub fn get_min_max(&mut self, max: bool) -> Result<Option<(u32, KEM::Plaintext)>, String> {
        let (id, iter, pt): (Option<u32>, Option<u32>, Option<Vec<u8>>) = self.query_row(
            if max {
                sql_pt!(
                    "SELECT id, iter, plaintext FROM {kem}{table} ORDER BY iter DESC, id DESC LIMIT 1", 
                    KEM
                )
            } else {
                sql_pt!(
                    "SELECT id, iter, plaintext FROM {kem}{table} ORDER BY iter ASC, id ASC LIMIT 1", 
                    KEM
                )
            },
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            (None, None, None),
        )?;
        if let (Some(id), Some(iter), Some(pt)) = (id, iter, pt) {
            let mut plaintext = KEM::Plaintext::new();
            plaintext.as_mut_slice().copy_from_slice(&pt);
            self.last_get_next_max_id.replace(id);
            Ok(Some((iter, plaintext)))
        } else {
            Ok(None)
        }
    }

    pub fn get_next(
        &mut self,
        previous_id: Option<u32>,
    ) -> Result<Option<(u32, u32, KEM::Plaintext)>, String> {
        let (id, iter, pt): (Option<u32>, Option<u32>, Option<Vec<u8>>) = if let Some(previous_id) =
            previous_id
        {
            self.query_row(
                sql_pt!(
                    "SELECT id, iter, plaintext FROM {kem}{table} WHERE id > ?1 ORDER BY id ASC LIMIT 1", 
                    KEM
                ),
                params![previous_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                (None, None, None),
            )?
        } else {
            self.query_row(
                sql_pt!(
                    "SELECT id, iter, plaintext FROM {kem}{table} ORDER BY id ASC LIMIT 1",
                    KEM
                ),
                params![],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                (None, None, None),
            )?
        };

        if let (Some(id), Some(iter), Some(pt)) = (id, iter, pt) {
            let mut plaintext = KEM::Plaintext::new();
            plaintext.as_mut_slice().copy_from_slice(&pt);
            Ok(Some((id, iter, plaintext)))
        } else {
            Ok(None)
        }
    }

    pub fn update_iter(&mut self, id: u32, iter: u32) -> Result<(), String> {
        self.modify(
            sql_pt!("UPDATE {kem}{table} SET iter = ?2 WHERE id = ?1", KEM),
            vec![Box::new(id), Box::new(iter)],
        )?;

        Ok(())
    }

    /// Gets the next available plaintext that matches the iteration count specified.
    /// No plaintext is returned twice for as long as iter remains constant.
    pub fn get_next_iter(
        &mut self,
        iter: u32,
        reset: bool,
    ) -> Result<Option<(u32, KEM::Plaintext)>, String> {
        let previous_id: u32 = match (
            self.last_get_next_iter_iter,
            self.last_get_next_iter_id,
            reset,
        ) {
            (Some(last_iter), Some(last_id), false) if last_iter == iter => last_id,
            _ => u32::MAX,
        };
        let (id, iter, pt): (Option<u32>, Option<u32>, Option<Vec<u8>>) = self.query_row(
            sql_pt!(
                "SELECT id, iter, plaintext FROM {kem}{table} WHERE id < ?1 AND iter == ?2 ORDER BY iter DESC, id DESC",
                KEM
            ),
            params![previous_id, iter],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            (None, None, None),
        )?;
        if let (Some(id), Some(iter), Some(pt)) = (id, iter, pt) {
            let mut plaintext = KEM::Plaintext::new();
            plaintext.as_mut_slice().copy_from_slice(&pt);
            self.last_get_next_iter_id.replace(id);
            self.last_get_next_iter_iter.replace(iter);
            Ok(Some((iter, plaintext)))
        } else {
            Ok(None)
        }
    }

    fn count_below(&mut self, iter: u32, below: u32) -> Result<bool, String> {
        let iterus = iter as usize;
        if let Some(below_cache) = self.count_below_cache.get(iterus) {
            if !below_cache {
                return Ok(false);
            }
        }
        let count = self.count(iter)?;
        if self.count_below_cache.len() <= iterus {
            self.count_below_cache.resize(iterus + 1, true);
        }

        let cmp = count < below;

        // Resize above makes this safe
        unsafe { *self.count_below_cache.get_unchecked_mut(iterus) = cmp };

        Ok(cmp)
    }

    pub fn count(&self, iter: u32) -> Result<u32, String> {
        if let Some(count) = self
            .query_row(
                sql_pt!("SELECT count(id) FROM {kem}{table} WHERE iter == ?1", KEM),
                [iter],
                |r| r.get(0),
                None,
            )
            .strerr()?
        {
            Ok(count)
        } else {
            Ok(0)
        }
    }

    pub fn iter_minmax(&self) -> Result<(Option<u32>, Option<u32>), String> {
        self.query_row(
            sql_pt!("SELECT MIN(iter), MAX(iter) FROM {kem}{table}", KEM),
            [],
            |r| match (r.get(0), r.get(1)) {
                (Ok(min), Ok(max)) => Ok((min, max)),
                (_, Err(e)) => Err(e),
                (Err(e), _) => Err(e),
            },
            (None, None),
        )
        .strerr()
    }

    pub fn aggregate_iter_counts(&self) -> Result<(), String> {
        if let Some(max_duplicate) = self.query_row(
            sql_cnt!(
                "SELECT MAX(a.c) FROM (SELECT iter, COUNT(*) as c FROM {kem}{table} GROUP BY iter ORDER BY iter) a;",
                KEM
            ),
            [],
            |r| r.get::<_, Option<u32>>(0),
            None,
        )? {
            if max_duplicate > 1 {
                info!(
                    "Aggregating up to {} duplicates per iteration count!",
                    max_duplicate
                );
                if let Some(iter_counts) = self.iter_counts()? {
                    self.modify(sql_cnt!("DELETE FROM {kem}{table}", KEM), vec![])?;
                    for (iter, count, _saved) in iter_counts {
                        self.modify(
                            sql_cnt!("INSERT INTO {kem}{table}(iter, count) VALUES (?1, ?2)", KEM),
                            vec![Box::new(iter), Box::new(count)],
                        )?;
                    }
                }
            }
        }
        self.modify(
            sql_cnt!(
                "CREATE UNIQUE INDEX IF NOT EXISTS {kem}count_iter_index ON {kem}{table}(iter)",
                KEM
            ),
            vec![],
        )?;
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    pub fn iter_counts(&self) -> Result<Option<Vec<(u64, u64, u64)>>, String> {
        let v = if let (Some(iter_min), Some(iter_max)) = self.iter_minmax()? {
            let mut v = vec![];
            for iter in iter_min..=iter_max {
                if let Some(count) = self.query_row(
                    sql_cnt!("SELECT SUM(count) FROM {kem}{table} WHERE iter = ?1", KEM),
                    params![iter],
                    |r| r.get(0),
                    Some(0),
                )? {
                    let saved_count = self.count(iter)?;
                    if count > 0 || saved_count > 0 {
                        v.push((iter as u64, count, saved_count as u64));
                    }
                }
            }
            Some(v)
        } else {
            None
        };

        Ok(v)
    }

    pub fn iter_saved_counts(&self) -> Result<Option<Vec<(u64, u64)>>, String> {
        let v = if let (Some(iter_min), Some(iter_max)) = self.iter_minmax()? {
            let mut v = vec![];
            for iter in iter_min..=iter_max {
                let saved_count = self.count(iter)?;
                if saved_count > 0 {
                    v.push((iter as u64, saved_count as u64));
                }
            }
            Some(v)
        } else {
            None
        };

        Ok(v)
    }

    fn add_pt(&mut self, pt: &KEM::Plaintext, iter: u32) -> Result<(), String> {
        if self.count_below(iter, self.add_limit)? {
            self.modify(
                sql_pt!(
                    "INSERT INTO {kem}{table} (iter, plaintext) VALUES (?1, ?2)",
                    KEM
                ),
                vec![Box::new(iter), Box::new(pt.as_slice().to_vec())],
            )?;
        }

        if let Some(count) = self.count_plaintexts.get_mut(iter as usize) {
            *count += 1;
        } else {
            self.count_plaintexts.resize((iter + 1) as usize, 0);
            // Resize above makes this safe
            unsafe { *self.count_plaintexts.get_unchecked_mut(iter as usize) = 1 };
        }

        Ok(())
    }

    fn save_iter_counts(&mut self) -> Result<(), String> {
        for iter in 0..self.count_plaintexts.len() {
            if let Some(count) = self.count_plaintexts.get(iter as usize).copied() {
                if count > 0 {
                    info!(
                        "{} new plaintexts encountered with {} iterations",
                        count, iter
                    );
                    self.modify(
                        sql_cnt!(
                            "INSERT INTO {kem}{table} (iter, count) VALUES (?1, ?2) ON CONFLICT(iter) DO UPDATE SET count=count + ?2", 
                            KEM
                        ),
                        vec![Box::new(iter), Box::new(count)],
                    )?;

                    self.count_plaintexts[iter] = 0;
                }
            }
        }

        Ok(())
    }

    fn clear(&self) -> Result<(), String> {
        self.modify(sql_pt!("DELETE FROM {kem}{table}", KEM), vec![])?;
        self.modify(sql_cnt!("DELETE FROM {kem}{table}", KEM), vec![])
    }
}

fn update_progress<KEM: KemWithRejectionSampling>(
    ptdb: &PlaintextDb<KEM>,
    pm: &ClonableProgressManager<u8>,
) -> Result<(), String> {
    let mut parts = String::from("Saved plaintexts, per iteration count: {");
    if let (Some(min), Some(max)) = ptdb.iter_minmax()? {
        for iter in (min..=max).rev() {
            let count = ptdb.count(iter)?;
            if count > 0 {
                parts.push_str(&iter.to_string());
                parts.push_str(": ");
                parts.push_str(&count.to_string());
                parts.push_str(", ");
            }
        }
        parts.pop(); // ' '
        parts.pop(); // ','
    }
    parts.push('}');
    pm.set_message(0, parts);
    pm.tick();

    Ok(())
}

fn get_stop_signal() -> Result<Arc<AtomicBool>, String> {
    // Make sure double CTRL+C and similar kills
    let stop_signal = Arc::new(AtomicBool::new(false));
    for sig in TERM_SIGNALS {
        // When terminated by a second term signal, exit with exit code 1.
        // This will do nothing the first time (because term_now is false).
        flag::register_conditional_shutdown(*sig, 1, Arc::clone(&stop_signal)).strerr()?;
        // But this will "arm" the above for the second time, by setting it to true.
        // The order of registering these is important, if you put this one first, it will
        // first arm and then terminate ‒ all in the first round.
        flag::register(*sig, Arc::clone(&stop_signal)).strerr()?;
    }
    Ok(stop_signal)
}

#[logfn_inputs(Trace)]
pub fn run<KEM: 'static + KemWithRejectionSampling + std::marker::Send + std::marker::Sync>(
    opt: CollectPlaintextsOptions,
) -> Result<(), String> {
    let start_time = std::time::Instant::now();
    info!(
        "Opening or creating plaintext database at: {:?}",
        opt.destination
    );
    let mut ptdb = PlaintextDb::<KEM>::new(&opt.destination, opt.pt_limit_per_iter)?;
    {
        if opt.clear {
            ptdb.clear()?;
            info!("Cleared all plaintexts from database");
        }

        ptdb.aggregate_iter_counts()?;

        if let Some(iter_counts) = ptdb.iter_counts()? {
            for (iter, count, stored) in iter_counts {
                info!(
                    "Currently {} out of {} encountered plaintexts with {} iterations",
                    stored, count, iter
                );
            }
        }
    }

    if opt.reindex_plaintexts {
        let mut previous_id = None;
        let mut mapping = HashMap::new();
        let mut counter = 0;
        while let Some((id, iter, mut pt)) = ptdb.get_next(previous_id)? {
            previous_id = Some(id);
            counter += 1;
            if counter % 1000 == 0 {
                info!("Reindexed {} plaintexts", counter);
            };

            let new_iter = KEM::num_rejections(&mut pt)? as u32;

            let key = if iter != new_iter {
                format!(
                    "Changed plaintext number of iterations from {} to {}",
                    iter, new_iter
                )
            } else {
                String::from("No change")
            };
            let count = mapping.entry(key).or_insert(0);
            *count += 1;
            ptdb.update_iter(id, new_iter)?;
        }

        let mut mapping: Vec<_> = mapping.drain().collect();
        mapping.sort();
        mapping
            .into_iter()
            .for_each(|(k, v)| info!("{} {} times", k, v));

        info!("Done reindexing plaintexts, exiting now");
        return Ok(());
    }

    let mut save_signals: Vec<_> = (0..opt.threads)
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect();

    let stop_signal = get_stop_signal()?;

    let workers: Vec<_> = save_signals
        .iter()
        .cloned()
        .enumerate()
        .map(|(t, savesignal)| {
            let mut ptdb = ptdb.clone();
            let stop_signal = stop_signal.clone();
            std::thread::spawn(move || {
                let mut inner = || -> Result<(), String> {
                    info!("Thread {} has started working!", t);
                    let mut rng = thread_rng();
                    let mut pt = KEM::Plaintext::new();
                    loop {
                        pt.as_mut_slice().try_fill(&mut rng).strerr()?;
                        let iter = KEM::num_rejections(&mut pt)? as u32;
                        ptdb.add_pt(&pt, iter)?;
                        if savesignal.load(Ordering::Relaxed) {
                            ptdb.save_iter_counts()?;
                            savesignal.store(false, Ordering::Relaxed);
                        }
                        if stop_signal.load(Ordering::Relaxed) {
                            info!("Stopping thread {} gracefully...", t);
                            ptdb.save_iter_counts()?;
                            break Ok(());
                        }
                    }
                };
                match inner() {
                    Ok(()) => {}
                    Err(e) => error!("{:?}", e),
                }
            })
        })
        .collect();

    let progress = if !opt.quiet {
        let pm = ClonableProgressManager::create();
        pm.add(0, None, "", "Stop with Ctrl-C. {wide_msg}");
        pm.start([]);
        Some(pm)
    } else {
        None
    };
    let reset_until_save = opt
        .save_interval
        .map(|si| UPDATE_RATE_HZ * std::cmp::max(si.as_secs(), 1));
    let mut until_save = reset_until_save;
    loop {
        // First, update progress (unless --quiet)
        if let Some(pm) = &progress {
            update_progress(&ptdb, pm)?;
        }

        // Then we sleep for a while
        std::thread::sleep(UPDATE_RATE_MS);

        // Check save interval
        if let Some(until_save) = until_save.as_mut() {
            *until_save -= 1;
            if *until_save == 0 {
                save_signals
                    .iter_mut()
                    .for_each(|savesignal| savesignal.store(true, Ordering::Relaxed));
                *until_save = reset_until_save.unwrap();
            }
        }

        // Check stop_after interval
        if let Some(stop_after) = opt.stop_after {
            let elapsed = start_time.elapsed();
            if elapsed >= stop_after {
                info!(
                    "{:?} has elapsed since start, performing gracefull shutdown!",
                    elapsed
                );
                stop_signal.store(true, Ordering::Relaxed);
            }
        }

        // Shutdown if stop_signal is true
        if stop_signal.load(Ordering::Relaxed) {
            break;
        }
    }

    // Wait for all the worker threads to stop
    for jh in workers {
        jh.join().strerr()?
    }

    // Report on the final statistics
    if let Some(iter_counts) = ptdb.iter_counts()? {
        for (iter, count, stored) in iter_counts {
            info!(
                "Ended with {} out of {} in total encountered plaintexts with {} iterations",
                stored, count, iter
            );
        }
    }

    // Update and stop the live-terminal progress reporting
    if let Some(pm) = &progress {
        update_progress(&ptdb, pm)?;
        pm.stop();
    }

    Ok(())
}
