use std::sync::Arc;

use log::info;

use crate::utils::{StrErr, RATE_MS};

pub fn thread_work<I, T, ARG, F, FS>(
    num_threads: usize,
    arg: ARG,
    work: F,
    watch_stop: FS,
) -> Result<Vec<T>, String>
where
    I: Default + Send + Sync + 'static,
    T: Send + 'static,
    ARG: Clone + Send + 'static,
    F: Fn(usize, Arc<I>, ARG) -> Result<Option<T>, String>,
    F: Send + Clone + 'static,
    FS: Fn(&Arc<I>) -> bool,
{
    info!("Starting {} threads...", num_threads);
    let syncronization = Arc::new(I::default());
    #[allow(clippy::needless_collect)]
    let threads: Vec<_> = (0..num_threads)
        .map(|tid| {
            let arg = arg.clone();
            let syncronization = syncronization.clone();
            let work = work.clone();
            std::thread::spawn(move || work(tid, syncronization, arg))
        })
        .collect(); // Collect so that we start all threads before we start to join them

    while !watch_stop(&syncronization) {
        std::thread::sleep(RATE_MS / 2);
    }

    info!("Stopping {} threads...", num_threads);
    let some_results = threads
        .into_iter()
        .map(|jh| jh.join()) // Wait for results of thread
        .collect::<Result<Vec<_>, _>>() //Short-circuit any join errors
        .strerr()? // Convert join errors to string
        .into_iter() // Iterate over all return-values from the threads
        .collect::<Result<Vec<_>, String>>()? // Short-circuit if any thread returned an error
        .into_iter() // Iterate over all Ok results
        .flatten() // filter out all the Some(T)
        .collect(); // Store all T's in a vector

    Ok(some_results)
}
