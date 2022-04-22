use log::{debug, error};
use rapl::{Float, Integer, Weight};
use std::{panic, path::PathBuf, process};
use structopt::StructOpt;

mod rapl;
mod utils;

#[derive(StructOpt, Debug)]
#[structopt(name = "command")]
#[allow(clippy::enum_variant_names)]
/// Post Processing for oqs-afw data files.
enum Commands {
    RaplMeta {
        destination: PathBuf,
        min_time: Integer,
        max_time: Integer,
        min_samples: Integer,
        max_samples: Integer,
        bins: Integer,
        paths: Vec<PathBuf>,
    },
    RaplSelect {
        destination: PathBuf,
        min_time: Integer,
        max_time: Integer,
        min_samples: Integer,
        max_samples: Integer,
        min_power: Float,
        max_power: Float,
        bins: Integer,
        paths: Vec<PathBuf>,
    },
    /// Extracts traces that matches into the destination file. Each trace is given a new id (the repeat "column")
    RaplExtract {
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
    },
}

#[derive(StructOpt, Debug)]
#[structopt(name = "postprocess")]
struct ProgramArgs {
    #[structopt(short, long, default_value = "info")]
    /// Set log level to trace, debug, info, warn or error
    loglevel: log::LevelFilter,
    #[structopt(subcommand)]
    command: Commands,
}

fn main() {
    // Let's make sure the entire program exits when a single thread panics
    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        // invoke the default handler and exit the process
        orig_hook(panic_info);
        process::exit(1);
    }));

    let matches = ProgramArgs::from_args();
    simple_logger::SimpleLogger::new()
        .with_level(matches.loglevel)
        .init()
        .unwrap();
    debug!("command line arguments parsed: {:?}", matches);

    let result = match matches.command {
        Commands::RaplMeta {
            min_time,
            max_time,
            min_samples,
            max_samples,
            bins,
            paths,
            destination,
        } => rapl::aggregate_meta(
            min_time,
            max_time,
            min_samples,
            max_samples,
            bins,
            paths,
            destination,
        ),
        Commands::RaplSelect {
            min_time,
            max_time,
            min_power,
            max_power,
            min_samples,
            max_samples,
            bins,
            paths,
            destination,
        } => rapl::aggregate_selection(
            min_time,
            max_time,
            min_power,
            max_power,
            min_samples,
            max_samples,
            bins,
            paths,
            destination,
        ),
        Commands::RaplExtract {
            destination_folder,
            weight_train,
            weight_test,
            weight_validate,
            batch_size,
            min_time,
            max_time,
            min_samples,
            max_samples,
            paths,
        } => rapl::extract_selection(
            destination_folder,
            weight_train,
            weight_test,
            weight_validate,
            batch_size,
            min_time,
            max_time,
            min_samples,
            max_samples,
            paths,
        ),
    };

    if let Err(errmsg) = result {
        error!("Aborting due to error: {}", errmsg);
    }
}
