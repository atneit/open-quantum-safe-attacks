use std::{io::Write, path::PathBuf};

use indicatif::ProgressBar;
use log::error;
use slog::{slog_o, Drain, Logger, Record};
use slog_term::{
    CountingWriter, Decorator, FullFormat, PlainSyncDecorator, RecordDecorator,
    ThreadSafeTimestampFn,
};

struct LogInterface<D> {
    terminal: D,
}

struct ProgressBarWriter {
    pb: ProgressBar,
    buf: Vec<u8>,
}

impl ProgressBarWriter {
    fn new(pb: ProgressBar) -> Self {
        ProgressBarWriter { pb, buf: vec![] }
    }
}

fn predicate(byte: &u8) -> bool {
    *byte as u32 == '\n' as u32 || *byte as u32 == '\r' as u32
}

impl Write for ProgressBarWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);

        let mut lastslice = vec![];

        for slice in self.buf.split_inclusive(predicate) {
            if let Some(last) = slice.last() {
                if predicate(last) {
                    // this slice ends with newline
                    let string = String::from_utf8_lossy(slice);
                    self.pb.println(string);
                } else {
                    // This slice does not end with a newline
                    // Let's cache it!
                    lastslice.extend_from_slice(slice);
                }
            }
        }

        self.buf = lastslice;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<D: Decorator> Decorator for LogInterface<D> {
    fn with_record<F>(
        &self,
        record: &slog::Record,
        logger_values: &slog::OwnedKVList,
        f: F,
    ) -> std::io::Result<()>
    where
        F: FnOnce(&mut dyn slog_term::RecordDecorator) -> std::io::Result<()>,
    {
        let opt_pb = unsafe { LOG_INTERCEPT_PROGRESSBAR.clone() };
        if let Some(pb_intercept) = opt_pb {
            let pd = PlainSyncDecorator::new(ProgressBarWriter::new(pb_intercept));
            pd.with_record(record, logger_values, f)
        } else {
            self.terminal.with_record(record, logger_values, f)
        }
    }
}

impl<D: Decorator> LogInterface<D> {
    fn new(terminal: D) -> Self {
        LogInterface { terminal }
    }
}

pub static mut LOG_INTERCEPT_PROGRESSBAR: Option<ProgressBar> = None;

fn print_msg_header(
    fn_timestamp: &dyn ThreadSafeTimestampFn<Output = std::io::Result<()>>,
    mut rd: &mut dyn RecordDecorator,
    record: &Record,
    use_file_location: bool,
) -> std::io::Result<bool> {
    rd.start_timestamp()?;
    fn_timestamp(&mut rd)?;

    rd.start_whitespace()?;
    write!(rd, " ")?;

    rd.start_level()?;
    write!(rd, "{}", record.level().as_str())?;

    if use_file_location {
        rd.start_location()?;
        write!(
            rd,
            "[{}:{}:{}]",
            record.location().file,
            record.location().line,
            record.location().column
        )?;
    }

    rd.start_whitespace()?;
    write!(rd, " ")?;

    rd.start_msg()?;
    let mut count_rd = CountingWriter::new(&mut rd);
    write!(count_rd, "{}", record.msg())?;
    Ok(count_rd.count() != 0)
}

pub fn setup_logging(
    level: log::Level,
    logdest: &Option<PathBuf>,
) -> slog_scope::GlobalLoggerGuard {
    let decorator = PlainSyncDecorator::new(std::io::stdout());
    let interface = LogInterface::new(decorator);
    let logdest = FullFormat::new(PlainSyncDecorator::new(
        std::fs::File::create(logdest.as_ref().unwrap_or(&"/dev/null".into()))
            .expect("logdest not available for writing"),
    ))
    .use_custom_header_print(print_msg_header)
    .build();
    let drain = FullFormat::new(interface)
        .use_custom_header_print(print_msg_header)
        .build();
    let leveldrain = drain.filter_level(match level {
        log::Level::Error => slog::Level::Error,
        log::Level::Warn => slog::Level::Warning,
        log::Level::Info => slog::Level::Info,
        log::Level::Debug => slog::Level::Debug,
        log::Level::Trace => slog::Level::Trace,
    });
    let dualdrain = slog::Duplicate::new(leveldrain, logdest).fuse();
    let logger = Logger::root(dualdrain, slog_o!());

    let scope_guard = slog_scope::set_global_logger(logger);
    slog_stdlog::init().unwrap();

    if level > log::STATIC_MAX_LEVEL {
        error!("Log level {} has been statically removed during compilation. Manually enable it and recompile.", level);
        std::process::exit(-1);
    }
    scope_guard
}
