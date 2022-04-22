use anyhow::Result;
use std::{
    convert::TryInto,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    sync::{Arc, Mutex},
};

use linya::{Bar, Progress};

pub struct ProgressRead<R: Read> {
    inner: R,
    progress: Arc<Mutex<Progress>>,
    bar: Bar,
}

impl<R: Read> ProgressRead<R> {
    pub fn from_length<S: Into<String>>(
        inner: R,
        label: S,
        length: usize,
        progress: Arc<Mutex<Progress>>,
    ) -> ProgressRead<R> {
        let bar = progress.lock().unwrap().bar(length, label);
        ProgressRead {
            inner,
            progress,
            bar,
        }
    }

    pub fn from_seekable<S>(
        mut inner: R,
        label: S,
        progress: Arc<Mutex<Progress>>,
    ) -> Result<ProgressRead<R>>
    where
        R: Read + Seek,
        S: Into<String>,
    {
        let length = inner.seek(SeekFrom::End(0))?.try_into()?;
        inner.seek(SeekFrom::Start(0))?;
        Ok(ProgressRead::from_length(inner, label, length, progress))
    }
}
impl ProgressRead<File> {
    pub fn from_path(path: &Path, progress: Arc<Mutex<Progress>>) -> Result<ProgressRead<File>> {
        ProgressRead::from_seekable(File::open(path)?, format!("{:?}", path), progress)
    }
}

impl<R: Read> Read for ProgressRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.inner.read(buf) {
            Ok(bytes) => {
                self.progress.lock().unwrap().inc_and_draw(&self.bar, bytes);
                Ok(bytes)
            }
            Err(err) => Err(err),
        }
    }
}
