use std::{
    borrow::Borrow,
    cell::RefCell,
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    rc::Rc,
    thread,
    time::{Duration, Instant},
};

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};

use super::LOG_INTERCEPT_PROGRESSBAR;

macro_rules! pb_add {
    ($pos:ident = $pm:ident[$id:expr].add($add:expr)) => {
        $pos += $add;
        $pm.set_position($id, $pos);
        $pm.tick();
    };
}
pub(crate) use pb_add;

pub trait BarSelector: Copy + PartialEq + Eq + Hash + Send + Debug {}

/// Orchestrates progressbars
pub struct ProgressManager<S: BarSelector> {
    progress: Option<MultiProgress>,
    bars: HashMap<S, RateLimitProgressBar>,
    _thread: Option<std::thread::JoinHandle<()>>,
    //_logpbstate: Option<happylog::LogPBState>,
    updated: Instant,
    hidden: bool,
}

impl<S: BarSelector> std::fmt::Debug for ProgressManager<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgressManager")
            .field("progress", &self.progress)
            .field("bars", &self.bars)
            .field("_thread", &self._thread)
            //.field("_logpbstate", &self._logpbstate.as_ref().map(|_| ()))
            .field("updated", &self.updated)
            .finish()
    }
}

impl<S: BarSelector> Drop for ProgressManager<S> {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Debug, Clone)]
struct RateLimitProgressBar {
    bar: ProgressBar,
    position: Option<u64>,
    message: Option<String>,
    template: Option<String>,
}

impl RateLimitProgressBar {
    fn create(bar: ProgressBar, template: Option<String>) -> Self {
        Self {
            bar,
            position: None,
            message: None,
            template,
        }
    }

    fn set_position(&mut self, position: u64) {
        self.position = Some(position);
    }

    fn set_message(&mut self, msg: String) {
        self.message = Some(msg);
    }

    fn update(&mut self) {
        if let Some(position) = self.position.take() {
            self.bar.set_position(position);
        }
        if let Some(message) = self.message.take() {
            self.bar.set_message(message);
        }
    }
}

pub const RATE_MS: Duration = Duration::from_millis(500);
pub const RATE_HZ: u64 = (1000 / RATE_MS.as_millis()) as u64;

pub trait ProgressBars<S: BarSelector> {
    /// Creates a new progress manager
    fn create() -> Self;

    /// Must be called for the progress bars to be updated (Note that it is rate-limited)
    fn tick(&self);

    /// Add a new progressbar
    fn add(
        &self,
        selector: S,
        length: impl Into<Option<u64>>,
        message: impl Into<String>,
        template: impl Into<Option<&'static str>>,
    );

    /// Sets the new position (not visible until tick is called)
    fn set_position(&self, selector: S, value: u64);

    /// Set a new message (not visible until tick is called)
    fn set_message(&self, selector: S, message: String);

    fn set_length(&self, selector: S, length: u64);

    /// enables the proggressbars (resets positions)
    fn start(&self, reset: impl IntoIterator<Item = S>);

    /// Stops the progress
    fn stop(&self);
}

#[derive(Debug, Clone)]
pub struct ClonableProgressManager<S: BarSelector + Send> {
    inner: Rc<RefCell<ProgressManager<S>>>,
}

impl<S: BarSelector + 'static> ProgressBars<S> for ClonableProgressManager<S> {
    /// Creates a new progress manager
    fn create() -> Self {
        let draw_target = ProgressDrawTarget::stdout_with_hz(RATE_HZ);
        let hidden = draw_target.is_hidden();
        let progress = Some(MultiProgress::with_draw_target(draw_target));
        Self {
            inner: Rc::new(RefCell::new(ProgressManager {
                progress,
                bars: HashMap::new(),
                _thread: None,
                //_logpbstate: None,
                updated: Instant::now(),
                hidden,
            })),
        }
    }

    /// Must be called for the progress bars to be updated (Note that it is rate-limited)
    fn tick(&self) {
        let mut this = self.inner.borrow_mut();
        // we use every message as a tick to check the timer
        if this.updated.elapsed() >= RATE_MS {
            this.update_bars();
        }
    }

    /// Add a new progressbar
    fn add(
        &self,
        selector: S,
        length: impl Into<Option<u64>>,
        message: impl Into<String>,
        template: impl Into<Option<&'static str>>,
    ) {
        let mut this = self.inner.borrow_mut();
        this.add_bar(
            selector,
            length.into(),
            message.into(),
            template.into().map(|t| t.to_string()),
        )
    }

    /// Sets the new position (not visible until tick is called)
    fn set_position(&self, selector: S, value: u64) {
        self.inner
            .borrow_mut()
            .bars
            .get_mut(&selector)
            .unwrap()
            .set_position(value);
    }

    /// Set a new message (not visible until tick is called)
    fn set_message(&self, selector: S, message: String) {
        self.inner
            .borrow_mut()
            .bars
            .get_mut(&selector)
            .unwrap()
            .set_message(message);
    }

    fn set_length(&self, selector: S, length: u64) {
        self.inner
            .borrow_mut()
            .bars
            .get_mut(&selector)
            .unwrap()
            .bar
            .set_length(length);
    }

    /// enables the proggressbars (resets positions)
    fn start(&self, reset: impl IntoIterator<Item = S>) {
        let mut this = self.inner.borrow_mut();
        this.update_bars();
        reset.into_iter().for_each(|selector| {
            this.bars.get_mut(&selector).unwrap().set_position(0);
            this.bars[&selector].bar.reset();
        });
        // redirect log messages
        if let Some(bar) = this.bars.values().next() {
            if !this.hidden {
                let bar: &ProgressBar = bar.bar.borrow();
                unsafe { LOG_INTERCEPT_PROGRESSBAR.replace(bar.clone()) };
            }
        }
        // Start the drawing thread
        if this._thread.is_none() {
            if let Some(progress) = this.progress.take() {
                this._thread = Some(thread::spawn(move || progress.join().unwrap()));
            }
        }
        // Set the correct template
        this.bars.values().for_each(|rbar| {
            let mut newstyle = ProgressStyle::default_bar();
            if let Some(template) = &rbar.template {
                newstyle = newstyle.template(template);
            }
            rbar.bar.set_style(newstyle)
        });
    }

    /// Stops the progress
    fn stop(&self) {
        self.inner.borrow_mut().stop()
    }
}

impl<S: BarSelector> ProgressManager<S> {
    /// internal function to actually do to the progress update
    fn update_bars(&mut self) {
        self.updated = Instant::now();
        self.bars.values_mut().for_each(|bar| bar.update());
    }

    fn add_bar(
        &mut self,
        selector: S,
        length: Option<u64>,
        message: String,
        template: Option<String>,
    ) {
        if let Some(progress) = &self.progress {
            self.bars.insert(
                selector,
                RateLimitProgressBar::create(
                    progress.add(
                        if let Some(length) = length {
                            ProgressBar::new(length)
                        } else {
                            ProgressBar::new_spinner()
                        }
                        .with_message(message)
                        .with_style(ProgressStyle::default_bar().template("")),
                    ),
                    template,
                ),
            );
        } else {
            panic!("Cannot add more progressbars after start has already been called!");
        }
    }

    /// Stops the progress
    fn stop(&mut self) {
        self.update_bars();
        self.bars.values().for_each(|rbar| {
            rbar.bar
                .set_style(ProgressStyle::default_bar().template(""))
        });
    }
}
