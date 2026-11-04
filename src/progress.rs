use clap::ValueEnum;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle, TermLike};
use serde_json::json;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, IsTerminal, Write};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ProgressMode {
    Auto,
    Always,
    Never,
    Plain,
    Json,
}

pub trait ProgressReporter {
    fn phase(&self, label: &'static str);
    fn step_start(&self, label: &'static str);
    fn step_finish(&self, label: &'static str);
    fn counted(&self, label: &'static str, completed: u64, total: u64);
    fn warning(&self, message: &'static str);
}

pub struct NoopProgress;

impl ProgressReporter for NoopProgress {
    fn phase(&self, _label: &'static str) {}
    fn step_start(&self, _label: &'static str) {}
    fn step_finish(&self, _label: &'static str) {}
    fn counted(&self, _label: &'static str, _completed: u64, _total: u64) {}
    fn warning(&self, _message: &'static str) {}
}

pub fn reporter_for_mode(mode: ProgressMode) -> Box<dyn ProgressReporter> {
    match mode {
        ProgressMode::Never => Box::new(NoopProgress),
        ProgressMode::Plain => Box::new(PlainProgress::new()),
        ProgressMode::Json => Box::new(JsonProgress::new()),
        ProgressMode::Always => Box::new(TtyProgress::forced()),
        ProgressMode::Auto if std::io::stderr().is_terminal() => Box::new(TtyProgress::new()),
        ProgressMode::Auto => Box::new(PlainProgress::new()),
    }
}

struct PlainProgress {
    started_at: Instant,
    counted_started_at: Mutex<BTreeMap<&'static str, Instant>>,
}

impl PlainProgress {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            counted_started_at: Mutex::new(BTreeMap::new()),
        }
    }

    fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    fn counted_elapsed(&self, label: &'static str) -> Duration {
        let mut started = self
            .counted_started_at
            .lock()
            .expect("progress mutex poisoned");
        let started_at = started.entry(label).or_insert_with(Instant::now);
        started_at.elapsed()
    }
}

impl ProgressReporter for PlainProgress {
    fn phase(&self, label: &'static str) {
        eprintln!("progress phase: {label}");
    }

    fn step_start(&self, label: &'static str) {
        eprintln!("progress step: {label} started");
    }

    fn step_finish(&self, label: &'static str) {
        eprintln!(
            "progress step: {label} done elapsed={}",
            format_duration(self.elapsed())
        );
    }

    fn counted(&self, label: &'static str, completed: u64, total: u64) {
        let elapsed = self.counted_elapsed(label);
        eprintln!(
            "progress count: {label} {completed}/{total} elapsed={} eta={}",
            format_duration(elapsed),
            format_duration(eta(elapsed, completed, total))
        );
    }

    fn warning(&self, message: &'static str) {
        eprintln!("progress warning: {message}");
    }
}

struct JsonProgress {
    started_at: Instant,
    counted_started_at: Mutex<BTreeMap<&'static str, Instant>>,
}

impl JsonProgress {
    fn new() -> Self {
        Self {
            started_at: Instant::now(),
            counted_started_at: Mutex::new(BTreeMap::new()),
        }
    }

    fn elapsed_ms(&self) -> u128 {
        self.started_at.elapsed().as_millis()
    }

    fn counted_elapsed(&self, label: &'static str) -> Duration {
        let mut started = self
            .counted_started_at
            .lock()
            .expect("progress mutex poisoned");
        let started_at = started.entry(label).or_insert_with(Instant::now);
        started_at.elapsed()
    }
}

impl ProgressReporter for JsonProgress {
    fn phase(&self, label: &'static str) {
        eprintln!(
            "{}",
            json!({"kind":"phase","label":label,"elapsed_ms":self.elapsed_ms()})
        );
    }

    fn step_start(&self, label: &'static str) {
        eprintln!(
            "{}",
            json!({"kind":"step_start","label":label,"elapsed_ms":self.elapsed_ms()})
        );
    }

    fn step_finish(&self, label: &'static str) {
        eprintln!(
            "{}",
            json!({"kind":"step_finish","label":label,"elapsed_ms":self.elapsed_ms()})
        );
    }

    fn counted(&self, label: &'static str, completed: u64, total: u64) {
        let elapsed = self.counted_elapsed(label);
        eprintln!(
            "{}",
            json!({
                "kind":"count",
                "label":label,
                "completed":completed,
                "total":total,
                "elapsed_ms":elapsed.as_millis(),
                "eta_ms":eta(elapsed, completed, total).as_millis(),
            })
        );
    }

    fn warning(&self, message: &'static str) {
        eprintln!(
            "{}",
            json!({"kind":"warning","message":message,"elapsed_ms":self.elapsed_ms()})
        );
    }
}

struct TtyProgress {
    active_step: Mutex<Option<ProgressBar>>,
    counted_bars: Mutex<BTreeMap<&'static str, ProgressBar>>,
    force_draw: bool,
}

impl TtyProgress {
    fn new() -> Self {
        Self {
            active_step: Mutex::new(None),
            counted_bars: Mutex::new(BTreeMap::new()),
            force_draw: false,
        }
    }

    fn forced() -> Self {
        Self {
            active_step: Mutex::new(None),
            counted_bars: Mutex::new(BTreeMap::new()),
            force_draw: true,
        }
    }

    fn finish_active_step(&self) {
        if let Some(bar) = self
            .active_step
            .lock()
            .expect("progress mutex poisoned")
            .take()
        {
            bar.finish_and_clear();
        }
    }

    fn spinner(&self) -> ProgressBar {
        if self.force_draw {
            let bar = ProgressBar::with_draw_target(None, forced_stderr_target());
            bar.set_style(ProgressStyle::default_spinner());
            bar
        } else {
            ProgressBar::new_spinner()
        }
    }

    fn bar(&self, total: u64) -> ProgressBar {
        if self.force_draw {
            ProgressBar::with_draw_target(Some(total), forced_stderr_target())
        } else {
            ProgressBar::new(total)
        }
    }
}

impl ProgressReporter for TtyProgress {
    fn phase(&self, label: &'static str) {
        self.finish_active_step();
        eprintln!("progress: {label}");
    }

    fn step_start(&self, label: &'static str) {
        self.finish_active_step();
        let bar = self.spinner();
        bar.set_style(spinner_style());
        bar.set_message(label);
        bar.enable_steady_tick(Duration::from_millis(100));
        *self.active_step.lock().expect("progress mutex poisoned") = Some(bar);
    }

    fn step_finish(&self, label: &'static str) {
        if let Some(bar) = self
            .active_step
            .lock()
            .expect("progress mutex poisoned")
            .take()
        {
            bar.finish_with_message(format!("{label} done"));
        }
    }

    fn counted(&self, label: &'static str, completed: u64, total: u64) {
        let mut bars = self.counted_bars.lock().expect("progress mutex poisoned");
        let bar = bars.entry(label).or_insert_with(|| {
            let bar = self.bar(total);
            bar.set_style(bar_style());
            bar.set_message(label);
            bar
        });
        bar.set_length(total);
        bar.set_position(completed);
        if completed >= total {
            bar.finish_with_message(format!("{label} done"));
        }
    }

    fn warning(&self, message: &'static str) {
        self.finish_active_step();
        eprintln!("progress warning: {message}");
    }
}

fn spinner_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.green} {msg} [{elapsed_precise}]")
        .expect("valid spinner template")
}

fn bar_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "{bar:40.cyan/blue} {pos}/{len} {msg} [{elapsed_precise}, eta {eta_precise}]",
    )
    .expect("valid progress bar template")
}

fn forced_stderr_target() -> ProgressDrawTarget {
    ProgressDrawTarget::term_like_with_hz(Box::new(ForcedStderrTerm), 20)
}

struct ForcedStderrTerm;

impl fmt::Debug for ForcedStderrTerm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ForcedStderrTerm")
    }
}

impl TermLike for ForcedStderrTerm {
    fn width(&self) -> u16 {
        80
    }

    fn move_cursor_up(&self, n: usize) -> io::Result<()> {
        write_ansi_move('A', n)
    }

    fn move_cursor_down(&self, n: usize) -> io::Result<()> {
        write_ansi_move('B', n)
    }

    fn move_cursor_right(&self, n: usize) -> io::Result<()> {
        write_ansi_move('C', n)
    }

    fn move_cursor_left(&self, n: usize) -> io::Result<()> {
        write_ansi_move('D', n)
    }

    fn write_line(&self, s: &str) -> io::Result<()> {
        let mut stderr = io::stderr().lock();
        stderr.write_all(s.as_bytes())?;
        stderr.write_all(b"\n")
    }

    fn write_str(&self, s: &str) -> io::Result<()> {
        io::stderr().lock().write_all(s.as_bytes())
    }

    fn clear_line(&self) -> io::Result<()> {
        io::stderr().lock().write_all(b"\r\x1b[2K")
    }

    fn flush(&self) -> io::Result<()> {
        io::stderr().lock().flush()
    }
}

fn write_ansi_move(direction: char, n: usize) -> io::Result<()> {
    if n == 0 {
        return Ok(());
    }
    write!(io::stderr().lock(), "\x1b[{n}{direction}")
}

fn eta(elapsed: Duration, completed: u64, total: u64) -> Duration {
    if completed == 0 || completed >= total {
        return Duration::ZERO;
    }
    elapsed
        .checked_div(completed as u32)
        .and_then(|per_item| per_item.checked_mul((total - completed) as u32))
        .unwrap_or(Duration::ZERO)
}

fn format_duration(duration: Duration) -> String {
    format!("{}s", duration.as_secs())
}
