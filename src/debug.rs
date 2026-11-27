use std::fmt::Arguments;
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::text::one_line;

static ENABLED: AtomicBool = AtomicBool::new(false);

pub(crate) fn enable() {
    ENABLED.store(true, Ordering::Relaxed);
}

pub(crate) fn log(line: Arguments<'_>) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let _ = writeln!(
        std::io::stderr().lock(),
        "proofline debug: {}",
        one_line(&line.to_string())
    );
}
