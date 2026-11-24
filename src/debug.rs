use std::ffi::OsStr;
use std::fmt::Arguments;
use std::io::Write as _;
use std::sync::LazyLock;

use crate::text::one_line;

static ENABLED: LazyLock<bool> =
    LazyLock::new(|| switched_on(std::env::var_os("PROOFLINE_DEBUG").as_deref()));

fn switched_on(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| !value.is_empty() && value != "0")
}

pub(crate) fn log(line: Arguments<'_>) {
    if !*ENABLED {
        return;
    }
    let _ = writeln!(
        std::io::stderr().lock(),
        "proofline debug: {}",
        one_line(&line.to_string())
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_value_other_than_empty_or_zero_switches_it_on() {
        assert!(!switched_on(None));
        assert!(!switched_on(Some(OsStr::new(""))));
        assert!(!switched_on(Some(OsStr::new("0"))));
        assert!(switched_on(Some(OsStr::new("1"))));
        assert!(switched_on(Some(OsStr::new("true"))));
    }
}
