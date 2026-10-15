//! Server and repository text printed to a terminal. Findings quote model
//! output and repository content, which is untrusted, so control characters
//! that could move the cursor or rewrite earlier lines never reach the terminal.

/// Replaces every control character except a newline and a tab.
pub fn terminal_safe(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() && character != '\n' && character != '\t' {
                '\u{FFFD}'
            } else {
                character
            }
        })
        .collect()
}

/// As [`terminal_safe`], on one line.
pub fn one_line(text: &str) -> String {
    terminal_safe(text).replace(['\n', '\t'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_sequences_never_reach_the_terminal() {
        assert_eq!(
            terminal_safe("ok\u{1b}[2Jgone\r"),
            "ok\u{FFFD}[2Jgone\u{FFFD}"
        );
        assert_eq!(terminal_safe("a\u{9b}31m"), "a\u{FFFD}31m");
        assert_eq!(terminal_safe("line\n\tindent"), "line\n\tindent");
        assert_eq!(one_line("a\nb\tc"), "a b c");
    }
}
