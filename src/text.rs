//! Server and repository text printed to a terminal. Findings quote model
//! output and repository content, which is untrusted, so control characters
//! that could move the cursor or rewrite earlier lines never reach the terminal.

/// Returns whether a character is a Unicode bidirectional formatting control.
fn is_bidi_control(character: char) -> bool {
    matches!(
        character as u32,
        0x061C
            | 0x200E..=0x200F
            | 0x202A..=0x202E
            | 0x2066..=0x2069
    )
}

/// Replaces every control character except a newline and a tab.
pub fn terminal_safe(text: &str) -> String {
    text.chars()
        .map(|character| {
            if (character.is_control() || is_bidi_control(character))
                && character != '\n'
                && character != '\t'
            {
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

    #[test]
    fn bidirectional_override_is_replaced() {
        assert_eq!(terminal_safe("file\u{202E}gpj.exe"), "file\u{FFFD}gpj.exe");
    }

    #[test]
    fn bidirectional_isolates_are_replaced() {
        assert_eq!(
            terminal_safe("text\u{2066}hidden\u{2069}"),
            "text\u{FFFD}hidden\u{FFFD}"
        );
    }

    #[test]
    fn bidirectional_controls_are_removed_from_single_line_output() {
        assert_eq!(one_line("report\u{202E}txt"), "report\u{FFFD}txt");
    }

    #[test]
    fn ordinary_unicode_is_preserved() {
        assert_eq!(terminal_safe("Café — résumé"), "Café — résumé");
    }
}
