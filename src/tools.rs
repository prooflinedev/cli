//! Native operations on the existing token API.
use std::collections::HashSet;
use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use clap::{Args, Subcommand, ValueEnum};
use uuid::Uuid;

use crate::{OutputArgs, OutputFormat, RepositoryArgs, Verdict, api::Api, say, show};

#[derive(Debug, Args)]
pub(crate) struct RerunArgs {
    review_id: Uuid,
    /// Return the new review acknowledgment without polling.
    #[arg(long)]
    no_wait: bool,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Debug, Args)]
pub(crate) struct HistoryArgs {
    #[arg(long)]
    pub pr: u64,
    #[command(flatten)]
    pub repository: RepositoryArgs,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Dataset {
    Reviews,
    #[value(name = "finding_outcomes")]
    FindingOutcomes,
    #[value(name = "finding_validations")]
    FindingValidations,
    Spend,
    Findings,
}

impl Dataset {
    const fn name(self) -> &'static str {
        match self {
            Self::Reviews => "reviews",
            Self::FindingOutcomes => "finding_outcomes",
            Self::FindingValidations => "finding_validations",
            Self::Spend => "spend",
            Self::Findings => "findings",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Format {
    Csv,
    Ndjson,
}

#[derive(Debug, Args)]
pub(crate) struct ExportArgs {
    #[arg(value_enum)]
    dataset: Dataset,
    /// Inclusive RFC3339 start of a window of at most 31 days.
    #[arg(long)]
    from: String,
    /// Exclusive RFC3339 end of the window.
    #[arg(long)]
    to: String,
    #[arg(long, value_enum, default_value = "ndjson")]
    format: Format,
    /// Opaque continuation from the preceding page; keep the same filters.
    #[arg(long)]
    cursor: Option<String>,
    /// Grouping for `finding_outcomes` only.
    #[arg(long)]
    group_by: Option<String>,
    /// Follow every page of every window of at most 31 days into --output;
    /// --from and --to may then span any length.
    #[arg(long, requires = "output", conflicts_with = "cursor")]
    all: bool,
    /// File that --all replaces only after every page succeeded.
    #[arg(long, requires = "all")]
    output: Option<PathBuf>,
}

pub(crate) fn json(value: &serde_json::Value) -> anyhow::Result<Verdict> {
    writeln!(
        std::io::stdout().lock(),
        "{}",
        serde_json::to_string_pretty(value)?
    )?;
    Ok(Verdict::Done)
}

pub(crate) async fn rerun(api: &Api, args: &RerunArgs) -> anyhow::Result<Verdict> {
    let reply = api.rerun(args.review_id).await?;
    let id: Uuid = reply
        .get("review_id")
        .and_then(serde_json::Value::as_str)
        .context("the rerun response has no review_id")?
        .parse()?;
    if args.no_wait {
        if args.output.json {
            return json(&reply);
        }
        writeln!(std::io::stdout().lock(), "{}", api.review_url(id))?;
        return Ok(Verdict::Done);
    }
    show(
        api,
        id,
        true,
        &args.output,
        OutputFormat::from_json(args.output.json),
    )
    .await
}

pub(crate) async fn export(api: &Api, args: &ExportArgs) -> anyhow::Result<Verdict> {
    if args.group_by.is_some() && !matches!(args.dataset, Dataset::FindingOutcomes) {
        bail!("--group-by is available only for finding_outcomes");
    }
    // clap accepts --output only together with --all.
    if let Some(output) = &args.output {
        return export_all(api, args, output).await;
    }
    let page = export_page(api, args, &args.from, &args.to, args.cursor.as_deref()).await?;
    let stdout = std::io::stdout();
    if stdout.is_terminal() {
        write!(stdout.lock(), "{}", crate::text::terminal_safe(&page.body))?;
    } else {
        stdout.lock().write_all(page.body.as_bytes())?;
    }
    say(&format!(
        "settled-until: {}",
        crate::text::terminal_safe(&page.horizon)
    ));
    if let Some(cursor) = &page.next_cursor {
        say(&format!(
            "next-cursor: {}",
            crate::text::terminal_safe(cursor)
        ));
    }
    Ok(Verdict::Done)
}

/// Every page of a whole export, so a reader cannot mistake partial output
/// for the complete range.
const MAX_EXPORT_PAGES: usize = 1000;

/// The longest window one export request accepts.
const MAX_WINDOW_SECONDS: i64 = 31 * 86_400;

/// One validated export page.
struct ExportPage {
    body: String,
    horizon: String,
    next_cursor: Option<String>,
}

const fn export_media(format: Format) -> (&'static str, &'static str) {
    match format {
        Format::Csv => ("csv", "text/csv"),
        Format::Ndjson => ("ndjson", "application/x-ndjson"),
    }
}

async fn export_page(
    api: &Api,
    args: &ExportArgs,
    from: &str,
    to: &str,
    cursor: Option<&str>,
) -> anyhow::Result<ExportPage> {
    let (format, accept) = export_media(args.format);
    let mut query = vec![
        ("from", from.to_owned()),
        ("to", to.to_owned()),
        ("format", format.to_owned()),
    ];
    if let Some(cursor) = cursor {
        query.push(("cursor", cursor.to_owned()));
    }
    if let Some(group) = &args.group_by {
        query.push(("group_by", group.clone()));
    }
    let reply = api.export(args.dataset.name(), &query, accept).await?;
    let content_type = reply
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if content_type.split(';').next().map(str::trim) != Some(accept)
        || reply
            .headers
            .get("x-proofline-export-version")
            .and_then(|v| v.to_str().ok())
            != Some("1")
    {
        bail!("the server returned an unsupported export format or version");
    }
    let horizon = reply
        .headers
        .get("x-proofline-export-settled-until")
        .context("the export has no settled horizon")?
        .to_str()?
        .to_owned();
    let next_cursor = reply
        .headers
        .get("x-proofline-export-next-cursor")
        .map(|cursor| cursor.to_str().map(str::to_owned))
        .transpose()?;
    let body = String::from_utf8(reply.body).context("the export is not UTF-8")?;
    Ok(ExportPage {
        body,
        horizon,
        next_cursor,
    })
}

async fn export_all(api: &Api, args: &ExportArgs, output: &Path) -> anyhow::Result<Verdict> {
    let windows = export_windows(&args.from, &args.to)?;
    let directory = match output.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let temporary = tempfile::Builder::new()
        .prefix(".proofline-export-")
        .tempfile_in(directory)
        .with_context(|| format!("could not create a file next to {}", output.display()))?;
    let mut file = ExportFile::new(args.format, temporary);
    let mut pages = 0;
    let mut earliest: Option<(Instant, String)> = None;
    for (from, to) in &windows {
        let mut cursor: Option<String> = None;
        let mut cursors = HashSet::new();
        let mut window_horizon: Option<String> = None;
        loop {
            pages += 1;
            if pages > MAX_EXPORT_PAGES {
                bail!(
                    "the export exceeded {MAX_EXPORT_PAGES} pages; split --from and --to into smaller ranges"
                );
            }
            let page = export_page(api, args, from, to, cursor.as_deref()).await?;
            match &window_horizon {
                None => window_horizon = Some(page.horizon.clone()),
                Some(horizon) if *horizon != page.horizon => bail!(
                    "the settled horizon changed within the window {from} to {to}, so its pages describe different snapshots"
                ),
                Some(_) => {}
            }
            file.append(&page.body)?;
            match page.next_cursor {
                None => break,
                Some(next) if next.is_empty() || !cursors.insert(next.clone()) => {
                    bail!("the server returned an empty or repeated export cursor")
                }
                Some(next) => cursor = Some(next),
            }
        }
        let horizon = window_horizon.context("the export window returned no page")?;
        let instant =
            parse_rfc3339(&horizon).context("the export has an invalid settled horizon")?;
        if earliest.as_ref().is_none_or(|(first, _)| instant < *first) {
            earliest = Some((instant, horizon));
        }
    }
    file.persist(output)?;
    if let Some((_, horizon)) = earliest {
        say(&format!(
            "settled-until: {}",
            crate::text::terminal_safe(&horizon)
        ));
    }
    Ok(Verdict::Done)
}

/// The export as it is written: a temporary file beside the destination that
/// replaces it only once complete, so a failure leaves the destination as it was.
struct ExportFile {
    format: Format,
    temporary: tempfile::NamedTempFile,
    csv_header: Option<String>,
}

impl ExportFile {
    const fn new(format: Format, temporary: tempfile::NamedTempFile) -> Self {
        Self {
            format,
            temporary,
            csv_header: None,
        }
    }

    fn append(&mut self, page: &str) -> anyhow::Result<()> {
        let records = match self.format {
            Format::Ndjson => page,
            Format::Csv => {
                let (header, records) = page.split_once('\n').unwrap_or((page, ""));
                let header = header.strip_suffix('\r').unwrap_or(header);
                if header.is_empty() {
                    bail!("an export page has no CSV header");
                }
                match &self.csv_header {
                    None => {
                        self.csv_header = Some(header.to_owned());
                        page
                    }
                    Some(first) if first == header => records,
                    Some(_) => bail!("an export page has a different CSV header"),
                }
            }
        };
        if records.is_empty() {
            return Ok(());
        }
        let file = self.temporary.as_file_mut();
        file.write_all(records.as_bytes())?;
        if !records.ends_with('\n') {
            // A page without a final newline would join its last record to the next page's first.
            let newline = match self.format {
                Format::Csv => "\r\n",
                Format::Ndjson => "\n",
            };
            file.write_all(newline.as_bytes())?;
        }
        Ok(())
    }

    fn persist(self, output: &Path) -> anyhow::Result<()> {
        self.temporary.as_file().sync_all()?;
        self.temporary
            .persist(output)
            .map_err(|error| error.error)
            .with_context(|| format!("could not write {}", output.display()))?;
        Ok(())
    }
}

/// Splits `[from, to)` into adjacent windows the server accepts. Each window's
/// exclusive end is the next window's inclusive start, so no record is read
/// twice or skipped. A range that already fits is sent exactly as typed.
fn export_windows(from: &str, to: &str) -> anyhow::Result<Vec<(String, String)>> {
    let start = parse_rfc3339(from).context("--from is not an RFC3339 timestamp")?;
    let end = parse_rfc3339(to).context("--to is not an RFC3339 timestamp")?;
    if end <= start {
        bail!("--to must be later than --from");
    }
    let mut windows = Vec::new();
    let mut window_from = from.to_owned();
    let mut window_start = start;
    loop {
        let window_end = window_start.plus_seconds(MAX_WINDOW_SECONDS);
        if window_end >= end {
            windows.push((window_from, to.to_owned()));
            return Ok(windows);
        }
        let boundary = window_end.to_rfc3339();
        windows.push((window_from, boundary.clone()));
        window_from = boundary;
        window_start = window_end;
    }
}

/// A UTC instant. Field order makes the derived ordering chronological.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Instant {
    seconds: i64,
    nanoseconds: u32,
}

impl Instant {
    const fn plus_seconds(self, seconds: i64) -> Self {
        Self {
            seconds: self.seconds + seconds,
            nanoseconds: self.nanoseconds,
        }
    }

    fn to_rfc3339(self) -> String {
        let days = self.seconds.div_euclid(86_400);
        let second_of_day = self.seconds.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        let mut text = format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
            second_of_day / 3600,
            second_of_day % 3600 / 60,
            second_of_day % 60
        );
        if self.nanoseconds != 0 {
            let fraction = format!("{:09}", self.nanoseconds);
            text.push('.');
            text.push_str(fraction.trim_end_matches('0'));
        }
        text.push('Z');
        text
    }
}

/// Parses `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)`. Leap seconds and
/// fractions finer than a nanosecond are refused rather than rounded.
fn parse_rfc3339(text: &str) -> Option<Instant> {
    let bytes = text.as_bytes();
    let year = digits(bytes, 0, 4)?;
    let month = digits(bytes, 5, 2)?;
    let day = digits(bytes, 8, 2)?;
    let hour = digits(bytes, 11, 2)?;
    let minute = digits(bytes, 14, 2)?;
    let second = digits(bytes, 17, 2)?;
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || !matches!(bytes.get(10), Some(b'T' | b't'))
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let mut position = 19;
    let mut nanoseconds = 0;
    if bytes.get(position) == Some(&b'.') {
        position += 1;
        let first = position;
        while bytes.get(position).is_some_and(u8::is_ascii_digit) {
            position += 1;
        }
        let count = position - first;
        if count == 0 || count > 9 {
            return None;
        }
        let fraction = u32::try_from(digits(bytes, first, count)?).ok()?;
        nanoseconds = fraction * 10_u32.pow(u32::try_from(9 - count).ok()?);
    }
    let offset = match bytes.get(position..)? {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let hours = digits(bytes, position + 1, 2)?;
            let minutes = digits(bytes, position + 4, 2)?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let magnitude = hours * 3600 + minutes * 60;
            if *sign == b'-' { -magnitude } else { magnitude }
        }
        _ => return None,
    };
    let seconds =
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset;
    Some(Instant {
        seconds,
        nanoseconds,
    })
}

/// The decimal value of `count` ASCII digits starting at `start`.
fn digits(bytes: &[u8], start: usize, count: usize) -> Option<i64> {
    bytes
        .get(start..start + count)?
        .iter()
        .try_fold(0, |value, byte| {
            byte.is_ascii_digit()
                .then(|| value * 10 + i64::from(byte - b'0'))
        })
}

const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
const fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The proleptic Gregorian date of days since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`).
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[derive(Debug, Args)]
pub(crate) struct ListArgs {
    #[arg(long)]
    pub repository_id: Option<Uuid>,
    #[arg(long)]
    pub search: Option<String>,
    #[arg(long)]
    pub cursor: Option<String>,
}

#[derive(Debug, Args)]
pub(crate) struct RunArgs {
    #[arg(long)]
    pub pr: u64,
    #[arg(long)]
    pub run: u64,
    #[command(flatten)]
    pub repository: RepositoryArgs,
}

#[derive(Debug, Subcommand)]
pub(crate) enum SessionCommand {
    /// Read the protected prompt and eligible vendor connections before starting.
    Prompt { finding_id: Uuid },
    /// Start once with the digest of the prompt you reviewed. Vendor charges apply.
    Start {
        finding_id: Uuid,
        #[arg(long)]
        connection_id: Uuid,
        #[arg(long)]
        prompt_digest: String,
    },
    /// Read the recorded vendor session status.
    Get { session_id: Uuid },
}

pub(crate) async fn session(api: &Api, command: SessionCommand) -> anyhow::Result<Verdict> {
    let value = match command {
        SessionCommand::Prompt { finding_id } => api.tool_get(&["findings", &finding_id.to_string(), "agent-session-prompt"]).await?,
        SessionCommand::Get { session_id } => api.tool_get(&["agent-sessions", &session_id.to_string()]).await?,
        SessionCommand::Start { finding_id, connection_id, prompt_digest } => api.tool_post(
            &["findings", &finding_id.to_string(), "agent-sessions"],
            &serde_json::json!({"connection_id": connection_id, "prompt_digest": prompt_digest}),
        ).await?,
    };
    json(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(from: &str, to: &str) -> (String, String) {
        (from.to_owned(), to.to_owned())
    }

    #[test]
    fn windows_share_each_exclusive_end_as_the_next_start() {
        let windows = export_windows("2026-08-01T00:00:00Z", "2026-10-10T00:00:00Z").unwrap();
        assert_eq!(
            windows,
            [
                pair("2026-08-01T00:00:00Z", "2026-09-01T00:00:00Z"),
                pair("2026-09-01T00:00:00Z", "2026-10-02T00:00:00Z"),
                pair("2026-10-02T00:00:00Z", "2026-10-10T00:00:00Z"),
            ]
        );
        // Offsets and fractions are kept at the edges and carried into UTC boundaries.
        let windows =
            export_windows("2024-02-01T01:30:00.25+02:00", "2024-03-10T00:00:00Z").unwrap();
        assert_eq!(
            windows,
            [
                pair("2024-02-01T01:30:00.25+02:00", "2024-03-02T23:30:00.25Z"),
                pair("2024-03-02T23:30:00.25Z", "2024-03-10T00:00:00Z"),
            ]
        );
        for window in windows.windows(2) {
            assert_eq!(
                parse_rfc3339(&window[0].1).unwrap(),
                parse_rfc3339(&window[1].0).unwrap()
            );
        }
    }

    #[test]
    fn a_fitting_span_is_sent_as_typed() {
        for (from, to) in [
            ("2026-10-01T02:00:00+02:00", "2026-10-25T00:00:00z"),
            ("2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z"),
            ("2026-10-01t00:00:00.000Z", "2026-10-01T00:00:00.000000001Z"),
        ] {
            assert_eq!(export_windows(from, to).unwrap(), [pair(from, to)]);
        }
    }

    #[test]
    fn malformed_or_empty_ranges_are_refused() {
        for (from, to) in [
            ("2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z"),
            ("2026-10-02T00:00:00Z", "2026-10-01T00:00:00Z"),
            ("2026-10-01T02:00:00+02:00", "2026-10-01T00:00:00Z"),
            ("2026-10-01", "2026-10-25T00:00:00Z"),
            ("2026-10-01T00:00:00", "2026-10-25T00:00:00Z"),
            ("2026-02-29T00:00:00Z", "2026-10-25T00:00:00Z"),
            ("2026-06-30T23:59:60Z", "2026-10-25T00:00:00Z"),
            ("2026-10-01T00:00:00.1234567891Z", "2026-10-25T00:00:00Z"),
            ("2026-10-01T00:00:00.Z", "2026-10-25T00:00:00Z"),
            ("2026-10-01T00:00:00+2:00", "2026-10-25T00:00:00Z"),
            ("2026-10-01T00:00:00Z ", "2026-10-25T00:00:00Z"),
            ("2026-10-01T00:00:00Z", "２026-10-25T00:00:00Z"),
            ("", ""),
        ] {
            assert!(export_windows(from, to).is_err(), "{from} {to}");
        }
    }

    #[test]
    fn civil_dates_round_trip() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        for days in [-719_468, -1, 0, 11_016, 11_017, 20_000, 2_932_896] {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), days);
        }
        assert_eq!(
            parse_rfc3339("2024-02-29T12:00:00Z").unwrap().to_rfc3339(),
            "2024-02-29T12:00:00Z"
        );
    }
}
