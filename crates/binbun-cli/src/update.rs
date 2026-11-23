//! Whether a newer binbun is out, asked only where the user agreed (the
//! GUI's `updates.check`, `binbun update --check`).
//!
//! The answer is a small static file, [`URL`] (`latest.json`, schema 1):
//!
//! ```json
//! {"schema":1,"version":"0.2.0","date":"2026-11-13",
//!  "notes":"https://binbun.org/releases/0.2.0",
//!  "download":"https://binbun.org/download","security":false}
//! ```
//!
//! `schema` changes only for a change an older binbun would misread
//! (it then ignores the file); fields added later keep schema 1 and are
//! ignored by older builds. `security` may be left out (false). `notes`
//! and `download` are `https` URLs.
//!
//! - [`version`]: semver precedence, pre-releases before their release.
//! - [`Latest`]: the file, parsed and checked ([`Latest::parse`]).
//! - [`Request`]: one blocking fetch: a short timeout, `If-None-Match`
//!   with the last `ETag`, nothing sent but the request and a plain
//!   `User-Agent: binbun/<version>`.
//! - [`Checker`]: the GUI's background check: at launch, then hourly
//!   ([`Schedule`], time passed in), the last answer kept across a `304`
//!   and across failures, which are silent.
//! - [`offer`]: whether to tell the user: a newer version, not skipped
//!   unless it is a security release.
//! - [`Build`]: what the build allows: `BINBUN_UPDATE_CHECK=off` at build
//!   time compiles the check out; `BINBUN_PACKAGED_BY=<name>` says to
//!   update through that package manager instead of offering Download.
//!
//! [`URL_ENV`] (`BINBUN_UPDATE_URL`) replaces [`URL`], for tests against a
//! local server.
//!
//! [`command`]: `binbun update --check`, on top of these.

pub mod command;
pub mod version;

use std::fmt;
use std::time::{Duration, Instant};

use serde::Deserialize;
use ureq::Agent;

pub use version::Version;

/// Where the latest release is published.
pub const URL: &str = "https://binbun.org/latest.json";

/// The environment variable that replaces [`URL`] (tests: a local
/// server).
pub const URL_ENV: &str = "BINBUN_UPDATE_URL";

/// The schema of `latest.json` this build reads.
pub const SCHEMA: u64 = 1;

/// How long one check may take, connecting and reading together.
pub const TIMEOUT: Duration = Duration::from_secs(10);

/// How often the GUI checks again.
pub const INTERVAL: Duration = Duration::from_hours(1);

/// The most bytes of `latest.json` read.
const LIMIT: u64 = 64 * 1024;

/// What the build allows, fixed when it was compiled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Build {
    /// The running build's version.
    pub version: &'static str,
    /// Whether checking is compiled in (`BINBUN_UPDATE_CHECK` is not
    /// `off`).
    pub check: bool,
    /// The package manager this build came from (`BINBUN_PACKAGED_BY`):
    /// updates go through it.
    pub packaged_by: Option<&'static str>,
}

impl Build {
    /// This build, at `version` (the caller's `CARGO_PKG_VERSION`).
    pub fn current(version: &'static str) -> Self {
        Self {
            version,
            check: !matches!(option_env!("BINBUN_UPDATE_CHECK"), Some("off")),
            packaged_by: option_env!("BINBUN_PACKAGED_BY").filter(|name| !name.trim().is_empty()),
        }
    }

    /// The `User-Agent` sent: `binbun/<version>`, nothing more.
    pub fn user_agent(&self) -> String {
        format!("binbun/{}", self.version)
    }
}

/// The URL checked: [`URL_ENV`]'s if set, else [`URL`].
pub fn url() -> String {
    std::env::var(URL_ENV)
        .ok()
        .filter(|url| !url.trim().is_empty())
        .unwrap_or_else(|| URL.to_owned())
}

/// The latest release, as published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Latest {
    /// Its version.
    pub version: Version,
    /// Its date (`2026-11-13`).
    pub date: String,
    /// Its release notes (an `https` URL).
    pub notes: String,
    /// Where to download it (an `https` URL).
    pub download: String,
    /// Whether it fixes a security problem.
    pub security: bool,
}

/// `latest.json` as written.
#[derive(Deserialize)]
struct Raw {
    version: String,
    date: String,
    notes: String,
    download: String,
    #[serde(default)]
    security: bool,
}

/// `latest.json`'s schema alone, read first.
#[derive(Deserialize)]
struct Schema {
    schema: u64,
}

impl Latest {
    /// Parses `latest.json`.
    ///
    /// # Errors
    ///
    /// It is not JSON of [`SCHEMA`], its version is no version, or a URL
    /// is not `https`.
    pub fn parse(json: &str) -> Result<Self, Error> {
        let schema: Schema =
            serde_json::from_str(json).map_err(|error| Error::Invalid(error.to_string()))?;
        if schema.schema != SCHEMA {
            return Err(Error::Schema(schema.schema));
        }
        let raw: Raw =
            serde_json::from_str(json).map_err(|error| Error::Invalid(error.to_string()))?;
        let version = raw
            .version
            .parse()
            .map_err(|error: version::Invalid| Error::Invalid(error.to_string()))?;
        for url in [&raw.notes, &raw.download] {
            if !url.starts_with("https://")
                || url.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                return Err(Error::Invalid(format!("not an https URL: {url:?}")));
            }
        }
        Ok(Self {
            version,
            date: raw.date,
            notes: raw.notes,
            download: raw.download,
            security: raw.security,
        })
    }
}

/// Why a check brought no answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The server could not be reached or read.
    Network(String),
    /// It answered with this HTTP status.
    Status(u16),
    /// Its file is of a schema this build does not read.
    Schema(u64),
    /// Its file is not `latest.json`.
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(message) => f.write_str(message),
            Self::Status(status) => write!(f, "HTTP {status}"),
            Self::Schema(schema) => write!(f, "latest.json schema {schema} is not {SCHEMA}"),
            Self::Invalid(message) => write!(f, "latest.json: {message}"),
        }
    }
}

impl std::error::Error for Error {}

/// One check's answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// The file, and its `ETag` if the server gave one.
    Fresh {
        /// The latest release.
        latest: Latest,
        /// Its `ETag`.
        etag: Option<String>,
    },
    /// Unchanged since the `ETag` sent.
    NotModified,
}

/// One check to make: owned, so it runs on any thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The URL.
    pub url: String,
    /// The `User-Agent` ([`Build::user_agent`]).
    pub user_agent: String,
    /// The `ETag` of the answer kept (sent as `If-None-Match`).
    pub etag: Option<String>,
}

impl Request {
    /// Fetches, blocking up to [`TIMEOUT`].
    ///
    /// # Errors
    ///
    /// No answer, an HTTP status other than 200 (or 304 to an `ETag`
    /// sent), or an answer that is not `latest.json`.
    pub fn send(&self) -> Result<Response, Error> {
        self.send_within(TIMEOUT)
    }

    /// Fetches, blocking up to `timeout`.
    ///
    /// # Errors
    ///
    /// As [`Request::send`].
    pub fn send_within(&self, timeout: Duration) -> Result<Response, Error> {
        let agent: Agent = Agent::config_builder()
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .user_agent(self.user_agent.as_str())
            .build()
            .into();
        let mut request = agent.get(&self.url);
        if let Some(etag) = &self.etag {
            request = request.header("If-None-Match", etag);
        }
        let mut response = request
            .call()
            .map_err(|error| Error::Network(error.to_string()))?;
        let status = response.status().as_u16();
        if status == 304 && self.etag.is_some() {
            return Ok(Response::NotModified);
        }
        if status != 200 {
            return Err(Error::Status(status));
        }
        let etag = response
            .headers()
            .get("ETag")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response
            .body_mut()
            .with_config()
            .limit(LIMIT)
            .read_to_string()
            .map_err(|error| Error::Network(error.to_string()))?;
        Ok(Response::Fresh {
            latest: Latest::parse(&body)?,
            etag,
        })
    }
}

/// When the next check is due: at once, then [`INTERVAL`] after the last
/// one began, whatever it brought.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Schedule {
    last: Option<Instant>,
}

impl Schedule {
    /// Whether a check is due at `now`.
    pub fn due(&self, now: Instant) -> bool {
        self.last
            .is_none_or(|last| now.saturating_duration_since(last) >= INTERVAL)
    }

    /// A check began at `now`.
    pub fn ran(&mut self, now: Instant) {
        self.last = Some(now);
    }
}

/// The checks of a running GUI: what to fetch when, and the last answer.
#[derive(Clone, Debug)]
pub struct Checker {
    url: String,
    user_agent: String,
    schedule: Schedule,
    etag: Option<String>,
    latest: Option<Latest>,
}

impl Checker {
    /// Checks `url` as `build`.
    pub fn new(url: String, build: &Build) -> Self {
        Self {
            url,
            user_agent: build.user_agent(),
            schedule: Schedule::default(),
            etag: None,
            latest: None,
        }
    }

    /// The check due at `now`, if one is (it counts as begun).
    pub fn start(&mut self, now: Instant) -> Option<Request> {
        if !self.schedule.due(now) {
            return None;
        }
        self.schedule.ran(now);
        Some(Request {
            url: self.url.clone(),
            user_agent: self.user_agent.clone(),
            // Only an answer kept can be confirmed.
            etag: self.latest.as_ref().and(self.etag.clone()),
        })
    }

    /// Takes a check's `result`; whether the latest release changed. A
    /// failure keeps the last answer and is not reported.
    pub fn finish(&mut self, result: Result<Response, Error>) -> bool {
        match result {
            Ok(Response::Fresh { latest, etag }) => {
                self.etag = etag;
                let changed = self.latest.as_ref() != Some(&latest);
                self.latest = Some(latest);
                changed
            }
            Ok(Response::NotModified) | Err(_) => false,
        }
    }

    /// The latest release, as last answered.
    pub fn latest(&self) -> Option<&Latest> {
        self.latest.as_ref()
    }
}

/// A newer release to tell the user of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    /// The release.
    pub latest: Latest,
    /// The running version.
    pub current: Version,
    /// The package manager to update through, if any.
    pub packaged_by: Option<&'static str>,
}

impl Offer {
    /// Whether "Skip this version" is offered (not for a security
    /// release).
    pub fn skippable(&self) -> bool {
        !self.latest.security
    }

    /// Where to download it; none where a package manager updates.
    pub fn download(&self) -> Option<&str> {
        self.packaged_by
            .is_none()
            .then_some(self.latest.download.as_str())
    }

    /// The offer in one line: "binbun 0.2.0 is available (you have
    /// 0.1.0).", stronger for a security release, through the package
    /// manager where there is one.
    pub fn text(&self) -> String {
        let (latest, current) = (&self.latest.version, &self.current);
        match (self.latest.security, self.packaged_by) {
            (false, None) => format!("binbun {latest} is available (you have {current})."),
            (false, Some(by)) => {
                format!(
                    "binbun {latest} is available (you have {current}): update it through {by}."
                )
            }
            (true, None) => {
                format!("binbun {latest} is a security release (you have {current}): update now.")
            }
            (true, Some(by)) => format!(
                "binbun {latest} is a security release (you have {current}): update it through {by} now."
            ),
        }
    }
}

/// Whether to tell the user of `latest`: checking compiled in, newer than
/// the running build, and not a version `skipped` (or older) unless it is
/// a security release.
pub fn offer(build: &Build, latest: &Latest, skipped: Option<&Version>) -> Option<Offer> {
    if !build.check {
        return None;
    }
    let current: Version = build.version.parse().ok()?;
    if latest.version <= current {
        return None;
    }
    if !latest.security && skipped.is_some_and(|skipped| latest.version <= *skipped) {
        return None;
    }
    Some(Offer {
        latest: latest.clone(),
        current,
        packaged_by: build.packaged_by,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn latest(version: &str, security: bool) -> Latest {
        Latest {
            version: version.parse().unwrap(),
            date: "2026-11-13".to_owned(),
            notes: "https://binbun.org/releases".to_owned(),
            download: "https://binbun.org/download".to_owned(),
            security,
        }
    }

    fn build(version: &'static str) -> Build {
        Build {
            version,
            check: true,
            packaged_by: None,
        }
    }

    fn v(text: &str) -> Version {
        text.parse().unwrap()
    }

    #[test]
    fn only_a_newer_release_is_offered() {
        let at = build("0.2.0");
        assert!(offer(&at, &latest("0.2.1", false), None).is_some());
        assert_eq!(offer(&at, &latest("0.2.0", false), None), None);
        assert_eq!(offer(&at, &latest("0.1.9", false), None), None);
        // A release candidate is older than its release, newer than the
        // one before.
        assert_eq!(offer(&at, &latest("0.2.0-rc.1", false), None), None);
        assert!(offer(&build("0.2.0-rc.1"), &latest("0.2.0", false), None).is_some());
        // A build whose version cannot be read offers nothing.
        assert_eq!(offer(&build("dev"), &latest("9.0.0", false), None), None);
    }

    #[test]
    fn a_skipped_version_stays_quiet_until_a_newer_one() {
        let at = build("0.1.0");
        let skipped = v("0.2.0");
        assert_eq!(offer(&at, &latest("0.2.0", false), Some(&skipped)), None);
        // Skipping 0.2.0 skips nothing older that might come later.
        assert_eq!(
            offer(&at, &latest("0.2.0-rc.2", false), Some(&skipped)),
            None
        );
        let newer = offer(&at, &latest("0.2.1", false), Some(&skipped)).unwrap();
        assert_eq!(newer.latest.version, v("0.2.1"));
        assert!(newer.skippable());
    }

    #[test]
    fn a_security_release_ignores_skips_and_cannot_be_skipped() {
        let at = build("0.1.0");
        let skipped = v("0.2.0");
        let offered = offer(&at, &latest("0.2.0", true), Some(&skipped)).unwrap();
        assert!(!offered.skippable());
        assert_eq!(
            offered.text(),
            "binbun 0.2.0 is a security release (you have 0.1.0): update now."
        );
        // Still only when newer.
        assert_eq!(offer(&build("0.2.0"), &latest("0.2.0", true), None), None);
    }

    #[test]
    fn a_packaged_build_updates_through_its_package_manager() {
        let packaged = Build {
            packaged_by: Some("Arch Linux"),
            ..build("0.1.0")
        };
        let offered = offer(&packaged, &latest("0.2.0", false), None).unwrap();
        assert_eq!(offered.download(), None);
        assert_eq!(
            offered.text(),
            "binbun 0.2.0 is available (you have 0.1.0): update it through Arch Linux."
        );
        let direct = offer(&build("0.1.0"), &latest("0.2.0", false), None).unwrap();
        assert_eq!(direct.download(), Some("https://binbun.org/download"));
    }

    #[test]
    fn a_build_with_the_check_compiled_out_offers_nothing() {
        let off = Build {
            check: false,
            ..build("0.1.0")
        };
        assert_eq!(offer(&off, &latest("0.2.0", false), None), None);
        assert_eq!(offer(&off, &latest("9.0.0", true), None), None);
    }

    #[test]
    fn latest_json_is_parsed_and_checked() {
        let parsed = Latest::parse(
            r#"{"schema":1,"version":"0.2.0","date":"2026-11-13",
                "notes":"https://binbun.org/releases/0.2.0",
                "download":"https://binbun.org/download","later":[1,2]}"#,
        )
        .unwrap();
        assert_eq!(parsed.version, v("0.2.0"));
        // `security` left out is false; unknown fields are ignored.
        assert!(!parsed.security);
        assert_eq!(
            Latest::parse(r#"{"schema":2,"version":"9.0.0"}"#),
            Err(Error::Schema(2))
        );
        for bad in [
            "",
            "[]",
            r#"{"version":"0.2.0"}"#,
            r#"{"schema":1,"version":"0.2","date":"","notes":"https://a","download":"https://b"}"#,
            r#"{"schema":1,"version":"0.2.0","date":"","notes":"javascript:x","download":"https://b"}"#,
            r#"{"schema":1,"version":"0.2.0","date":"","notes":"https://a","download":"file:///bin/sh"}"#,
            r#"{"schema":1,"version":"0.2.0","date":"","notes":"https://a b","download":"https://b"}"#,
        ] {
            assert!(
                matches!(Latest::parse(bad), Err(Error::Invalid(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_schedule_checks_at_launch_then_hourly() {
        let launch = Instant::now();
        let mut schedule = Schedule::default();
        assert!(schedule.due(launch));
        schedule.ran(launch);
        assert!(!schedule.due(launch));
        let almost = (launch + INTERVAL).checked_sub(Duration::from_secs(1));
        assert!(!schedule.due(almost.unwrap()));
        assert!(schedule.due(launch + INTERVAL));
        // A clock seen going back (another thread's instant) is not due.
        schedule.ran(launch + INTERVAL);
        assert!(!schedule.due(launch));
    }

    #[test]
    fn the_checker_starts_one_check_per_hour_and_keeps_its_answer() {
        let launch = Instant::now();
        let mut checker =
            Checker::new("http://127.0.0.1:9/latest.json".to_owned(), &build("0.1.0"));
        let first = checker.start(launch).unwrap();
        assert_eq!(first.user_agent, "binbun/0.1.0");
        // Nothing to confirm yet: no If-None-Match.
        assert_eq!(first.etag, None);
        assert_eq!(checker.start(launch + Duration::from_mins(59)), None);
        assert!(checker.finish(Ok(Response::Fresh {
            latest: latest("0.2.0", false),
            etag: Some("\"a\"".to_owned()),
        })));
        let second = checker.start(launch + INTERVAL).unwrap();
        assert_eq!(second.etag.as_deref(), Some("\"a\""));
        // Unchanged, then failing: the answer stays, nothing reported.
        assert!(!checker.finish(Ok(Response::NotModified)));
        assert!(!checker.finish(Err(Error::Status(500))));
        assert_eq!(checker.latest(), Some(&latest("0.2.0", false)));
        // The same file again is no change; a new one is.
        assert!(!checker.finish(Ok(Response::Fresh {
            latest: latest("0.2.0", false),
            etag: None,
        })));
        assert!(checker.finish(Ok(Response::Fresh {
            latest: latest("0.3.0", true),
            etag: None,
        })));
        // No ETag given: none sent.
        assert_eq!(checker.start(launch + INTERVAL * 2).unwrap().etag, None);
    }
}
