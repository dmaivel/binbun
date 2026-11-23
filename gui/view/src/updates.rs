//! Update checks in the GUI ([`binbun_cli::update`]), only once the user
//! agreed: the first launch asks with a banner ([`question`]: Yes sets
//! `updates.check` to always, No to never), then binbun.org's
//! `latest.json` is fetched at launch and hourly, off the UI thread, and a
//! newer release shows a banner ([`banner`]: Release notes, Download,
//! Skip this version, close). A skipped version stays quiet until a newer
//! one (kept in [`binbun_paths::Place::SkippedUpdate`]); a security release cannot be
//! skipped, only closed for the session. A build with
//! `BINBUN_UPDATE_CHECK=off` never asks nor checks, whatever the setting;
//! one with `BINBUN_PACKAGED_BY=<name>` says to update through `<name>`
//! instead of offering Download. `BINBUN_UPDATE_URL` replaces the URL
//! (tests: a local server).

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use binbun_cli::update::{Build, Checker, Error, Offer, Request, Response, Version, offer};

use crate::banners::{Action, Banner, Button, Kind, Priority, Tone};
use crate::settings::UpdateCheck;

/// This build: the GUI's version, the check compiled in or out, its
/// package manager.
pub fn build() -> Build {
    Build::current(env!("CARGO_PKG_VERSION"))
}

/// Whether the first launch's question shows: the check compiled in and
/// `updates.check` still ask.
pub fn asks(build: &Build, setting: UpdateCheck) -> bool {
    build.check && setting == UpdateCheck::Ask
}

/// Whether binbun.org is checked: the check compiled in and agreed to.
pub fn checks(build: &Build, setting: UpdateCheck) -> bool {
    build.check && setting == UpdateCheck::Always
}

/// The first launch's question; closed, it asks again at the next launch.
pub fn question() -> Banner {
    Banner {
        kind: Kind::UpdateQuestion,
        priority: Priority::Question,
        about: String::new(),
        text: "Check for binbun updates automatically?".to_owned(),
        tone: Tone::Info,
        buttons: vec![
            Button {
                label: "Yes".to_owned(),
                action: Action::CheckUpdates(true),
            },
            Button {
                label: "No".to_owned(),
                action: Action::CheckUpdates(false),
            },
        ],
        closable: true,
    }
}

/// The banner of `offer`: a security release first in the stack, in
/// stronger words, with no Skip; Download only where no package manager
/// updates.
pub fn banner(offer: &Offer) -> Banner {
    let mut buttons = vec![Button {
        label: "Release notes".to_owned(),
        action: Action::Open(offer.latest.notes.clone()),
    }];
    if let Some(download) = offer.download() {
        buttons.push(Button {
            label: "Download".to_owned(),
            action: Action::Open(download.to_owned()),
        });
    }
    if offer.skippable() {
        buttons.push(Button {
            label: "Skip this version".to_owned(),
            action: Action::SkipVersion,
        });
    }
    let security = offer.latest.security;
    Banner {
        kind: Kind::Update,
        priority: if security {
            Priority::Security
        } else {
            Priority::Update
        },
        about: offer.latest.version.to_string(),
        text: offer.text(),
        tone: if security { Tone::Warning } else { Tone::Info },
        buttons,
        closable: true,
    }
}

/// Where the version skipped is kept
/// ([`binbun_paths::Place::SkippedUpdate`]).
pub fn skipped_path() -> Option<PathBuf> {
    binbun_paths::Place::SkippedUpdate.path()
}

/// The process's update checks, shared by its windows.
#[derive(Clone, Debug)]
pub struct Updates {
    build: Build,
    checker: Checker,
    skipped: Option<Version>,
    skipped_path: Option<PathBuf>,
    generation: u64,
}

impl Updates {
    /// Checks for `build` at `url`; the version skipped is kept at
    /// `skipped_path`.
    pub fn new(build: Build, url: String, skipped_path: Option<PathBuf>) -> Self {
        let skipped = skipped_path
            .as_deref()
            .and_then(|path| fs::read_to_string(path).ok())
            .and_then(|text| text.trim().parse().ok());
        Self {
            build,
            checker: Checker::new(url, &build),
            skipped,
            skipped_path,
            generation: 0,
        }
    }

    /// The check due at `now` under `setting`, if one is.
    pub fn start(&mut self, now: Instant, setting: UpdateCheck) -> Option<Request> {
        if !checks(&self.build, setting) {
            return None;
        }
        self.checker.start(now)
    }

    /// Takes a check's `result` (a failure silently).
    pub fn finish(&mut self, result: Result<Response, Error>) {
        if self.checker.finish(result) {
            self.generation += 1;
        }
    }

    /// The newer release to tell of, if any.
    pub fn offer(&self) -> Option<Offer> {
        offer(&self.build, self.checker.latest()?, self.skipped.as_ref())
    }

    /// Skips the version offered, for good (until a newer one).
    ///
    /// # Errors
    ///
    /// The file keeping it cannot be written (it is skipped for the
    /// session all the same).
    pub fn skip(&mut self) -> Result<(), String> {
        let Some(offer) = self.offer().filter(Offer::skippable) else {
            return Ok(());
        };
        let version = offer.latest.version;
        let text = format!("{version}\n");
        self.skipped = Some(version);
        self.generation += 1;
        let Some(path) = &self.skipped_path else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Counts the changes of what is offered: a window that saw another
    /// count draws again.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use binbun_cli::update::{INTERVAL, Latest};

    use super::*;

    fn build(check: bool, packaged_by: Option<&'static str>) -> Build {
        Build {
            version: "0.1.0",
            check,
            packaged_by,
        }
    }

    /// `updates` told `version` is out.
    fn found(updates: &mut Updates, version: &str, security: bool) {
        updates.finish(Ok(Response::Fresh {
            latest: Latest {
                version: version.parse().unwrap(),
                date: "2026-11-13".to_owned(),
                notes: format!("https://binbun.org/releases/{version}"),
                download: "https://binbun.org/download".to_owned(),
                security,
            },
            etag: None,
        }));
    }

    fn labels(banner: &Banner) -> Vec<&str> {
        banner.buttons.iter().map(|b| b.label.as_str()).collect()
    }

    /// A directory of this test's own under the system's temporary one.
    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("binbun-updates-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn only_always_checks_and_only_ask_asks() {
        let on = build(true, None);
        let off = build(false, None);
        assert!(asks(&on, UpdateCheck::Ask));
        assert!(!asks(&on, UpdateCheck::Always));
        assert!(!asks(&on, UpdateCheck::Never));
        assert!(checks(&on, UpdateCheck::Always));
        assert!(!checks(&on, UpdateCheck::Ask));
        assert!(!checks(&on, UpdateCheck::Never));
        // BINBUN_UPDATE_CHECK=off: no question, and the setting has no
        // effect.
        for setting in [UpdateCheck::Ask, UpdateCheck::Always, UpdateCheck::Never] {
            assert!(!asks(&off, setting));
            assert!(!checks(&off, setting));
        }
        let mut updates = Updates::new(off, "http://127.0.0.1:9/".to_owned(), None);
        assert_eq!(updates.start(Instant::now(), UpdateCheck::Always), None);
    }

    #[test]
    fn checks_start_at_launch_then_hourly_once_agreed() {
        let mut updates = Updates::new(build(true, None), "http://127.0.0.1:9/".to_owned(), None);
        let launch = Instant::now();
        // Not agreed yet: nothing, and the launch's check is still due
        // once agreed.
        assert_eq!(updates.start(launch, UpdateCheck::Ask), None);
        let later = launch + Duration::from_secs(5);
        assert!(updates.start(later, UpdateCheck::Always).is_some());
        assert_eq!(
            updates.start(later + INTERVAL / 2, UpdateCheck::Always),
            None
        );
        assert!(
            updates
                .start(later + INTERVAL, UpdateCheck::Always)
                .is_some()
        );
    }

    #[test]
    fn the_offer_banner_follows_security_and_packaging() {
        let mut updates = Updates::new(build(true, None), String::new(), None);
        assert_eq!(updates.offer(), None);
        found(&mut updates, "0.2.0", false);
        let normal = banner(&updates.offer().unwrap());
        assert_eq!(normal.priority, Priority::Update);
        assert_eq!(normal.text, "binbun 0.2.0 is available (you have 0.1.0).");
        assert_eq!(
            labels(&normal),
            ["Release notes", "Download", "Skip this version"]
        );
        assert_eq!(
            normal.buttons[1].action,
            Action::Open("https://binbun.org/download".to_owned())
        );

        found(&mut updates, "0.2.1", true);
        let security = banner(&updates.offer().unwrap());
        assert_eq!(security.priority, Priority::Security);
        assert_eq!(security.tone, Tone::Warning);
        assert_eq!(labels(&security), ["Release notes", "Download"]);
        assert!(security.closable);

        let mut packaged = Updates::new(build(true, Some("Homebrew")), String::new(), None);
        found(&mut packaged, "0.2.0", false);
        let packaged = banner(&packaged.offer().unwrap());
        assert_eq!(labels(&packaged), ["Release notes", "Skip this version"]);
        assert!(packaged.text.ends_with("update it through Homebrew."));
    }

    #[test]
    fn a_skipped_version_is_kept_until_a_newer_one() {
        let dir = scratch("skip");
        let path = dir.join("binbun").join("skipped-update");
        let mut updates = Updates::new(build(true, None), String::new(), Some(path.clone()));
        found(&mut updates, "0.2.0", false);
        let before = updates.generation();
        updates.skip().unwrap();
        assert_eq!(updates.offer(), None);
        assert!(updates.generation() > before);
        assert_eq!(fs::read_to_string(&path).unwrap(), "0.2.0\n");
        // The next launch remembers it.
        let mut next = Updates::new(build(true, None), String::new(), Some(path.clone()));
        found(&mut next, "0.2.0", false);
        assert_eq!(next.offer(), None);
        found(&mut next, "0.3.0", false);
        assert_eq!(next.offer().unwrap().latest.version.to_string(), "0.3.0");
        // A security release of a skipped version still shows, and
        // cannot be skipped.
        let mut security = Updates::new(build(true, None), String::new(), Some(path.clone()));
        found(&mut security, "0.2.0", true);
        security.skip().unwrap();
        assert!(security.offer().is_some());
        assert_eq!(fs::read_to_string(&path).unwrap(), "0.2.0\n");
        // A file that is no version skips nothing.
        fs::write(&path, "garbage").unwrap();
        let mut garbage = Updates::new(build(true, None), String::new(), Some(path));
        found(&mut garbage, "0.2.0", false);
        assert!(garbage.offer().is_some());
        fs::remove_dir_all(dir).unwrap();
    }
}
