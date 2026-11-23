//! `binbun update --check`: the running version against the latest
//! release ([`crate::update`]), checked only when asked. Exit code 0: up
//! to date; 1: a newer release is out; 2: no answer (no network, a bad
//! file, a build with the check compiled out, a usage error).

use std::fmt::Write as _;
use std::process::ExitCode;

use crate::update::{self, Build, Request, Response, Version, offer};

/// Up to date.
pub const CURRENT: u8 = 0;
/// A newer release is out.
pub const NEWER: u8 = 1;
/// No answer.
pub const FAILED: u8 = 2;

/// Checks `url` as `build`: the exit code and what to print.
pub fn check(build: &Build, url: &str) -> (u8, String) {
    if !build.check {
        let how = build.packaged_by.map_or_else(
            || "as it was installed".to_owned(),
            |by| format!("through {by}"),
        );
        return (
            FAILED,
            format!(
                "this build of binbun does not check for updates (BINBUN_UPDATE_CHECK=off): update it {how}"
            ),
        );
    }
    let Ok(current) = build.version.parse::<Version>() else {
        return (
            FAILED,
            format!("this build's version {:?} is no version", build.version),
        );
    };
    let request = Request {
        url: url.to_owned(),
        user_agent: build.user_agent(),
        etag: None,
    };
    let latest = match request.send() {
        Ok(Response::Fresh { latest, .. }) => latest,
        Ok(Response::NotModified) => {
            return (FAILED, format!("{url}: no answer"));
        }
        Err(error) => return (FAILED, format!("{url}: {error}")),
    };
    match offer(build, &latest, None) {
        Some(offer) => {
            let mut text = format!("{}\nrelease notes: {}\n", offer.text(), latest.notes);
            if let Some(download) = offer.download() {
                let _ = writeln!(text, "download: {download}");
            }
            (NEWER, text)
        }
        None => (
            CURRENT,
            format!(
                "binbun {current} is up to date (the latest release is {}, {}).\n",
                latest.version, latest.date
            ),
        ),
    }
}

/// `binbun update ARGS`.
pub fn command(args: &[String]) -> ExitCode {
    if !matches!(args, [flag] if flag == "--check") {
        eprintln!("usage: binbun update --check");
        return ExitCode::from(FAILED);
    }
    let build = Build::current(env!("CARGO_PKG_VERSION"));
    let (code, text) = check(&build, &update::url());
    if code == FAILED {
        eprintln!("binbun update: {text}");
    } else {
        print!("{text}");
    }
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_build_with_the_check_compiled_out_never_asks() {
        // Nothing listens at port 9 on 127.0.0.1 either: an attempt would
        // fail differently.
        let off = Build {
            version: "0.1.0",
            check: false,
            packaged_by: Some("Debian"),
        };
        let (code, text) = check(&off, "http://127.0.0.1:9/latest.json");
        assert_eq!(code, FAILED);
        assert!(text.ends_with("update it through Debian"), "{text}");
        assert!(!text.contains("127.0.0.1"), "{text}");
    }
}
