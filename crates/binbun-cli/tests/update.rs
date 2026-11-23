//! `binbun update --check` against a local server on 127.0.0.1
//! (`BINBUN_UPDATE_URL`): exit code 0 up to date, 1 a newer release out,
//! 2 no answer or a usage error.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::thread;

/// A server answering one request with `status` and `body`.
fn serve(status: u16, body: impl Into<String>) -> String {
    let body = body.into();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/latest.json", listener.local_addr().unwrap());
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 && line != "\r\n" {
            line.clear();
        }
        let _ = write!(
            stream,
            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
    });
    url
}

/// `binbun update ARGS` checking `url`.
fn update(url: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_binbun"))
        .arg("update")
        .args(args)
        .env("BINBUN_UPDATE_URL", url)
        .output()
        .unwrap()
}

fn latest(version: &str) -> String {
    format!(
        r#"{{"schema":1,"version":"{version}","date":"2026-11-13","notes":"https://binbun.org/releases/{version}","download":"https://binbun.org/download","security":false}}"#
    )
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn the_exit_code_says_up_to_date_newer_or_no_answer() {
    let running = env!("CARGO_PKG_VERSION");
    let same = update(&serve(200, latest(running)), &["--check"]);
    assert_eq!(same.status.code(), Some(0), "{}", text(&same.stderr));
    assert!(text(&same.stdout).contains("is up to date"));

    let older = update(
        &serve(200, latest(&format!("{running}-rc.1"))),
        &["--check"],
    );
    assert_eq!(older.status.code(), Some(0), "{}", text(&older.stderr));

    let newer = update(&serve(200, latest("999.0.0")), &["--check"]);
    assert_eq!(newer.status.code(), Some(1), "{}", text(&newer.stderr));
    let out = text(&newer.stdout);
    assert!(
        out.starts_with(&format!("binbun 999.0.0 is available (you have {running})")),
        "{out}"
    );
    assert!(out.contains("https://binbun.org/releases/999.0.0"), "{out}");

    let failed = update(&serve(500, ""), &["--check"]);
    assert_eq!(failed.status.code(), Some(2));
    assert!(text(&failed.stderr).contains("HTTP 500"));

    let broken = update(&serve(200, "{"), &["--check"]);
    assert_eq!(broken.status.code(), Some(2));
}

#[test]
fn no_server_or_no_flag_is_exit_code_2() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let url = format!("http://127.0.0.1:{port}/latest.json");
    assert_eq!(update(&url, &["--check"]).status.code(), Some(2));
    // Never unasked: `update` alone is a usage error, with no request.
    let bare = update(&url, &[]);
    assert_eq!(bare.status.code(), Some(2));
    assert!(text(&bare.stderr).contains("usage: binbun update --check"));
}
