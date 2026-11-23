//! Checks against a local server on 127.0.0.1: the `ETag` sent back and
//! a `304` taken as the answer kept; failures (a status, a broken file,
//! no server, a server too slow) silent, the answer kept; nothing sent
//! but the request and a plain `User-Agent`.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test helpers fail loudly"
)]

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use binbun_cli::update::{Build, Checker, Error, INTERVAL, Request, Response, Version};

const LATEST: &str = r#"{"schema":1,"version":"0.2.0","date":"2026-11-13","notes":"https://binbun.org/releases/0.2.0","download":"https://binbun.org/download","security":false}"#;

/// What the server answers one request with.
enum Answer {
    /// A status, headers and a body.
    Http(u16, Vec<(&'static str, &'static str)>, &'static str),
    /// Nothing for this long, then closing.
    Stall(Duration),
}

/// A server answering `answers` in turn, one connection each; the
/// requests' header lines (lowercased names) as they came.
fn serve(answers: Vec<Answer>) -> (String, Receiver<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/latest.json", listener.local_addr().unwrap());
    let (sent, received) = mpsc::channel();
    thread::spawn(move || {
        for answer in answers {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let request = read_request(&stream);
            let _ = sent.send(request);
            answer_with(stream, answer);
        }
    });
    (url, received)
}

fn read_request(stream: &TcpStream) -> Vec<String> {
    let mut reader = BufReader::new(stream);
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let line = line.trim_end().to_owned();
        if line.is_empty() {
            break;
        }
        lines.push(match line.split_once(':') {
            Some((name, value)) => format!("{}:{value}", name.to_ascii_lowercase()),
            None => line,
        });
    }
    lines
}

fn answer_with(mut stream: TcpStream, answer: Answer) {
    match answer {
        Answer::Http(status, headers, body) => {
            let mut text = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            for (name, value) in headers {
                let _ = write!(text, "{name}: {value}\r\n");
            }
            text.push_str("\r\n");
            text.push_str(body);
            let _ = stream.write_all(text.as_bytes());
        }
        Answer::Stall(time) => thread::sleep(time),
    }
}

fn build() -> Build {
    Build {
        version: "0.1.0",
        check: true,
        packaged_by: None,
    }
}

fn header<'a>(request: &'a [String], name: &str) -> Option<&'a str> {
    request.iter().find_map(|line| {
        line.strip_prefix(name)
            .and_then(|rest| rest.strip_prefix(':'))
            .map(str::trim)
    })
}

#[test]
fn an_etag_is_sent_back_and_a_304_keeps_the_answer() {
    let (url, requests) = serve(vec![
        Answer::Http(200, vec![("ETag", "\"v1\"")], LATEST),
        Answer::Http(304, vec![("ETag", "\"v1\"")], ""),
    ]);
    let launch = Instant::now();
    let mut checker = Checker::new(url, &build());
    let first = checker.start(launch).unwrap();
    assert!(checker.finish(first.send()));
    let version: Version = "0.2.0".parse().unwrap();
    assert_eq!(checker.latest().map(|l| &l.version), Some(&version));
    let request = requests.recv().unwrap();
    assert!(
        request[0].starts_with("GET /latest.json HTTP/1.1"),
        "{request:?}"
    );
    assert_eq!(header(&request, "if-none-match"), None);

    let second = checker.start(launch + INTERVAL).unwrap();
    assert_eq!(second.send(), Ok(Response::NotModified));
    assert!(!checker.finish(Ok(Response::NotModified)));
    assert_eq!(checker.latest().map(|l| &l.version), Some(&version));
    let request = requests.recv().unwrap();
    assert_eq!(header(&request, "if-none-match"), Some("\"v1\""));
}

#[test]
fn nothing_is_sent_but_the_request_and_a_plain_user_agent() {
    let (url, requests) = serve(vec![Answer::Http(200, Vec::new(), LATEST)]);
    let request = Request {
        url,
        user_agent: build().user_agent(),
        etag: None,
    };
    assert!(matches!(
        request.send(),
        Ok(Response::Fresh { etag: None, .. })
    ));
    let lines = requests.recv().unwrap();
    assert_eq!(header(&lines, "user-agent"), Some("binbun/0.1.0"));
    // The request line, then only these.
    for line in &lines[1..] {
        let name = line.split_once(':').unwrap().0;
        assert!(
            ["host", "user-agent", "accept"].contains(&name),
            "unexpected header {line:?}"
        );
    }
}

#[test]
fn failures_are_errors_and_keep_the_last_answer() {
    let (url, requests) = serve(vec![
        Answer::Http(200, vec![("ETag", "\"v1\"")], LATEST),
        Answer::Http(500, Vec::new(), "oops"),
        Answer::Http(200, Vec::new(), "<html>not json</html>"),
        Answer::Http(200, Vec::new(), r#"{"schema":7}"#),
        Answer::Stall(Duration::from_secs(3)),
    ]);
    let mut checker = Checker::new(url.clone(), &build());
    let mut now = Instant::now();
    let first = checker.start(now).unwrap();
    checker.finish(first.send());
    let kept = checker.latest().cloned().unwrap();
    let mut failures = Vec::new();
    for _ in 0..3 {
        now += INTERVAL;
        let result = checker.start(now).unwrap().send();
        failures.push(result.clone());
        assert!(!checker.finish(result));
        assert_eq!(checker.latest(), Some(&kept));
    }
    assert_eq!(failures[0], Err(Error::Status(500)));
    assert!(matches!(failures[1], Err(Error::Invalid(_))));
    assert_eq!(failures[2], Err(Error::Schema(7)));
    // Too slow: given up within the timeout.
    let slow = Request {
        url,
        user_agent: build().user_agent(),
        etag: None,
    };
    let began = Instant::now();
    assert!(matches!(
        slow.send_within(Duration::from_millis(300)),
        Err(Error::Network(_))
    ));
    assert!(began.elapsed() < Duration::from_secs(2));
    assert_eq!(requests.iter().take(5).count(), 5);
}

#[test]
fn no_server_is_a_silent_failure() {
    // A port just freed: nothing listens.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut checker = Checker::new(format!("http://127.0.0.1:{port}/latest.json"), &build());
    let request = checker.start(Instant::now()).unwrap();
    let result = request.send();
    assert!(matches!(result, Err(Error::Network(_))), "{result:?}");
    assert!(!checker.finish(result));
    assert_eq!(checker.latest(), None);
}

#[test]
fn a_304_without_an_etag_sent_is_an_error() {
    let (url, _requests) = serve(vec![Answer::Http(304, Vec::new(), "")]);
    let request = Request {
        url,
        user_agent: build().user_agent(),
        etag: None,
    };
    assert_eq!(request.send(), Err(Error::Status(304)));
}
