//! A symbol server for tests: HTTP/1.1 on a local port, serving fixed
//! bytes by path (404 otherwise) and recording every request's path, so a
//! test sees exactly what was asked. No test touches the network.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;

/// A local server running on a thread of its own until the test ends.
#[derive(Debug)]
pub struct LocalServer {
    /// Its URL (`http://127.0.0.1:<port>`).
    pub url: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl LocalServer {
    /// Serves `files` (URL path, starting with `/`, to bytes).
    pub fn serve(files: Vec<(String, Vec<u8>)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a local port");
        let url = format!("http://{}", listener.local_addr().expect("its address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let files: Arc<HashMap<String, Vec<u8>>> = Arc::new(files.into_iter().collect());
        {
            let requests = Arc::clone(&requests);
            thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let files = Arc::clone(&files);
                    let requests = Arc::clone(&requests);
                    thread::spawn(move || answer(stream, &files, &requests));
                }
            });
        }
        Self { url, requests }
    }

    /// The paths asked for so far, in order.
    pub fn requests(&self) -> Vec<String> {
        self.requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Answers the requests on one connection (kept alive while the client
/// keeps it).
fn answer(stream: TcpStream, files: &HashMap<String, Vec<u8>>, requests: &Mutex<Vec<String>>) {
    let Ok(mut out) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let path = line
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            if header == "\r\n" || header == "\n" {
                break;
            }
        }
        requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(path.clone());
        let written = match files.get(&path) {
            Some(body) => out
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .and_then(|()| out.write_all(body)),
            None => out.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"),
        };
        if written.and_then(|()| out.flush()).is_err() {
            return;
        }
    }
}
