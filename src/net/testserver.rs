//! A small threaded HTTP/1.1 server for the engine tests: one request per connection, one body
//! for every path, with switches for range support, If-Range, a dropped connection and pacing.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Deterministic bytes that differ per `seed`.
pub(crate) fn body(len: u64, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

pub(crate) struct Behaviour {
    pub body: Vec<u8>,
    pub etag: Option<String>,
    pub ranges: bool,
    pub if_range: bool,
    /// Drop the connection once this file offset has been sent (one time).
    pub die_at: Option<u64>,
    /// Answer every request with this status and `Retry-After: 7`.
    pub status: Option<u16>,
    /// Pause after each 16 KiB written.
    pub pace: Duration,
    /// Bodies by request path (no leading slash, query included), each with an `ETag` of its
    /// content; any other path is a 404. `None` serves `body` everywhere.
    pub routes: Option<HashMap<String, Vec<u8>>>,
    /// Paths answered with a 302 to the given Location, before anything else.
    pub redirects: HashMap<String, String>,
    /// Paths answered with this status and these raw header lines (each ending in CRLF) and no
    /// body, after the redirects.
    pub replies: HashMap<String, (u16, String)>,
}

impl Behaviour {
    pub(crate) fn new(body: Vec<u8>) -> Self {
        Self {
            body,
            etag: Some("\"v1\"".into()),
            ranges: true,
            if_range: true,
            die_at: None,
            status: None,
            pace: Duration::ZERO,
            routes: None,
            redirects: HashMap::new(),
            replies: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Hit {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
    pub range: Option<String>,
    pub if_range: Option<String>,
    pub status: u16,
}

#[derive(Default)]
struct Stats {
    hits: Mutex<Vec<Hit>>,
    served: AtomicU64,
    active: AtomicUsize,
    max_active: AtomicUsize,
}

pub(crate) struct Server {
    pub addr: SocketAddr,
    b: Arc<Mutex<Behaviour>>,
    stats: Arc<Stats>,
}

impl Server {
    pub(crate) fn start(ip: &str, b: Behaviour) -> Self {
        let ln = TcpListener::bind((ip, 0)).unwrap();
        let addr = ln.local_addr().unwrap();
        let b = Arc::new(Mutex::new(b));
        let stats = Arc::new(Stats::default());
        let (bb, ss) = (b.clone(), stats.clone());
        std::thread::spawn(move || {
            for sock in ln.incoming() {
                let Ok(sock) = sock else { return };
                let (b, s) = (bb.clone(), ss.clone());
                std::thread::spawn(move || serve(sock, &b, &s));
            }
        });
        Self { addr, b, stats }
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("http://{}/{path}", self.addr)
    }

    pub(crate) fn set(&self, f: impl FnOnce(&mut Behaviour)) {
        f(&mut self.b.lock().unwrap());
    }

    pub(crate) fn hits(&self) -> Vec<Hit> {
        self.stats.hits.lock().unwrap().clone()
    }

    pub(crate) fn served(&self) -> u64 {
        self.stats.served.load(Ordering::SeqCst)
    }

    pub(crate) fn max_active(&self) -> usize {
        self.stats.max_active.load(Ordering::SeqCst)
    }

    pub(crate) fn clear_log(&self) {
        self.stats.hits.lock().unwrap().clear();
        self.stats.served.store(0, Ordering::SeqCst);
    }
}

/// Counts a request as in flight until dropped.
struct Active<'a>(&'a AtomicUsize);

impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn serve(mut sock: TcpStream, behaviour: &Mutex<Behaviour>, counts: &Stats) {
    let mut reader = BufReader::new(sock.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let mut words = line.split_whitespace();
    let method = words.next().unwrap_or_default().to_string();
    let is_head = method == "HEAD";
    let path = words
        .next()
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_string();
    let (mut range, mut if_range, mut length) = (None, None, 0usize);
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).unwrap_or(0) == 0 || header.trim().is_empty() {
            break;
        }
        let (k, v) = header.split_once(':').unwrap_or_default();
        match k.to_ascii_lowercase().as_str() {
            "range" => range = Some(v.trim().to_string()),
            "if-range" => if_range = Some(v.trim().to_string()),
            "content-length" => length = v.trim().parse().unwrap_or(0),
            _ => {}
        }
    }
    let mut data = vec![0; length];
    if reader.read_exact(&mut data).is_err() {
        return;
    }
    let req = Req { method, path, data };
    let (to, reply) = {
        let b = behaviour.lock().unwrap();
        (
            b.redirects.get(req.path.as_str()).cloned(),
            b.replies.get(req.path.as_str()).cloned(),
        )
    };
    if let Some((status, lines)) = reply.filter(|_| to.is_none()) {
        req.record(counts, range, if_range, status);
        let head = format!(
            "HTTP/1.1 {status} Reply\r\n{lines}Content-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let _ = sock.write_all(head.as_bytes());
        return;
    }
    if let Some(to) = to {
        req.record(counts, range, if_range, 302);
        let head = format!(
            "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let _ = sock.write_all(head.as_bytes());
        return;
    }
    let now = counts.active.fetch_add(1, Ordering::SeqCst) + 1;
    counts.max_active.fetch_max(now, Ordering::SeqCst);
    respond(
        sock,
        behaviour,
        counts,
        range,
        if_range,
        Active(&counts.active),
        (is_head, req),
    );
}

struct Req {
    method: String,
    path: String,
    data: Vec<u8>,
}

impl Req {
    fn record(&self, counts: &Stats, range: Option<String>, if_range: Option<String>, status: u16) {
        let hit = Hit {
            method: self.method.clone(),
            path: self.path.clone(),
            body: self.data.clone(),
            range,
            if_range,
            status,
        };
        counts.hits.lock().unwrap().push(hit);
    }
}

/// An `ETag` that changes with the content (FNV-1a).
fn content_tag(body: &[u8]) -> String {
    let sum = body.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    });
    format!("\"{sum:016x}\"")
}

fn respond(
    mut sock: TcpStream,
    behaviour: &Mutex<Behaviour>,
    counts: &Stats,
    range: Option<String>,
    if_range: Option<String>,
    active: Active<'_>,
    (is_head, req): (bool, Req),
) {
    let path = req.path.as_str();
    let (data, etag, pace, die_at, status, head) = {
        let mut cfg = behaviour.lock().unwrap();
        let routed = cfg.routes.as_ref().map(|r| r.get(path).cloned());
        let missing = matches!(routed, Some(None));
        let body = match routed {
            Some(b) => b.unwrap_or_default(),
            None => cfg.body.clone(),
        };
        let etag = if cfg.routes.is_some() {
            Some(content_tag(&body))
        } else {
            cfg.etag.clone()
        };
        let len = body.len() as u64;
        let fresh = !cfg.if_range || if_range.is_none() || if_range == etag;
        let span = range
            .as_deref()
            .filter(|_| cfg.ranges && fresh)
            .and_then(|r| r.strip_prefix("bytes="))
            .and_then(|r| r.split_once('-'))
            .map(|(a, e)| {
                let a: u64 = a.parse().unwrap();
                (
                    a,
                    e.parse()
                        .map_or(len.saturating_sub(1), |e: u64| e.min(len - 1)),
                )
            });
        let (status, slice, head) = match (cfg.status, span) {
            (Some(st), _) => (st, 0..0, "Retry-After: 7\r\n".to_string()),
            (None, _) if missing => (404, 0..0, String::new()),
            (None, Some((a, _))) if a >= len => {
                (416, 0..0, format!("Content-Range: bytes */{len}\r\n"))
            }
            (None, Some((a, e))) => (
                206,
                a..e + 1,
                format!("Content-Range: bytes {a}-{e}/{len}\r\n"),
            ),
            (None, None) => (200, 0..len, String::new()),
        };
        let start = slice.start;
        let to = |x: u64| usize::try_from(x).unwrap();
        let data = body[to(slice.start)..to(slice.end)].to_vec();
        let die = cfg
            .die_at
            .filter(|d| (start..start + data.len() as u64).contains(d));
        if die.is_some() {
            cfg.die_at = None;
        }
        (data, etag, cfg.pace, die.map(|d| d - start), status, head)
    };
    req.record(counts, range, if_range, status);
    let reason = if status == 206 {
        "Partial Content"
    } else {
        "OK"
    };
    let etag = etag.map(|e| format!("ETag: {e}\r\n")).unwrap_or_default();
    let reply = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\nAccept-Ranges: bytes\r\n{head}{etag}\r\n",
        data.len()
    );
    if sock.write_all(reply.as_bytes()).is_err() || is_head {
        return;
    }
    let mut sent = 0u64;
    let mut active = Some(active);
    let last = data.len().div_ceil(16 << 10).saturating_sub(1);
    for (i, chunk) in data.chunks(16 << 10).enumerate() {
        // Not active once the client can have it all, so the next request never overlaps.
        if i == last {
            active.take();
        }
        let chunk = match die_at {
            Some(d) if sent + chunk.len() as u64 > d => {
                let n = usize::try_from(d - sent).unwrap();
                let _ = sock.write_all(&chunk[..n]);
                counts.served.fetch_add(n as u64, Ordering::SeqCst);
                break;
            }
            _ => chunk,
        };
        if sock.write_all(chunk).is_err() {
            return;
        }
        sent += chunk.len() as u64;
        counts
            .served
            .fetch_add(chunk.len() as u64, Ordering::SeqCst);
        if !pace.is_zero() && i != last {
            std::thread::sleep(pace);
        }
    }
    if die_at.is_some() {
        let _ = sock.shutdown(std::net::Shutdown::Both);
    }
}
