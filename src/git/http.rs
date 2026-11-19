//! gix's `Http` transport over the shared ureq agent, so git traffic uses the same TLS roots,
//! timeouts and bandwidth bucket as every other download.
//!
//! Each request runs on its own thread and talks to the caller through bounded pipes, in the
//! order gix expects: write the POST body, read the headers to the end, read the body. Nothing
//! here follows a redirect, and no header line ever reaches an error: only the status and the
//! URL without its query.

use crate::net::throttle::Throttle;
use gix::error::Error;
use gix::protocol::transport::client::blocking_io::http::{
    GetResponse, Http, PostBodyDataKind, PostResponse,
};
use std::io::{self, BufRead, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use ureq::Agent;
use ureq::http::{self, Method};

const CHUNK: usize = 64 << 10;
const POST_CAP: u64 = 16 << 20;
const IN_FLIGHT: usize = 4;
/// How often a producer facing a full pipe looks at the stop flags again.
const BACKOFF: Duration = Duration::from_millis(10);

type Chunk = io::Result<Vec<u8>>;

/// The read end of a pipe: the headers, or the POST body as the request thread sees it.
pub(crate) struct Pipe {
    rx: Receiver<Chunk>,
    buf: Vec<u8>,
    pos: usize,
}

impl Pipe {
    fn new(rx: Receiver<Chunk>) -> Self {
        Self {
            rx,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

impl BufRead for Pipe {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        while self.pos >= self.buf.len() {
            match self.rx.recv() {
                Ok(chunk) => (self.buf, self.pos) = (chunk?, 0),
                Err(_) => return Ok(&[]),
            }
        }
        Ok(&self.buf[self.pos..])
    }

    fn consume(&mut self, amt: usize) {
        self.pos = (self.pos + amt).min(self.buf.len());
    }
}

impl Read for Pipe {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.fill_buf()?.len().min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.consume(n);
        Ok(n)
    }
}

/// The response body. `got` counts what the consumer takes out, not what the thread read ahead,
/// and nothing counts once `stop` is set.
pub(crate) struct Body {
    pipe: Pipe,
    got: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl Body {
    fn check(&self) -> io::Result<()> {
        if self.stop.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "stopped"));
        }
        Ok(())
    }
}

impl Read for Body {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        let n = self.pipe.read(out)?;
        self.got.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

impl BufRead for Body {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.check()?;
        self.pipe.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        let n = amt.min(self.pipe.buf.len() - self.pipe.pos);
        self.got.fetch_add(n as u64, Ordering::Relaxed);
        self.pipe.consume(n);
    }
}

/// The POST body's write end.
pub(crate) struct Upload(SyncSender<Chunk>, Arc<Mutex<Option<String>>>);

impl Write for Upload {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.send(Ok(buf.to_vec())).map_err(|e| {
            match self.1.lock().ok().and_then(|w| w.clone()) {
                Some(why) => io::Error::other(why),
                None => io::Error::new(io::ErrorKind::BrokenPipe, e),
            }
        })?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bare(url: &str) -> &str {
    url.split(['?', '#']).next().unwrap_or(url)
}

struct Job {
    agent: Agent,
    throttle: Arc<Throttle>,
    limit: u64,
    stop: Arc<AtomicBool>,
    halt: Arc<AtomicBool>,
    url: String,
    headers: Vec<(String, String)>,
    upload: Option<Pipe>,
    why: Arc<Mutex<Option<String>>>,
}

impl Job {
    fn quit(&self) -> bool {
        self.stop.load(Ordering::Relaxed) || self.halt.load(Ordering::Relaxed)
    }

    /// Sends without ever blocking past a stop or the reader's end; false when it gave up.
    fn send(&self, tx: &SyncSender<Chunk>, mut item: Chunk) -> bool {
        loop {
            match tx.try_send(item) {
                Ok(()) => return true,
                Err(TrySendError::Disconnected(_)) => return false,
                Err(TrySendError::Full(back)) => {
                    if self.quit() {
                        return false;
                    }
                    item = back;
                    std::thread::sleep(BACKOFF);
                }
            }
        }
    }

    fn run(mut self, head_tx: SyncSender<Chunk>, body_tx: &SyncSender<Chunk>) {
        let resp = match self.open() {
            Ok(r) => r,
            Err(e) => {
                self.send(&head_tx, Err(e));
                return;
            }
        };
        let mut lines = Vec::new();
        for (k, v) in resp.headers() {
            lines.extend_from_slice(k.as_str().as_bytes());
            lines.push(b':');
            lines.extend_from_slice(v.as_bytes());
            lines.push(b'\n');
        }
        if !self.send(&head_tx, Ok(lines)) {
            return;
        }
        drop(head_tx);
        if let Err(e) = self.stream(resp.into_body(), body_tx) {
            self.send(body_tx, Err(e));
        }
    }

    fn open(&mut self) -> io::Result<http::Response<ureq::Body>> {
        let bad = |_| io::Error::other(format!("{}: bad request", bare(&self.url)));
        let mut req = http::Request::builder().uri(&self.url);
        for (k, v) in &self.headers {
            req = req.header(k, v);
        }
        let resp = match self.upload.take() {
            None => self
                .agent
                .run(req.method(Method::GET).body(()).map_err(bad)?),
            Some(mut up) => {
                let mut data = Vec::new();
                (&mut up).take(POST_CAP + 1).read_to_end(&mut data)?;
                if data.len() as u64 > POST_CAP {
                    let why = format!(
                        "{}: request body larger than {POST_CAP} bytes",
                        bare(&self.url)
                    );
                    // set before `up` drops, so the writer's failed send finds it
                    if let Ok(mut w) = self.why.lock() {
                        *w = Some(why.clone());
                    }
                    return Err(io::Error::other(why));
                }
                self.agent
                    .run(req.method(Method::POST).body(data).map_err(bad)?)
            }
        }
        .map_err(|e| io::Error::other(format!("{}: {e}", bare(&self.url))))?;
        let status = resp.status().as_u16();
        let url = bare(&self.url);
        match status {
            200..=299 => Ok(resp),
            401 | 403 => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{url}: {status}"),
            )),
            300..=399 => {
                let to = resp
                    .headers()
                    .get("location")
                    .and_then(|l| l.to_str().ok())
                    .map_or("", bare);
                Err(io::Error::other(format!("{url}: HTTP {status} to {to}")))
            }
            _ => Err(io::Error::other(format!("{url}: HTTP {status}"))),
        }
    }

    fn stream(&self, body: ureq::Body, tx: &SyncSender<Chunk>) -> io::Result<()> {
        let mut reader = body.into_reader();
        let mut total = 0u64;
        loop {
            if self.quit() {
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "stopped"));
            }
            let mut buf = vec![0u8; CHUNK];
            let n = reader
                .read(&mut buf)
                .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", bare(&self.url))))?;
            if n == 0 {
                return Ok(());
            }
            self.throttle.take(n);
            total += n as u64;
            if total > self.limit {
                return Err(io::Error::other(format!(
                    "{}: larger than {} bytes",
                    bare(&self.url),
                    self.limit
                )));
            }
            buf.truncate(n);
            if !self.send(tx, Ok(buf)) {
                return Ok(());
            }
        }
    }
}

/// `limit` caps each response body; `got` counts the body bytes the consumer has taken; `stop`
/// ends every transfer and read at the next chunk.
pub(crate) struct Remote {
    agent: Agent,
    throttle: Arc<Throttle>,
    got: Arc<AtomicU64>,
    limit: u64,
    stop: Arc<AtomicBool>,
    halt: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Remote {
    pub(crate) fn new(
        agent: Agent,
        throttle: Arc<Throttle>,
        got: Arc<AtomicU64>,
        limit: u64,
        stop: Arc<AtomicBool>,
    ) -> Self {
        Self {
            agent,
            throttle,
            got,
            limit,
            stop,
            halt: Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
        }
    }

    fn start(
        &mut self,
        url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
        upload: Option<Pipe>,
        why: Arc<Mutex<Option<String>>>,
    ) -> Result<(Pipe, Body), Error> {
        let authority = url.split_once("://").map_or(url, |(_, r)| r);
        if authority
            .split(['/', '?', '#'])
            .next()
            .is_some_and(|a| a.contains('@'))
        {
            return Err(Error::from_error(io::Error::other(
                "a URL with credentials is refused",
            )));
        }
        let headers = headers
            .into_iter()
            .filter_map(|h| {
                let (k, v) = h.as_ref().split_once(':')?;
                Some((k.trim().to_string(), v.trim().to_string()))
            })
            .collect();
        let (head_tx, head_rx) = sync_channel(IN_FLIGHT);
        let (body_tx, body_rx) = sync_channel(IN_FLIGHT);
        let job = Job {
            agent: self.agent.clone(),
            throttle: self.throttle.clone(),
            limit: self.limit,
            stop: self.stop.clone(),
            halt: self.halt.clone(),
            url: url.to_string(),
            headers,
            upload,
            why,
        };
        self.threads.retain(|t| !t.is_finished());
        let thread = std::thread::Builder::new()
            .spawn(move || job.run(head_tx, &body_tx))
            .map_err(Error::from_error)?;
        self.threads.push(thread);
        let body = Body {
            pipe: Pipe::new(body_rx),
            got: self.got.clone(),
            stop: self.stop.clone(),
        };
        Ok((Pipe::new(head_rx), body))
    }
}

impl Drop for Remote {
    fn drop(&mut self) {
        self.halt.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            // A panicked request thread has nothing left to report.
            let _ = t.join();
        }
    }
}

impl Http for Remote {
    type Headers = Pipe;
    type ResponseBody = Body;
    type PostBody = Upload;

    fn get(
        &mut self,
        url: &str,
        _base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> gix::error::Result<GetResponse<Pipe, Body>> {
        let (headers, body) = self.start(url, headers, None, Arc::default())?;
        Ok(GetResponse { headers, body })
    }

    fn post(
        &mut self,
        url: &str,
        _base_url: &str,
        headers: impl IntoIterator<Item = impl AsRef<str>>,
        _kind: PostBodyDataKind,
    ) -> gix::error::Result<PostResponse<Pipe, Body, Upload>> {
        let (tx, rx) = sync_channel(IN_FLIGHT);
        let why = Arc::<Mutex<Option<String>>>::default();
        let (headers, body) = self.start(url, headers, Some(Pipe::new(rx)), why.clone())?;
        Ok(PostResponse {
            post_body: Upload(tx, why),
            headers,
            body,
        })
    }

    fn configure(&mut self, _config: &dyn std::any::Any) -> gix::error::Result {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::client::loopback_agent;
    use crate::net::testserver::{Behaviour, Server, body};
    use std::time::Instant;
    use tracing_subscriber::fmt::MakeWriter;
    use ureq::tls::RootCerts;

    const TOKEN: &str = "ghp_s3cr3t";

    struct Fixture {
        remote: Remote,
        got: Arc<AtomicU64>,
        stop: Arc<AtomicBool>,
    }

    fn fixture(rate: u64, limit: u64) -> Fixture {
        let got = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let remote = Remote::new(
            loopback_agent(RootCerts::new_with_certs(&[])),
            Arc::new(Throttle::new(rate)),
            got.clone(),
            limit,
            stop.clone(),
        );
        Fixture { remote, got, stop }
    }

    fn get(r: &mut Remote, url: &str) -> io::Result<(String, Vec<u8>)> {
        let resp = r
            .get(url, url, [format!("Authorization: Bearer {TOKEN}")])
            .unwrap();
        let (mut head, mut data) = (String::new(), Vec::new());
        let (mut h, mut b) = (resp.headers, resp.body);
        h.read_to_string(&mut head)?;
        b.read_to_end(&mut data)?;
        Ok((head, data))
    }

    #[test]
    fn passthrough() {
        let data = body(200_000, 1);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        let mut f = fixture(0, u64::MAX);
        let (head, got) = get(&mut f.remote, &srv.url("a")).unwrap();
        assert_eq!(got, data);
        assert!(head.contains("content-length:200000\n"), "{head}");
        assert_eq!(f.got.load(Ordering::Relaxed), 200_000);
    }

    #[test]
    fn throttle_applies() {
        let srv = Server::start("127.0.0.1", Behaviour::new(body(512 << 10, 2)));
        let mut f = fixture(1 << 20, u64::MAX);
        let start = Instant::now();
        get(&mut f.remote, &srv.url("a")).unwrap();
        assert!(
            start.elapsed() >= Duration::from_millis(450),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn post_body_arrives_intact() {
        let srv = Server::start("127.0.0.1", Behaviour::new(b"answer".to_vec()));
        let mut f = fixture(0, u64::MAX);
        let sent = body(100_000, 3);
        let url = srv.url("svc");
        let resp = f
            .remote
            .post(&url, &url, ["Content-Type: x"], PostBodyDataKind::Unbounded)
            .unwrap();
        let mut up = resp.post_body;
        for part in sent.chunks(7000) {
            up.write_all(part).unwrap();
        }
        drop(up);
        let (mut head, mut got) = (String::new(), Vec::new());
        let (mut h, mut b) = (resp.headers, resp.body);
        h.read_to_string(&mut head).unwrap();
        b.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"answer");
        let hits = srv.hits();
        assert_eq!((hits.len(), hits[0].method.as_str()), (1, "POST"));
        assert_eq!(hits[0].body, sent);
    }

    #[test]
    fn post_over_the_cap_fails() {
        let srv = Server::start("127.0.0.1", Behaviour::new(Vec::new()));
        let mut f = fixture(0, u64::MAX);
        let url = srv.url("svc");
        let resp = f
            .remote
            .post(&url, &url, ["A: b"], PostBodyDataKind::Unbounded)
            .unwrap();
        let mut up = resp.post_body;
        let chunk = vec![0u8; 1 << 20];
        let mut write_err = None;
        for _ in 0..64 {
            if let Err(e) = up.write_all(&chunk) {
                write_err = Some(e);
                break;
            }
        }
        let write_err = write_err.expect("the cap never stopped the upload");
        assert!(write_err.to_string().contains("larger than"), "{write_err}");
        drop(up);
        let err = io::read_to_string(resp.headers).unwrap_err();
        assert!(err.to_string().contains("larger than"), "{err}");
        assert!(srv.hits().is_empty());
    }

    #[test]
    fn a_redirect_is_one_request_and_an_error() {
        let srv = Server::start("127.0.0.1", Behaviour::new(Vec::new()));
        srv.set(|b| {
            b.redirects
                .insert("a".into(), "http://127.0.0.1:9/m?sig=hidden".into());
        });
        let mut f = fixture(0, u64::MAX);
        let err = get(&mut f.remote, &srv.url("a")).unwrap_err().to_string();
        assert!(err.ends_with("HTTP 302 to http://127.0.0.1:9/m"), "{err}");
        assert_eq!(srv.hits().len(), 1);
    }

    #[test]
    fn statuses_and_limit() {
        let srv = Server::start("127.0.0.1", Behaviour::new(vec![7; 1000]));
        srv.set(|b| {
            b.routes = Some([("ok?k=v".to_string(), vec![7; 1000])].into());
            b.replies.insert("e500?k=v".into(), (500, String::new()));
            b.replies.insert(
                "e401?k=v".into(),
                (401, "WWW-Authenticate: Basic\r\n".into()),
            );
            b.replies.insert("e403?k=v".into(), (403, String::new()));
        });
        let mut f = fixture(0, 999);
        for (path, kind, text) in [
            ("missing", io::ErrorKind::Other, "HTTP 404"),
            ("e500", io::ErrorKind::Other, "HTTP 500"),
            ("e401", io::ErrorKind::PermissionDenied, "/e401: 401"),
            ("e403", io::ErrorKind::PermissionDenied, "/e403: 403"),
            ("ok", io::ErrorKind::Other, "larger than 999 bytes"),
        ] {
            let err = get(&mut f.remote, &srv.url(&format!("{path}?k=v"))).unwrap_err();
            assert_eq!(err.kind(), kind, "{path}: {err}");
            assert!(err.to_string().contains(text), "{path}: {err}");
            assert!(!err.to_string().contains("k=v"), "{path}: {err}");
        }
        let mut f = fixture(0, 1000);
        assert_eq!(
            get(&mut f.remote, &srv.url("ok?k=v")).unwrap().1.len(),
            1000
        );
    }

    #[test]
    fn stop_ends_the_reader_and_the_count() {
        let mut data = Behaviour::new(body(2 << 20, 4));
        data.pace = Duration::from_millis(2);
        let srv = Server::start("127.0.0.1", data);
        let mut f = fixture(0, u64::MAX);
        let url = srv.url("a");
        let resp = f.remote.get(&url, &url, ["A: b"]).unwrap();
        let (mut h, mut b) = (resp.headers, resp.body);
        io::read_to_string(&mut h).unwrap();
        let mut buf = [0u8; 4096];
        assert!(b.read(&mut buf).unwrap() > 0);
        f.stop.store(true, Ordering::Relaxed);
        let seen = f.got.load(Ordering::Relaxed);
        let err = b.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(b.read_exact(&mut buf[..4]).is_err());
        assert!(b.read_to_end(&mut Vec::new()).is_err());
        assert_eq!(f.got.load(Ordering::Relaxed), seen);
        let start = Instant::now();
        drop(b);
        drop(f.remote);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
        assert_eq!(f.got.load(Ordering::Relaxed), seen);
    }

    #[test]
    fn dropping_the_reader_frees_the_thread() {
        let srv = Server::start("127.0.0.1", Behaviour::new(body(4 << 20, 5)));
        let mut f = fixture(0, u64::MAX);
        let url = srv.url("a");
        let resp = f.remote.get(&url, &url, ["A: b"]).unwrap();
        drop((resp.headers, resp.body));
        let start = Instant::now();
        drop(f.remote);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn a_url_with_userinfo_is_refused() {
        let srv = Server::start("127.0.0.1", Behaviour::new(Vec::new()));
        let mut f = fixture(0, u64::MAX);
        for url in [
            format!("http://user:hunter2@{}/x", srv.addr),
            format!("http://{TOKEN}@{}/x?a=b", srv.addr),
        ] {
            let Err(err) = f.remote.get(&url, &url, ["A: b"]) else {
                panic!("{url} was accepted");
            };
            let text = format!("{err} {err:?}");
            assert!(!text.contains("hunter2") && !text.contains(TOKEN), "{text}");
        }
        assert!(srv.hits().is_empty());
    }

    static LOGGED: Mutex<Vec<u8>> = Mutex::new(Vec::new());

    #[derive(Clone)]
    struct Capture;

    impl Write for Capture {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            LOGGED.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl MakeWriter<'_> for Capture {
        type Writer = Capture;

        fn make_writer(&self) -> Capture {
            Capture
        }
    }

    struct LogCapture;

    impl log::Log for LogCapture {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }

        fn log(&self, r: &log::Record) {
            let line = format!("{} {}\n", r.target(), r.args());
            LOGGED.lock().unwrap().extend_from_slice(line.as_bytes());
        }

        fn flush(&self) {}
    }

    #[test]
    fn token_never_in_errors() {
        let gone = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let srv = Server::start("127.0.0.1", Behaviour::new(Vec::new()));
        srv.set(|b| {
            b.replies.insert("boom".into(), (500, String::new()));
        });
        // global, not `with_default`: requests run on their own threads. ureq logs through `log`.
        tracing::subscriber::set_global_default(
            tracing_subscriber::fmt().with_writer(Capture).finish(),
        )
        .unwrap();
        log::set_logger(&LogCapture).unwrap();
        log::set_max_level(log::LevelFilter::Trace);
        let mut f = fixture(0, u64::MAX);
        let errs = [srv.url("boom"), format!("http://{gone}/x")]
            .map(|u| get(&mut f.remote, &u).unwrap_err());
        for e in &errs {
            let text = format!("{e} {e:?}");
            assert!(!text.contains(TOKEN) && !text.contains("Bearer"), "{text}");
        }
        assert!(
            errs[1]
                .to_string()
                .starts_with(&format!("http://{gone}/x: "))
        );
        let logged = String::from_utf8(LOGGED.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("boom"), "nothing was captured: {logged}");
        assert!(!logged.contains(TOKEN), "{logged}");
    }
}
