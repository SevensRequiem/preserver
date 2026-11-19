//! An https server on loopback that hands each request to `git http-backend`, so the mirror
//! tests fetch through the same TLS client, pipes and gix transport as against a real host.
#![cfg(unix)]

use crate::net::client::{loopback_agent, provider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use ureq::Agent;
use ureq::tls::{Certificate, RootCerts};

const CA: &[u8] = include_bytes!("../net/testdata/ca.der");
const LEAF: &[u8] = include_bytes!("../net/testdata/leaf.der");
const KEY: &[u8] = include_bytes!("../net/testdata/leaf.key.der");

#[derive(Debug, Clone)]
pub(crate) struct Hit {
    pub method: String,
    pub path: String,
    pub auth: Option<String>,
}

pub(crate) struct Cgi {
    pub addr: SocketAddr,
    hits: Arc<Mutex<Vec<Hit>>>,
}

/// An agent that trusts only the test CA.
pub(crate) fn agent() -> Agent {
    loopback_agent(RootCerts::new_with_certs(&[
        Certificate::from_der(CA).to_owned()
    ]))
}

impl Cgi {
    /// Serves the repos under `root`. With `auth` set, a request whose Authorization header is
    /// not exactly that value gets a 401.
    pub(crate) fn start(root: &Path, auth: Option<String>) -> Self {
        let cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(LEAF.to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec())),
            )
            .unwrap();
        let cfg = Arc::new(cfg);
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = ln.local_addr().unwrap();
        let hits = Arc::new(Mutex::new(Vec::new()));
        let (root, h) = (root.to_path_buf(), hits.clone());
        std::thread::spawn(move || {
            for sock in ln.incoming() {
                let Ok(sock) = sock else { return };
                let (cfg, root, auth, h) = (cfg.clone(), root.clone(), auth.clone(), h.clone());
                std::thread::spawn(move || {
                    // A client that hung up is the test's business, not the server's.
                    let _ = serve(sock, cfg, &root, auth.as_deref(), &h);
                });
            }
        });
        Self { addr, hits }
    }

    pub(crate) fn url(&self, repo: &str) -> String {
        format!("https://127.0.0.1:{}/{repo}", self.addr.port())
    }

    pub(crate) fn hits(&self) -> Vec<Hit> {
        self.hits.lock().unwrap().clone()
    }
}

fn serve(
    sock: TcpStream,
    cfg: Arc<rustls::ServerConfig>,
    root: &Path,
    auth: Option<&str>,
    hits: &Mutex<Vec<Hit>>,
) -> io::Result<()> {
    let conn = rustls::ServerConnection::new(cfg).map_err(io::Error::other)?;
    let mut tls = rustls::StreamOwned::new(conn, sock);
    let (method, target, headers, body) = {
        let mut r = BufReader::new(&mut tls);
        let mut line = String::new();
        r.read_line(&mut line)?;
        let mut words = line.split_whitespace();
        let method = words.next().unwrap_or_default().to_string();
        let target = words.next().unwrap_or_default().to_string();
        let mut headers = Vec::new();
        loop {
            let mut h = String::new();
            if r.read_line(&mut h)? == 0 || h.trim().is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }
        let header = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let len = header("content-length").map_or(0, |v| v.parse().unwrap_or(0));
        let mut body = vec![0; len];
        r.read_exact(&mut body)?;
        (method, target, headers, body)
    };
    let header = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let given = header("authorization");
    hits.lock().unwrap().push(Hit {
        method: method.clone(),
        path: path.to_string(),
        auth: given.clone(),
    });
    let reply = if auth.is_some_and(|a| given.as_deref() != Some(a)) {
        b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"t\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
    } else {
        backend(root, &method, path, query, &header, &body)?
    };
    tls.write_all(&reply)?;
    tls.conn.send_close_notify();
    tls.flush()
}

fn backend(
    root: &Path,
    method: &str,
    path: &str,
    query: &str,
    header: &dyn Fn(&str) -> Option<String>,
    body: &[u8],
) -> io::Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.arg("http-backend")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_PROJECT_ROOT", root)
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("REMOTE_ADDR", "127.0.0.1")
        .env("REQUEST_METHOD", method)
        .env("PATH_INFO", path)
        .env("QUERY_STRING", query)
        .env("CONTENT_LENGTH", body.len().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (var, h) in [
        ("CONTENT_TYPE", "content-type"),
        ("GIT_PROTOCOL", "git-protocol"),
    ] {
        if let Some(v) = header(h) {
            cmd.env(var, v);
        }
    }
    let mut child = cmd.spawn()?;
    let mut stdin = child.stdin.take().expect("piped");
    let out = std::thread::scope(|s| {
        s.spawn(move || stdin.write_all(body));
        child.wait_with_output()
    })?;
    let cgi = out.stdout;
    let (split, gap) = match cgi.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => (i, 4),
        None => (cgi.windows(2).position(|w| w == b"\n\n").unwrap_or(0), 2),
    };
    let head = String::from_utf8_lossy(&cgi[..split]);
    let data = &cgi[(split + gap).min(cgi.len())..];
    let mut status = "200 OK".to_string();
    let mut lines = String::new();
    for l in head.lines() {
        match l.split_once(':') {
            Some((k, v)) if k.eq_ignore_ascii_case("status") => status = v.trim().to_string(),
            Some(_) => {
                lines.push_str(l.trim_end());
                lines.push_str("\r\n");
            }
            None => {}
        }
    }
    let mut reply = format!(
        "HTTP/1.1 {status}\r\n{lines}Content-Length: {}\r\nConnection: close\r\n\r\n",
        data.len()
    )
    .into_bytes();
    reply.extend_from_slice(data);
    Ok(reply)
}
