//! A loopback CONNECT proxy for child processes (git, rsync), so their traffic shares the
//! download throttle. Any local user can reach 127.0.0.1, so a tunnel needs the run's
//! `Proxy-Authorization` value, only the ports those children use are tunnelled, only CONNECT
//! is spoken, and (unless `private_ok`) only to public addresses: the proxy must not be a way
//! onto loopback or the LAN for a confined local process.

use super::throttle::Throttle;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

/// https, rsync and git.
pub(crate) const CHILD_PORTS: [u16; 3] = [443, 873, 9418];
const HEAD_MAX: u64 = 8 << 10;
const MAX_TUNNELS: usize = 64;
/// A tunnel that moves nothing in this long is closed.
const IDLE: Duration = Duration::from_secs(300);

struct Rules {
    ports: Vec<u16>,
    /// The exact `Proxy-Authorization` header value a client must send.
    auth: String,
    private_ok: bool,
}

/// Not loopback, private, link-local, ULA, CGNAT, multicast or unspecified.
fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_loopback()
                || a.is_private()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_broadcast()
                || a.is_multicast()
                || (o[0] == 100 && o[1] & 0xc0 == 64))
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return public(IpAddr::V4(v4));
            }
            let first = a.segments()[0];
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80)
        }
    }
}

pub(crate) struct Proxy {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Proxy {
    /// Listens on `bind`, which must be a loopback address (port 0 picks one). `auth` is the
    /// `Proxy-Authorization` value every client must send; `private_ok` lifts the public-
    /// address rule (for tests against a local server).
    pub(crate) fn start(
        bind: SocketAddr,
        ports: &[u16],
        throttle: Arc<Throttle>,
        auth: String,
        private_ok: bool,
    ) -> io::Result<Self> {
        if !bind.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("proxy must bind a loopback address, not {bind}"),
            ));
        }
        let ln = TcpListener::bind(bind)?;
        let addr = ln.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let rules = Arc::new(Rules {
            ports: ports.to_vec(),
            auth,
            private_ok,
        });
        let live = Arc::new(AtomicUsize::new(0));
        let flag = stop.clone();
        std::thread::spawn(move || {
            for c in ln.incoming() {
                if flag.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(c) = c else { continue };
                if live.fetch_add(1, Ordering::SeqCst) >= MAX_TUNNELS {
                    live.fetch_sub(1, Ordering::SeqCst);
                    continue;
                }
                let (rules, t, live) = (rules.clone(), throttle.clone(), live.clone());
                std::thread::spawn(move || {
                    if let Err(e) = serve(&c, &rules, &t) {
                        tracing::debug!("proxy: {e}");
                    }
                    live.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        Ok(Self { addr, stop })
    }

    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wakes the accept loop so it sees the flag.
        let _ = TcpStream::connect(self.addr);
    }
}

fn serve(client: &TcpStream, rules: &Rules, throttle: &Throttle) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut writer = client.try_clone()?;
    let mut reader = BufReader::new(client.try_clone()?);
    let mut head = (&mut reader).take(HEAD_MAX);
    let mut line = String::new();
    head.read_line(&mut line)?;
    let mut authed = false;
    loop {
        let mut h = String::new();
        if head.read_line(&mut h)? == 0 {
            return Ok(());
        }
        if h.trim().is_empty() {
            break;
        }
        if let Some((name, value)) = h.split_once(':')
            && name.eq_ignore_ascii_case("proxy-authorization")
        {
            authed = value.trim() == rules.auth;
        }
    }
    let mut words = line.split_ascii_whitespace();
    let (Some(method), Some(target)) = (words.next(), words.next()) else {
        return writer.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
    };
    if !authed {
        return writer.write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n",
        );
    }
    if method != "CONNECT" {
        return writer.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n");
    }
    let allowed = target
        .rsplit_once(':')
        .filter(|(host, _)| !host.is_empty())
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .is_some_and(|p| rules.ports.contains(&p));
    if !allowed {
        return writer.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
    }
    let up = target.to_socket_addrs().ok().and_then(|addrs| {
        addrs
            .into_iter()
            .filter(|a| rules.private_ok || public(a.ip()))
            .find_map(|a| TcpStream::connect_timeout(&a, Duration::from_secs(15)).ok())
    });
    let Some(mut up) = up else {
        return writer.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
    };
    client.set_read_timeout(Some(IDLE))?;
    up.set_read_timeout(Some(IDLE))?;
    writer.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
    let mut up_r = up.try_clone()?;
    std::thread::scope(|s| {
        s.spawn(|| {
            pump(&mut up_r, &mut writer, throttle);
            let _ = client.shutdown(Shutdown::Both);
            let _ = up_r.shutdown(Shutdown::Both);
        });
        // The reader may already hold the start of the tunnel (a pipelined ClientHello).
        pump(&mut reader, &mut up, throttle);
        let _ = up.shutdown(Shutdown::Both);
        let _ = client.shutdown(Shutdown::Both);
    });
    Ok(())
}

fn pump(src: &mut impl Read, dst: &mut impl Write, t: &Throttle) {
    let mut buf = vec![0u8; 16 << 10];
    while let Ok(n) = src.read(&mut buf) {
        if n == 0 {
            return;
        }
        t.take(n);
        if dst.write_all(&buf[..n]).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    const AUTH: &str = "Basic dGVzdDpzZWNyZXQ=";

    fn connect(p: &Proxy, target: &str) -> (TcpStream, String) {
        connect_as(p, target, Some(AUTH))
    }

    fn connect_as(p: &Proxy, target: &str, auth: Option<&str>) -> (TcpStream, String) {
        let mut c = TcpStream::connect(p.addr()).unwrap();
        let auth = auth.map_or(String::new(), |a| format!("Proxy-Authorization: {a}\r\n"));
        write!(
            c,
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n"
        )
        .unwrap();
        let mut r = BufReader::new(c.try_clone().unwrap());
        let mut status = String::new();
        r.read_line(&mut status).unwrap();
        let mut blank = String::new();
        r.read_line(&mut blank).unwrap();
        (c, status)
    }

    #[test]
    fn refuses_other_ports_methods_and_non_loopback_binds() {
        let t = Arc::new(Throttle::new(0));
        for bind in ["0.0.0.0:0", "[::]:0"] {
            let err = Proxy::start(
                bind.parse().unwrap(),
                &CHILD_PORTS,
                t.clone(),
                AUTH.into(),
                false,
            )
            .err();
            assert_eq!(
                err.map(|e| e.kind()),
                Some(io::ErrorKind::InvalidInput),
                "{bind}"
            );
        }
        let p = Proxy::start(
            "127.0.0.1:0".parse().unwrap(),
            &CHILD_PORTS,
            t,
            AUTH.into(),
            false,
        )
        .unwrap();
        assert!(p.addr().ip().is_loopback());
        for target in [
            "127.0.0.1:22",
            "127.0.0.1:80",
            "example.invalid:8443",
            ":443",
            "x",
        ] {
            assert!(connect(&p, target).1.contains(" 403 "), "{target}");
        }
        let mut c = TcpStream::connect(p.addr()).unwrap();
        write!(
            c,
            "GET http://127.0.0.1:443/ HTTP/1.1\r\nProxy-Authorization: {AUTH}\r\n\r\n"
        )
        .unwrap();
        let mut resp = String::new();
        BufReader::new(c).read_line(&mut resp).unwrap();
        assert!(resp.contains(" 405 "), "{resp}");
    }

    #[test]
    fn needs_the_run_token_and_a_public_destination() {
        let p = Proxy::start(
            "127.0.0.1:0".parse().unwrap(),
            &CHILD_PORTS,
            Arc::new(Throttle::new(0)),
            AUTH.into(),
            false,
        )
        .unwrap();
        for auth in [None, Some("Basic d3Jvbmc=")] {
            assert!(
                connect_as(&p, "93.184.216.34:443", auth)
                    .1
                    .contains(" 407 "),
                "{auth:?}"
            );
        }
        for target in [
            "127.0.0.1:443",
            "[::1]:873",
            "192.168.1.1:443",
            "[fd00::1]:443",
        ] {
            assert!(connect(&p, target).1.contains(" 502 "), "{target}");
        }
        for ip in [
            "10.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "::ffff:127.0.0.1",
            "fe80::1",
        ] {
            assert!(!public(ip.parse().unwrap()), "{ip}");
        }
        assert!(public("93.184.216.34".parse().unwrap()));
        assert!(public("2606:4700::1111".parse().unwrap()));
    }

    #[test]
    fn tunnels_an_allowed_port_through_the_bucket() {
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = up.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = up.accept().unwrap();
            let mut hello = [0u8; 5];
            s.read_exact(&mut hello).unwrap();
            assert_eq!(&hello, b"hello");
            s.write_all(&vec![7u8; 2 << 20]).unwrap();
        });
        let p = Proxy::start(
            "127.0.0.1:0".parse().unwrap(),
            &[port],
            Arc::new(Throttle::new(4 << 20)),
            AUTH.into(),
            true,
        )
        .unwrap();
        let start = Instant::now();
        let (mut c, status) = connect(&p, &format!("127.0.0.1:{port}"));
        assert!(status.contains(" 200 "), "{status}");
        c.write_all(b"hello").unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).unwrap();
        assert_eq!(got.len(), 2 << 20);
        // 2 MiB through a 4 MiB/s bucket.
        let secs = start.elapsed().as_secs_f64();
        assert!((0.45..1.0).contains(&secs), "{secs}");
    }
}
