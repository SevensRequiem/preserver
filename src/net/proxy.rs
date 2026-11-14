//! A loopback CONNECT proxy for child processes (git, rsync), so their traffic shares the
//! download throttle. Any local user can reach 127.0.0.1, so only the ports those children use
//! are tunnelled, and only CONNECT is spoken.

use super::throttle::Throttle;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// https, rsync and git.
pub(crate) const CHILD_PORTS: [u16; 3] = [443, 873, 9418];
const HEAD_MAX: u64 = 8 << 10;

pub(crate) struct Proxy {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Proxy {
    /// Listens on `bind`, which must be a loopback address (port 0 picks one).
    pub(crate) fn start(
        bind: SocketAddr,
        ports: &[u16],
        throttle: Arc<Throttle>,
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
        let ports: Arc<[u16]> = ports.into();
        let flag = stop.clone();
        std::thread::spawn(move || {
            for c in ln.incoming() {
                if flag.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(c) = c else { continue };
                let (ports, t) = (ports.clone(), throttle.clone());
                std::thread::spawn(move || {
                    if let Err(e) = serve(&c, &ports, &t) {
                        tracing::debug!("proxy: {e}");
                    }
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

fn serve(client: &TcpStream, ports: &[u16], throttle: &Throttle) -> io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut writer = client.try_clone()?;
    let mut reader = BufReader::new(client.try_clone()?);
    let mut head = (&mut reader).take(HEAD_MAX);
    let mut line = String::new();
    head.read_line(&mut line)?;
    loop {
        let mut h = String::new();
        if head.read_line(&mut h)? == 0 {
            return Ok(());
        }
        if h.trim().is_empty() {
            break;
        }
    }
    let mut words = line.split_ascii_whitespace();
    let (Some(method), Some(target)) = (words.next(), words.next()) else {
        return writer.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
    };
    if method != "CONNECT" {
        return writer.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n");
    }
    let allowed = target
        .rsplit_once(':')
        .filter(|(host, _)| !host.is_empty())
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .is_some_and(|p| ports.contains(&p));
    if !allowed {
        return writer.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
    }
    let up = target.to_socket_addrs().ok().and_then(|addrs| {
        addrs
            .into_iter()
            .find_map(|a| TcpStream::connect_timeout(&a, Duration::from_secs(15)).ok())
    });
    let Some(mut up) = up else {
        return writer.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
    };
    client.set_read_timeout(None)?;
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

    fn connect(p: &Proxy, target: &str) -> (TcpStream, String) {
        let mut c = TcpStream::connect(p.addr()).unwrap();
        write!(c, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").unwrap();
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
            let err = Proxy::start(bind.parse().unwrap(), &CHILD_PORTS, t.clone()).err();
            assert_eq!(
                err.map(|e| e.kind()),
                Some(io::ErrorKind::InvalidInput),
                "{bind}"
            );
        }
        let p = Proxy::start("127.0.0.1:0".parse().unwrap(), &CHILD_PORTS, t).unwrap();
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
        c.write_all(b"GET http://127.0.0.1:443/ HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        BufReader::new(c).read_line(&mut resp).unwrap();
        assert!(resp.contains(" 405 "), "{resp}");
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
