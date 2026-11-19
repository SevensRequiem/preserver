use rustls::crypto::CryptoProvider;
use std::sync::Arc;
use std::time::Duration;
use ureq::Agent;
use ureq::tls::{RootCerts, TlsConfig, TlsProvider};

const USER_AGENT: &str = concat!("preserver/", env!("CARGO_PKG_VERSION"));

pub(crate) fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The OS trust store, or the embedded roots when the OS has none (a bare container, a rescue
/// system). Only Linux can fail here: the Windows and macOS verifiers load their roots per check.
pub(crate) fn os_roots() -> RootCerts {
    match rustls_platform_verifier::Verifier::new(provider()) {
        Ok(_) => RootCerts::PlatformVerifier,
        Err(e) => {
            tracing::warn!("OS trust store: {e}; using the embedded Mozilla roots");
            embedded_roots()
        }
    }
}

/// Mozilla's root store as of the pinned webpki-roots release, compiled in.
fn embedded_roots() -> RootCerts {
    RootCerts::WebPki
}

/// Every download runs on this config: https only, redirects included, and no phase without a
/// limit. The overall limit is set per request (`Downloader::timeout`), since it scales with
/// the size and the bandwidth cap. `loopback` (tests only) allows plain http and ignores the
/// environment's proxy.
fn build(roots: RootCerts, loopback: bool) -> Agent {
    let tls = TlsConfig::builder()
        .provider(TlsProvider::Rustls)
        .root_certs(roots)
        .unversioned_rustls_crypto_provider(provider())
        .build();
    let b = Agent::config_builder()
        .tls_config(tls)
        .https_only(true)
        .http_status_as_error(false)
        .user_agent(USER_AGENT)
        // Downloader follows redirects itself, so an error can name the hop that failed.
        .max_redirects(0)
        .timeout_resolve(Some(Duration::from_secs(15)))
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_response(Some(Duration::from_secs(60)))
        // A stalled connection (no bytes at all) fails fast; a slow one runs to the body limit.
        .timeout_per_read(Some(Duration::from_secs(60)))
        .timeout_per_write(Some(Duration::from_secs(60)));
    let b = if loopback {
        b.https_only(false).proxy(None)
    } else {
        b
    };
    b.build().new_agent()
}

pub(crate) fn agent(roots: RootCerts) -> Agent {
    build(roots, false)
}

#[cfg(test)]
pub(crate) fn loopback_agent(roots: RootCerts) -> Agent {
    build(roots, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use ureq::tls::Certificate;

    // A test CA and a leaf for 127.0.0.1 and localhost it signed (P-256, valid until 2125).
    // Made with openssl; testdata/gen.sh makes them.
    const CA: &[u8] = include_bytes!("testdata/ca.der");
    const LEAF: &[u8] = include_bytes!("testdata/leaf.der");
    const KEY: &[u8] = include_bytes!("testdata/leaf.key.der");

    /// Serves one TLS request with "hello" and returns the port.
    fn tls_server() -> u16 {
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
        let port = ln.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for sock in ln.incoming() {
                let Ok(sock) = sock else { return };
                let conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, sock);
                let mut req = Vec::new();
                let mut b = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut b) {
                        Ok(n) if n > 0 => req.extend_from_slice(&b[..n]),
                        _ => break,
                    }
                }
                let _ = tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                );
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
        });
        port
    }

    #[test]
    fn tls_with_a_custom_root() {
        let port = tls_server();
        let roots = RootCerts::new_with_certs(&[Certificate::from_der(CA).to_owned()]);
        let mut resp = loopback_agent(roots)
            .get(format!("https://127.0.0.1:{port}/x"))
            .call()
            .unwrap();
        assert_eq!(resp.body_mut().read_to_string().unwrap(), "hello");

        // The same server is refused under any other root, here the leaf's own cert.
        let other = RootCerts::new_with_certs(&[Certificate::from_der(LEAF).to_owned()]);
        let err = loopback_agent(other)
            .get(format!("https://127.0.0.1:{port}/x"))
            .call()
            .unwrap_err();
        assert!(err.to_string().contains("UnknownIssuer"), "{err}");
    }

    #[test]
    fn the_fallback_is_the_embedded_mozilla_store() {
        assert!(matches!(embedded_roots(), RootCerts::WebPki));
        assert!(webpki_roots::TLS_SERVER_ROOTS.len() > 50);
        // Wired, not a panic: the test CA is no Mozilla root, so the handshake is refused.
        let port = tls_server();
        let err = loopback_agent(embedded_roots())
            .get(format!("https://127.0.0.1:{port}/x"))
            .call()
            .unwrap_err();
        assert!(err.to_string().contains("UnknownIssuer"), "{err}");
    }

    #[test]
    fn plain_http_is_refused() {
        let err = agent(RootCerts::new_with_certs(&[]))
            .get("http://127.0.0.1:1/")
            .call()
            .unwrap_err();
        assert!(matches!(err, ureq::Error::RequireHttpsOnly(_)), "{err}");
    }
}
