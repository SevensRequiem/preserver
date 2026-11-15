//! Resumable downloads into `<dest>.part`, with the hash state in `<dest>.part.json`.
//!
//! Invariant: whenever the sidecar exists, the first `offset` bytes of the part are on disk
//! (`sync_data` comes before the sidecar's rename) and `sha256`/`sha512` are the midstates of
//! exactly those bytes. A resume truncates the part to `offset`, restores the hashers and asks
//! for the rest with `If-Range`, so a changed file comes back as a 200 and starts over.

use super::hash::{Resumable, S256, S512};
use super::throttle::Throttle;
use crate::resolve::listing::join;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use ureq::http::HeaderMap;
use ureq::{Agent, RequestBuilder, typestate::WithoutBody};

/// Download threads per worker.
pub(crate) const STREAMS: usize = 4;
pub(crate) const CHECKPOINT: u64 = 64 << 20;
const MAX_REDIRECTS: usize = 10;
const CHUNK: usize = 64 << 10;
const SIDECAR_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expect {
    None,
    Sha256([u8; 32]),
    Sha512([u8; 64]),
    Both([u8; 32], [u8; 64]),
}

#[derive(Debug, Clone)]
pub(crate) struct Fetch {
    pub url: String,
    /// The final name; its directory must exist (the staging dir on the drive). It is never
    /// created here, so a vanished mount point fails instead of filling the host's disk.
    pub dest: PathBuf,
    pub size: Option<u64>,
    /// The most a body of unknown size may grow to: the transfer stops and drops its part
    /// past it. A known `size` is the limit instead.
    pub limit: u64,
    pub expect: Expect,
}

impl Fetch {
    pub(crate) fn part(&self) -> PathBuf {
        suffixed(&self.dest, ".part")
    }

    pub(crate) fn sidecar(&self) -> PathBuf {
        suffixed(&self.dest, ".part.json")
    }

    /// The URL's host name, lower case, without user info or port: the per-host limit's key.
    pub(crate) fn host(&self) -> String {
        let rest = self.url.split_once("://").map_or("", |(_, r)| r);
        let auth = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let auth = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
        let host = match auth.strip_prefix('[') {
            Some(v6) => v6.split(']').next().unwrap_or_default(),
            None => auth.split(':').next().unwrap_or_default(),
        };
        host.to_ascii_lowercase()
    }
}

fn suffixed(p: &Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(suffix);
    s.into()
}

#[derive(Debug)]
pub(crate) enum Fail {
    /// Worth another try after the backoff; `after` is the server's Retry-After. `progressed`:
    /// this call saved a checkpoint past where it started, so it was no wasted try.
    Retry {
        msg: String,
        after: Option<Duration>,
        progressed: bool,
    },
    Permanent(String),
    /// A local file operation failed: the drive may be gone.
    Disk(io::Error),
    /// The stop flag was raised (pause, cancel, unplug elsewhere).
    Stopped,
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retry { msg, .. } | Self::Permanent(msg) => f.write_str(msg),
            Self::Disk(e) => write!(f, "write: {e}"),
            Self::Stopped => f.write_str("stopped"),
        }
    }
}

fn retry(msg: impl Into<String>) -> Fail {
    Fail::Retry {
        msg: msg.into(),
        after: None,
        progressed: false,
    }
}

/// `url`, or `url via hop` when a redirect led elsewhere. The hop's query is left out: a
/// mirror or CDN puts signatures there.
fn via(url: &str, at: &str) -> String {
    let hop = at.split(['?', '#']).next().unwrap_or(at);
    if at == url {
        url.to_string()
    } else {
        format!("{url} via {hop}")
    }
}

impl Fail {
    /// Puts where it happened in front of the message.
    fn at(self, at: &str) -> Self {
        match self {
            Self::Retry {
                msg,
                after,
                progressed,
            } => Self::Retry {
                msg: format!("{at}: {msg}"),
                after,
                progressed,
            },
            Self::Permanent(msg) => Self::Permanent(format!("{at}: {msg}")),
            other => other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Validator {
    Etag(String),
    LastModified(String),
}

impl Validator {
    /// A strong `ETag`, else `Last-Modified`. A weak `ETag` can't be used in `If-Range`.
    fn from_headers(h: &HeaderMap) -> Option<Self> {
        let get = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).map(str::to_string);
        get("etag")
            .filter(|e| !e.starts_with("W/"))
            .map(Self::Etag)
            .or_else(|| get("last-modified").map(Self::LastModified))
    }

    fn value(&self) -> &str {
        match self {
            Self::Etag(v) | Self::LastModified(v) => v,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PartState {
    v: u8,
    url: String,
    validator: Validator,
    offset: u64,
    total: u64,
    sha256: [u32; 8],
    sha512: Option<[u64; 8]>,
}

struct Part {
    file: File,
    offset: u64,
    /// The offset the sidecar records.
    saved: u64,
    total: Option<u64>,
    validator: Option<Validator>,
    h256: Resumable<S256>,
    h512: Option<Resumable<S512>>,
}

impl Part {
    fn reset(&mut self, side: &Path, done: &AtomicU64) -> Result<(), Fail> {
        remove(side)?;
        self.file.set_len(0).map_err(Fail::Disk)?;
        self.file.seek(SeekFrom::Start(0)).map_err(Fail::Disk)?;
        done.fetch_sub(self.offset, Ordering::Relaxed);
        self.offset = 0;
        self.saved = 0;
        self.total = None;
        self.validator = None;
        self.h256 = Resumable::new();
        if self.h512.is_some() {
            self.h512 = Some(Resumable::new());
        }
        Ok(())
    }
}

fn remove(p: &Path) -> Result<(), Fail> {
    match std::fs::remove_file(p) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(Fail::Disk(e)),
        _ => Ok(()),
    }
}

/// `bytes a-b/n` with a known total.
fn content_range(h: &HeaderMap) -> Option<(u64, u64, u64)> {
    let v = h
        .get("content-range")?
        .to_str()
        .ok()?
        .strip_prefix("bytes ")?;
    let (range, total) = v.split_once('/')?;
    let (first, last) = range.split_once('-')?;
    let (first, last, total) = (first.parse().ok()?, last.parse().ok()?, total.parse().ok()?);
    (first <= last && last < total).then_some((first, last, total))
}

fn retry_after(h: &HeaderMap) -> Option<Duration> {
    let secs: u64 = h.get("retry-after")?.to_str().ok()?.trim().parse().ok()?;
    Some(Duration::from_secs(secs.min(600)))
}

pub(crate) struct Downloader {
    agent: Agent,
    throttle: Arc<Throttle>,
    /// Bytes between checkpoints; a multiple of 128 (the SHA-512 block).
    checkpoint: u64,
}

impl Downloader {
    pub(crate) fn new(agent: Agent, throttle: Arc<Throttle>, checkpoint: u64) -> Self {
        assert_eq!(
            checkpoint % 128,
            0,
            "checkpoints must sit on hash block boundaries"
        );
        Self {
            agent,
            throttle,
            checkpoint,
        }
    }

    /// Time allowed for a body of `bytes`: ten minutes plus the bytes at the slowest rate a
    /// healthy stream runs, which is 64 KiB/s or its share of a tighter bandwidth cap.
    fn timeout(&self, bytes: Option<u64>) -> Duration {
        let cap = self.throttle.bytes_per_sec();
        #[expect(clippy::cast_precision_loss, reason = "a rate")]
        let share = cap / (2 * STREAMS) as f64;
        let floor = if cap > 0.0 {
            share.min(65536.0)
        } else {
            65536.0
        };
        #[expect(clippy::cast_precision_loss, reason = "a duration estimate")]
        let body = bytes.map_or(86_400.0, |b| b as f64 / floor);
        Duration::from_secs(600) + Duration::from_secs_f64(body)
    }

    /// The rest of the file from `part.offset` when `ranged`, else the whole file: one request
    /// per attempt, since a mirror may throttle or drop a client that keeps reconnecting.
    /// Returns the response, the hop that gave it and the bytes its timeout was sized for.
    fn request(
        &self,
        f: &Fetch,
        part: &Part,
        ranged: bool,
    ) -> Result<(ureq::http::Response<ureq::Body>, String, Option<u64>), Fail> {
        let mut headers = Vec::new();
        let mut want = f.size;
        if ranged {
            want = part.total.or(f.size).map(|t| t - part.offset);
            headers.push(("Range", format!("bytes={}-", part.offset)));
            if let (true, Some(v)) = (part.offset > 0, &part.validator) {
                headers.push(("If-Range", v.value().to_string()));
            }
        }
        let (resp, hop) = Self::call(&f.url, self.timeout(want), |hop| {
            headers
                .iter()
                .fold(self.agent.get(hop), |r, (k, v)| r.header(*k, v))
        })
        .map_err(|(again, msg)| {
            if again {
                retry(msg)
            } else {
                Fail::Permanent(msg)
            }
        })?;
        Ok((resp, hop, want))
    }

    /// Downloads `f` to its `.part`, verifies it and renames it to `dest`. `stop` is checked
    /// between 64 KiB chunks; `done` counts bytes on disk for progress.
    pub(crate) fn fetch(&self, f: &Fetch, stop: &AtomicBool, done: &AtomicU64) -> Result<(), Fail> {
        let side = f.sidecar();
        let mut part = Self::open(f, &side)?;
        // This call's share of `done` is always `part.offset` (open, copy and reset keep it so).
        // A failed call takes its share back, since the retry's open counts the resumed bytes
        // again. A stop ends the run, and its count is what the paused job shows.
        done.fetch_add(part.offset, Ordering::Relaxed);
        let start = part.saved;
        let mut r = self.transfer(f, &mut part, &side, stop, done);
        if let Err(Fail::Retry { progressed, .. }) = &mut r {
            *progressed = part.saved > start;
        }
        if matches!(r, Err(Fail::Permanent(_))) {
            remove(&f.part())?;
            remove(&side)?;
        }
        let share = part.offset;
        let r = r.and_then(|()| Self::finish(f, part, &side));
        if let Err(e) = &r
            && !matches!(e, Fail::Stopped)
        {
            done.fetch_sub(share, Ordering::Relaxed);
        }
        r
    }

    fn transfer(
        &self,
        f: &Fetch,
        part: &mut Part,
        side: &Path,
        stop: &AtomicBool,
        done: &AtomicU64,
    ) -> Result<(), Fail> {
        // False once the server has shown it can't be resumed: then one plain GET, no checkpoints.
        let mut ranged = true;
        let mut restarts = 0;
        loop {
            if part.total == Some(part.offset) {
                break;
            }
            let (resp, hop, want) = self.request(f, part, ranged)?;
            let at = via(&f.url, &hop);
            let status = resp.status().as_u16();
            let head = resp.headers().clone();
            let mut body = resp.into_body().into_reader();
            match status {
                206 if ranged => {
                    let validator = Validator::from_headers(&head);
                    let Some((first, last, total)) = content_range(&head) else {
                        // No usable Content-Range (or an unknown total): resuming is guesswork.
                        part.reset(side, done)?;
                        ranged = false;
                        continue;
                    };
                    // Without a validator, segments of two versions could be spliced.
                    if first != part.offset || (part.offset == 0 && validator.is_none()) {
                        part.reset(side, done)?;
                        ranged = false;
                        continue;
                    }
                    // A new version behind a server that ignored If-Range: start it over.
                    if part.offset > 0 && (validator != part.validator || part.total != Some(total))
                    {
                        restarts += 1;
                        if restarts > 2 {
                            return Err(retry(format!("{at}: server keeps changing")));
                        }
                        part.reset(side, done)?;
                        continue;
                    }
                    if let Some(s) = f.size.filter(|s| *s != total) {
                        return Err(retry(format!("{at}: {total} bytes, expected {s}")));
                    }
                    part.validator = validator;
                    part.total = Some(total);
                    // A server may send less than asked; the loop asks again from there.
                    let mut left = last - first + 1;
                    while left > 0 {
                        let n = left.min(self.checkpoint);
                        self.copy(&mut body, part, Some(n), f, stop, done)
                            .map_err(|e| e.at(&at))?;
                        left -= n;
                        if part.offset < total {
                            Self::checkpoint(f, part, side)?;
                        }
                    }
                }
                200 => {
                    if part.offset > 0 {
                        part.reset(side, done)?;
                    }
                    let len: Option<u64> = head
                        .get("content-length")
                        .and_then(|v| v.to_str().ok()?.parse().ok());
                    if let (Some(s), Some(n)) = (f.size, len)
                        && s != n
                    {
                        return Err(retry(format!("{at}: {n} bytes, expected {s}")));
                    }
                    // A ranged request's timeout covers the bytes it asked for. A server that
                    // ignores Range sends the whole file, which gets a plain GET timed by its size.
                    if ranged && want.is_some_and(|w| len.is_none_or(|n| n > w)) {
                        ranged = false;
                        continue;
                    }
                    self.copy(&mut body, part, len, f, stop, done)
                        .map_err(|e| e.at(&at))?;
                    if let Some(s) = f.size.filter(|s| part.offset > *s) {
                        return Err(retry(format!("{at}: more than the expected {s} bytes")));
                    }
                    break;
                }
                416 if ranged && part.offset == 0 => ranged = false,
                416 => {
                    part.reset(side, done)?;
                    return Err(retry(format!("{at}: range rejected, restarting")));
                }
                408 | 429 | 500..=599 => {
                    return Err(Fail::Retry {
                        msg: format!("{at}: HTTP {status}"),
                        after: retry_after(&head),
                        progressed: false,
                    });
                }
                _ => return Err(Fail::Permanent(format!("{at}: HTTP {status}"))),
            }
        }
        Ok(())
    }

    /// Opens the part, resuming from its sidecar when the sidecar fits; anything else restarts.
    fn open(f: &Fetch, side: &Path) -> Result<Part, Fail> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(f.part())
            .map_err(Fail::Disk)?;
        let len = file.metadata().map_err(Fail::Disk)?.len();
        let wants512 = matches!(f.expect, Expect::Sha512(_) | Expect::Both(..));
        let mut p = Part {
            file,
            offset: 0,
            saved: 0,
            total: None,
            validator: None,
            h256: Resumable::new(),
            h512: wants512.then(Resumable::new),
        };
        let st = std::fs::read(side)
            .ok()
            .and_then(|b| serde_json::from_slice::<PartState>(&b).ok())
            .filter(|st| {
                st.v == SIDECAR_VERSION
                    && st.url == f.url
                    && st.offset <= len
                    && st.offset < st.total
                    && st.offset % 128 == 0
                    && st.sha512.is_some() == wants512
            });
        match st {
            Some(st) => {
                p.offset = st.offset;
                p.saved = st.offset;
                p.total = Some(st.total);
                p.validator = Some(st.validator);
                p.h256 = Resumable::resume(st.sha256, st.offset);
                p.h512 = st.sha512.map(|s| Resumable::resume(s, st.offset));
            }
            // No (usable) sidecar: nothing proves what the bytes are.
            None => remove(side)?,
        }
        p.file.set_len(p.offset).map_err(Fail::Disk)?;
        p.file.seek(SeekFrom::Start(p.offset)).map_err(Fail::Disk)?;
        Ok(p)
    }

    /// Copies the body into the part: exactly `exact` bytes when given, else to EOF. Errors
    /// carry no URL; the caller knows which hop sent the body.
    fn copy(
        &self,
        body: &mut impl Read,
        p: &mut Part,
        exact: Option<u64>,
        f: &Fetch,
        stop: &AtomicBool,
        done: &AtomicU64,
    ) -> Result<(), Fail> {
        let cap = f.size.unwrap_or(f.limit);
        let mut buf = vec![0u8; CHUNK];
        let mut got = 0u64;
        loop {
            // Relaxed: the flag carries no data, it only has to be seen within a chunk or so.
            if stop.load(Ordering::Relaxed) {
                return Err(Fail::Stopped);
            }
            let room = exact.map_or(CHUNK, |e| {
                usize::try_from((e - got).min(CHUNK as u64)).unwrap_or(CHUNK)
            });
            if room == 0 {
                return Ok(());
            }
            let n = body
                .read(&mut buf[..room])
                .map_err(|e| retry(format!("read: {e}")))?;
            if n == 0 {
                return match exact {
                    Some(e) if got < e => Err(retry(format!("body ended at {got} of {e} bytes"))),
                    _ => Ok(()),
                };
            }
            self.throttle.take(n);
            p.file.write_all(&buf[..n]).map_err(Fail::Disk)?;
            p.h256.update(&buf[..n]);
            if let Some(h) = &mut p.h512 {
                h.update(&buf[..n]);
            }
            got += n as u64;
            p.offset += n as u64;
            done.fetch_add(n as u64, Ordering::Relaxed);
            if p.offset > cap {
                return Err(Fail::Permanent(format!(
                    "body is larger than the {cap} bytes allowed"
                )));
            }
        }
    }

    /// Makes the bytes so far durable, then records them: sync the data, write the sidecar's
    /// tmp, sync it, rename. A crash anywhere leaves the old sidecar or the new one, both true.
    fn checkpoint(f: &Fetch, p: &mut Part, side: &Path) -> Result<(), Fail> {
        let (Some((sha256, _)), Some(validator), Some(total)) =
            (p.h256.midstate(), &p.validator, p.total)
        else {
            return Ok(());
        };
        let st = PartState {
            v: SIDECAR_VERSION,
            url: f.url.clone(),
            validator: validator.clone(),
            offset: p.offset,
            total,
            sha256,
            sha512: p.h512.as_ref().and_then(Resumable::midstate).map(|m| m.0),
        };
        p.file.sync_data().map_err(Fail::Disk)?;
        let tmp = suffixed(side, ".tmp");
        let json = serde_json::to_vec(&st).map_err(|e| Fail::Permanent(e.to_string()))?;
        let mut t = File::create(&tmp).map_err(Fail::Disk)?;
        t.write_all(&json).map_err(Fail::Disk)?;
        t.sync_data().map_err(Fail::Disk)?;
        std::fs::rename(&tmp, side).map_err(Fail::Disk)?;
        p.saved = p.offset;
        Ok(())
    }

    fn finish(f: &Fetch, p: Part, side: &Path) -> Result<(), Fail> {
        if let Some(s) = f.size.filter(|s| *s != p.offset) {
            return Err(retry(format!(
                "{}: {} bytes, expected {s}",
                f.url, p.offset
            )));
        }
        let sha256 = p.h256.finish();
        let sha512 = p.h512.map(Resumable::finish);
        let ok = match &f.expect {
            Expect::None => true,
            Expect::Sha256(w) => sha256 == w,
            Expect::Sha512(w) => sha512.as_deref() == Some(w),
            Expect::Both(a, b) => sha256 == a && sha512.as_deref() == Some(b),
        };
        if !ok {
            remove(side)?;
            remove(&f.part())?;
            return Err(retry(format!("{}: checksum mismatch", f.url)));
        }
        p.file.sync_data().map_err(Fail::Disk)?;
        drop(p.file);
        std::fs::rename(f.part(), &f.dest).map_err(Fail::Disk)?;
        remove(&suffixed(side, ".tmp"))?;
        remove(side)
    }

    /// One request for a document or its headers: a 200 or an error, with whether to try again.
    fn doc(
        &self,
        url: &str,
        head: bool,
    ) -> Result<ureq::http::Response<ureq::Body>, (bool, String)> {
        let github = url.starts_with("https://api.github.com/");
        let (resp, at) = Self::call(url, Duration::from_secs(120), |hop| {
            let req = if head {
                self.agent.head(hop)
            } else {
                self.agent.get(hop)
            };
            if github {
                req.header("Accept", "application/vnd.github+json")
            } else {
                req
            }
        })?;
        match resp.status().as_u16() {
            200 => Ok(resp),
            s => Err((
                matches!(s, 408 | 429 | 500..=599),
                format!("{}: HTTP {s}", via(url, &at)),
            )),
        }
    }

    /// Asks for `url` and follows its redirects here, since the agent follows none: an error
    /// then names the hop that failed (typically the mirror a download host picked), not only
    /// the URL asked for. Returns the response and the URL that gave it.
    fn call(
        url: &str,
        timeout: Duration,
        req: impl Fn(&str) -> RequestBuilder<WithoutBody>,
    ) -> Result<(ureq::http::Response<ureq::Body>, String), (bool, String)> {
        let mut at = url.to_string();
        for _ in 0..=MAX_REDIRECTS {
            let resp = req(&at)
                .config()
                .timeout_global(Some(timeout))
                .build()
                .call()
                .map_err(|e| {
                    let again =
                        !matches!(e, ureq::Error::BadUri(_) | ureq::Error::RequireHttpsOnly(_));
                    (again, format!("{}: {e}", via(url, &at)))
                })?;
            if !matches!(resp.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                return Ok((resp, at));
            }
            let next = resp
                .headers()
                .get("location")
                .and_then(|l| l.to_str().ok())
                .and_then(|l| join(&at, l));
            let Some(n) = next else {
                let s = resp.status().as_u16();
                return Err((
                    false,
                    format!("{}: HTTP {s} without a usable Location", via(url, &at)),
                ));
            };
            at = n;
        }
        Err((
            false,
            format!("{}: more than {MAX_REDIRECTS} redirects", via(url, &at)),
        ))
    }

    fn doc_retried(
        &self,
        url: &str,
        head: bool,
    ) -> anyhow::Result<ureq::http::Response<ureq::Body>> {
        let mut tries = 0;
        loop {
            match self.doc(url, head) {
                Ok(r) => return Ok(r),
                Err((again, msg)) if again && tries < 2 => {
                    tries += 1;
                    tracing::info!("{msg}; retrying");
                    std::thread::sleep(Duration::from_secs(2 * tries));
                }
                Err((_, msg)) => anyhow::bail!(msg),
            }
        }
    }

    /// A small document (an index, an API answer, a key) of at most `limit` bytes. It goes
    /// through the bandwidth bucket like every other body.
    pub(crate) fn get(&self, url: &str, limit: u64) -> anyhow::Result<Vec<u8>> {
        let mut body = self
            .doc_retried(url, false)?
            .into_body()
            .into_reader()
            .take(limit + 1);
        let mut out = Vec::new();
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = body
                .read(&mut buf)
                .map_err(|e| anyhow::anyhow!("{url}: {e}"))?;
            if n == 0 {
                break;
            }
            self.throttle.take(n);
            out.extend_from_slice(&buf[..n]);
        }
        if out.len() as u64 > limit {
            anyhow::bail!("{url}: larger than {limit} bytes");
        }
        Ok(out)
    }

    pub(crate) fn head(&self, url: &str) -> anyhow::Result<HeaderMap> {
        Ok(self.doc_retried(url, true)?.headers().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::client::loopback_agent;
    use crate::net::testserver::{Behaviour, Server, body};
    use crate::testutil::TempDir;
    use sha2::Digest;
    use std::time::Instant;
    use ureq::tls::RootCerts;

    const CP: u64 = 1 << 20;

    fn dl(rate: u64) -> Downloader {
        Downloader::new(
            loopback_agent(RootCerts::new_with_certs(&[])),
            Arc::new(Throttle::new(rate)),
            CP,
        )
    }

    fn fetch(srv: &Server, dir: &Path, name: &str, data: &[u8]) -> Fetch {
        Fetch {
            url: srv.url(name),
            dest: dir.join(name),
            size: Some(data.len() as u64),
            limit: u64::MAX,
            expect: Expect::Both(
                sha2::Sha256::digest(data).into(),
                sha2::Sha512::digest(data).into(),
            ),
        }
    }

    fn sidecar(f: &Fetch) -> PartState {
        serde_json::from_slice(&std::fs::read(f.sidecar()).unwrap()).unwrap()
    }

    /// Runs `f` once with a server that drops the connection at 2.5 MiB, leaving a part whose
    /// last checkpoint is 2 MiB, plus trailing junk such as a killed process leaves. The
    /// failed call gives back what it added to `done`.
    fn interrupted(srv: &Server, d: &Downloader, f: &Fetch, done: &AtomicU64) {
        srv.set(|b| b.die_at = Some(5 * CP / 2));
        let err = d.fetch(f, &AtomicBool::new(false), done).unwrap_err();
        assert!(
            matches!(
                err,
                Fail::Retry {
                    progressed: true,
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(done.load(Ordering::Relaxed), 0);
        assert_eq!(sidecar(f).offset, 2 * CP);
        let mut part = OpenOptions::new().append(true).open(f.part()).unwrap();
        part.write_all(b"junk past the checkpoint").unwrap();
        srv.clear_log();
    }

    #[test]
    fn resumes_from_the_last_checkpoint() {
        let tmp = TempDir::new();
        let data = body(5 * CP + 12_345, 1);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        let d = dl(0);
        let f = fetch(&srv, tmp.path(), "a.iso", &data);
        // One counter for both calls, as the worker's pool shares one across retries.
        let done = AtomicU64::new(0);
        interrupted(&srv, &d, &f, &done);

        d.fetch(&f, &AtomicBool::new(false), &done).unwrap();
        assert_eq!(std::fs::read(&f.dest).unwrap(), data);
        assert!(!f.part().exists() && !f.sidecar().exists());
        // The rest in one request, checkpointed as it arrives.
        let hits = srv.hits();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].range.as_deref(), Some("bytes=2097152-"));
        assert_eq!(hits[0].if_range.as_deref(), Some("\"v1\""));
        // Only the missing 3 MiB came over the wire again.
        assert_eq!(srv.served(), data.len() as u64 - 2 * CP);
        assert_eq!(done.load(Ordering::Relaxed), data.len() as u64);
    }

    #[test]
    fn a_body_past_the_limit_is_cut_off_and_dropped() {
        let tmp = TempDir::new();
        let data = body(3 * CP, 5);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        srv.set(|b| b.ranges = false);
        let f = Fetch {
            size: None,
            limit: CP / 2,
            expect: Expect::None,
            ..fetch(&srv, tmp.path(), "big.bin", &data)
        };
        let err = d_fetch(&f).unwrap_err();
        assert!(matches!(err, Fail::Permanent(_)), "{err}");
        assert!(!f.part().exists() && !f.sidecar().exists() && !f.dest.exists());
    }

    fn d_fetch(f: &Fetch) -> Result<(), Fail> {
        dl(0).fetch(f, &AtomicBool::new(false), &AtomicU64::new(0))
    }

    #[test]
    fn server_ignoring_range_restarts_from_zero() {
        let tmp = TempDir::new();
        let data = body(3 * CP + 7, 2);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        let d = dl(0);
        let f = fetch(&srv, tmp.path(), "b.tar", &data);
        let done = AtomicU64::new(0);
        interrupted(&srv, &d, &f, &done);

        srv.set(|b| b.ranges = false);
        d.fetch(&f, &AtomicBool::new(false), &done).unwrap();
        assert_eq!(std::fs::read(&f.dest).unwrap(), data);
        // The whole file in answer to a request for the rest is not read under that request's
        // timeout: it is asked for again with a plain GET.
        let hits = srv.hits();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].range.as_deref(), Some("bytes=2097152-"));
        assert_eq!(hits[0].status, 200);
        assert_eq!((hits[1].range.as_deref(), hits[1].status), (None, 200));
        assert_eq!(done.load(Ordering::Relaxed), data.len() as u64);
    }

    #[test]
    fn changed_etag_restarts_from_zero() {
        let tmp = TempDir::new();
        let old = body(3 * CP, 3);
        let new = body(3 * CP + 99, 4);
        let srv = Server::start("127.0.0.1", Behaviour::new(old.clone()));
        let d = dl(0);
        let f = fetch(&srv, tmp.path(), "c.img", &old);
        interrupted(&srv, &d, &f, &AtomicU64::new(0));

        srv.set(|b| {
            b.body.clone_from(&new);
            b.etag = Some("\"v2\"".into());
        });
        let f = fetch(&srv, tmp.path(), "c.img", &new);
        d.fetch(&f, &AtomicBool::new(false), &AtomicU64::new(0))
            .unwrap();
        assert_eq!(std::fs::read(&f.dest).unwrap(), new);
        let hits = srv.hits();
        assert_eq!(hits[0].if_range.as_deref(), Some("\"v1\""));
        assert_eq!(
            hits[0].status, 200,
            "If-Range mismatch sends the whole file"
        );
    }

    #[test]
    fn changed_etag_in_a_206_restarts_too() {
        let tmp = TempDir::new();
        let old = body(3 * CP, 5);
        let new = body(3 * CP, 6);
        let srv = Server::start("127.0.0.1", Behaviour::new(old.clone()));
        let d = dl(0);
        let f = fetch(&srv, tmp.path(), "d.img", &old);
        interrupted(&srv, &d, &f, &AtomicU64::new(0));

        // A server that ignores If-Range would splice the new version onto the old bytes.
        srv.set(|b| {
            b.body.clone_from(&new);
            b.etag = Some("\"v2\"".into());
            b.if_range = false;
        });
        let f = Fetch {
            expect: Expect::Both(
                sha2::Sha256::digest(&new).into(),
                sha2::Sha512::digest(&new).into(),
            ),
            ..f
        };
        d.fetch(&f, &AtomicBool::new(false), &AtomicU64::new(0))
            .unwrap();
        assert_eq!(std::fs::read(&f.dest).unwrap(), new);
        assert_eq!(srv.hits()[1].range.as_deref(), Some("bytes=0-"));
    }

    #[test]
    fn checksum_mismatch_never_becomes_visible() {
        let tmp = TempDir::new();
        let data = body(100_000, 7);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        let mut f = fetch(&srv, tmp.path(), "e.bin", &data);
        f.expect = Expect::Sha512([0; 64]);
        let done = AtomicU64::new(0);
        let err = dl(0).fetch(&f, &AtomicBool::new(false), &done).unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"), "{err}");
        assert_eq!(done.load(Ordering::Relaxed), 0);
        assert!(!f.dest.exists() && !f.part().exists());
    }

    #[test]
    fn stop_flag_keeps_the_part() {
        let tmp = TempDir::new();
        let data = body(2 * CP, 8);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        let f = fetch(&srv, tmp.path(), "f.bin", &data);
        let err = dl(0)
            .fetch(&f, &AtomicBool::new(true), &AtomicU64::new(0))
            .unwrap_err();
        assert!(matches!(err, Fail::Stopped));
        assert!(f.part().exists() && !f.dest.exists());
    }

    #[test]
    fn each_attempt_follows_the_redirects_once() {
        let tmp = TempDir::new();
        let data = body(3 * CP + 7, 2);
        let mirror = Server::start("127.0.0.2", Behaviour::new(data.clone()));
        let srv = Server::start("127.0.0.1", Behaviour::new(Vec::new()));
        srv.set(|b| {
            b.redirects.insert("a.iso".into(), "lb/a.iso".into());
            b.redirects
                .insert("lb/a.iso".into(), mirror.url("zim/a.iso"));
        });
        let d = dl(0);
        let f = fetch(&srv, tmp.path(), "a.iso", &data);
        let done = AtomicU64::new(0);
        interrupted(&mirror, &d, &f, &done);

        // Dies again before the next checkpoint: a try that got nowhere.
        mirror.set(|b| b.die_at = Some(5 * CP / 2));
        let err = d.fetch(&f, &AtomicBool::new(false), &done).unwrap_err();
        assert!(
            matches!(
                err,
                Fail::Retry {
                    progressed: false,
                    ..
                }
            ),
            "{err}"
        );

        d.fetch(&f, &AtomicBool::new(false), &done).unwrap();
        assert_eq!(std::fs::read(&f.dest).unwrap(), data);
        let hops = srv.hits();
        assert_eq!(hops.len(), 6);
        assert!(hops.iter().all(|h| h.status == 302));
        let got = mirror.hits();
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|h| h.status == 206));
        assert!(
            got.iter()
                .all(|h| h.range.as_deref() == Some("bytes=2097152-"))
        );
        assert!(got.iter().all(|h| h.if_range.as_deref() == Some("\"v1\"")));
    }

    #[test]
    fn an_error_names_the_hop_that_failed() {
        let tmp = TempDir::new();
        let gone = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let srv = Server::start("127.0.0.1", Behaviour::new(Vec::new()));
        srv.set(|b| {
            let to = format!("http://127.0.0.1:{gone}/m/a?sig=s3cr3t");
            b.redirects.insert("a".into(), to);
            b.redirects.insert("loop".into(), "/loop".into());
        });
        let f = fetch(&srv, tmp.path(), "a", &[1; 10]);
        let err = dl(0)
            .fetch(&f, &AtomicBool::new(false), &AtomicU64::new(0))
            .unwrap_err();
        let msg = err.to_string();
        let hop = format!("{} via http://127.0.0.1:{gone}/m/a: ", f.url);
        assert!(
            matches!(err, Fail::Retry { .. }) && msg.starts_with(&hop),
            "{msg}"
        );
        assert!(!msg.contains("s3cr3t"), "{msg}");

        let f = fetch(&srv, tmp.path(), "loop", &[1; 10]);
        let err = dl(0)
            .fetch(&f, &AtomicBool::new(false), &AtomicU64::new(0))
            .unwrap_err();
        assert!(
            matches!(&err, Fail::Permanent(m) if m.ends_with("more than 10 redirects")),
            "{err}"
        );
    }

    #[test]
    fn statuses_map_to_retry_or_permanent() {
        let tmp = TempDir::new();
        let srv = Server::start("127.0.0.1", Behaviour::new(vec![1; 10]));
        let f = fetch(&srv, tmp.path(), "g", &[1; 10]);
        for (status, permanent) in [(404, true), (403, true), (429, false), (503, false)] {
            srv.set(|b| b.status = Some(status));
            let err = dl(0)
                .fetch(&f, &AtomicBool::new(false), &AtomicU64::new(0))
                .unwrap_err();
            assert_eq!(
                matches!(err, Fail::Permanent(_)),
                permanent,
                "{status}: {err}"
            );
            if status == 503 {
                assert!(
                    matches!(err, Fail::Retry { after: Some(d), .. } if d == Duration::from_secs(7))
                );
            }
        }
    }

    #[test]
    fn throttle_holds_two_mib_per_second() {
        let tmp = TempDir::new();
        let data = body(3 << 20, 9);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        let d = dl(2 << 20);
        let start = Instant::now();
        // Two streams share the one bucket: 6 MiB in all.
        std::thread::scope(|s| {
            for name in ["t1", "t2"] {
                let f = fetch(&srv, tmp.path(), name, &data);
                let d = &d;
                s.spawn(move || {
                    d.fetch(&f, &AtomicBool::new(false), &AtomicU64::new(0))
                        .unwrap();
                });
            }
        });
        #[expect(clippy::cast_precision_loss, reason = "test arithmetic")]
        let rate = (2 * data.len()) as f64 / start.elapsed().as_secs_f64();
        let want = f64::from(2u32 << 20);
        assert!((rate - want).abs() < want * 0.1, "{rate} B/s");
    }

    #[test]
    fn host_key() {
        let cases = [
            ("https://Example.ORG/x", "example.org"),
            ("https://u:p@host.net:8443/a?b", "host.net"),
            ("https://[::1]:443/", "::1"),
            ("http://127.0.0.2:9/z", "127.0.0.2"),
        ];
        for (url, want) in cases {
            let f = Fetch {
                url: url.into(),
                dest: PathBuf::new(),
                size: None,
                limit: u64::MAX,
                expect: Expect::None,
            };
            assert_eq!(f.host(), want, "{url}");
        }
    }
}
