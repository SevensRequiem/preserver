//! Resumable downloads into `<dest>.part`, with the hash state in `<dest>.part.json`.
//!
//! Invariant: whenever the sidecar exists, the first `offset` bytes of the part are on disk
//! (`sync_data` comes before the sidecar's rename) and `sha256`/`sha512` are the midstates of
//! exactly those bytes. A resume truncates the part to `offset`, restores the hashers and asks
//! for the rest with `If-Range`, so a changed file comes back as a 200 and starts over.
//!
//! A fetch with `reuse` first links or copies that file and reads it back against `expect`;
//! only when that fails does it go to the network, in the same call. A sidecar that records a
//! non-empty expected hash also resumes under a new URL when the fetch expects the same hash.

use super::hash::{Resumable, S256, S512};
use super::throttle::Throttle;
use crate::platform;
use crate::resolve::hex;
use crate::resolve::listing::join;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use ureq::http::HeaderMap;
use ureq::{Agent, RequestBuilder, typestate::WithoutBody};

/// Download threads per worker.
pub(crate) const STREAMS: usize = 4;
pub(crate) const CHECKPOINT: u64 = 64 << 20;
/// Bounds what a crash loses on a slow link; on a fast one the byte cap fires first.
const CHECKPOINT_EVERY: Duration = Duration::from_secs(60);
/// The SHA-512 block: a midstate only exists at a multiple of it.
const BLOCK: u64 = 128;
const MAX_REDIRECTS: usize = 10;
const CHUNK: usize = 64 << 10;
const SIDECAR_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Expect {
    None,
    Sha256([u8; 32]),
    Sha512([u8; 64]),
    Both([u8; 32], [u8; 64]),
    /// An Alpine apk with this `Q1`: the whole part is read back and checked in `finish`.
    Apk([u8; 20]),
}

impl Expect {
    /// The expected hash as text: the sidecar's `expect` field.
    pub(crate) fn tag(&self) -> String {
        match self {
            Self::None => String::new(),
            Self::Sha256(a) => format!("sha256:{}", hex(a)),
            Self::Sha512(b) => format!("sha512:{}", hex(b)),
            Self::Both(a, b) => format!("sha256:{} sha512:{}", hex(a), hex(b)),
            Self::Apk(q) => format!("apk-q1:{}", hex(q)),
        }
    }
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
    /// A visible file on the same drive believed to hold these bytes: linked or copied and
    /// checked against `expect` before anything is downloaded.
    pub reuse: Option<PathBuf>,
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
        host_of(&self.url)
    }
}

pub(crate) fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or("", |(_, r)| r);
    let auth = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let auth = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    let host = match auth.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => auth.split(':').next().unwrap_or_default(),
    };
    host.to_ascii_lowercase()
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
    /// A body fetched whole did not hash to the published value: what upstream serves, so
    /// another try in the same run would only fetch it again. `seen` identifies that version.
    Mismatch {
        msg: String,
        seen: Seen,
    },
    /// A local file operation failed: the drive may be gone.
    Disk(io::Error),
    /// The stop flag was raised (pause, cancel, unplug elsewhere).
    Stopped,
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retry { msg, .. } | Self::Permanent(msg) | Self::Mismatch { msg, .. } => {
                f.write_str(msg)
            }
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
            Self::Mismatch { msg, seen } => Self::Mismatch {
                msg: format!("{at}: {msg}"),
                seen,
            },
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

/// What a server said about one version of a file: its validator, length and the host that
/// finally answered. Equal `Seen`s before and after mean upstream has not changed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Seen {
    validator: Option<Validator>,
    len: Option<u64>,
    host: String,
}

impl Seen {
    pub(crate) fn has_validator(&self) -> bool {
        self.validator.is_some()
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
    /// `Expect::tag` of the fetch that wrote it. Older sidecars have none and resume only
    /// under their own URL.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    expect: String,
}

/// The sidecar, read without following a link or waiting on a FIFO, and capped: it sits on a
/// drive anyone may have written to.
fn read_side(side: &Path) -> Option<PartState> {
    let mut buf = Vec::new();
    platform::open_regular(side)
        .ok()?
        .take(64 << 10)
        .read_to_end(&mut buf)
        .ok()?;
    serde_json::from_slice(&buf).ok()
}

/// The expected hash a current-format sidecar records, if any, and the bytes it vouches for.
pub(crate) fn part_expect(side: &Path) -> Option<(String, u64)> {
    read_side(side)
        .filter(|s| s.v == SIDECAR_VERSION && !s.expect.is_empty())
        .map(|s| (s.expect, s.offset))
}

/// Whether the digests match what `e` expects. `Apk` needs the whole file and is checked by
/// `finish` itself, so it never matches here.
fn sums_match(e: &Expect, sha256: &[u8], sha512: Option<&[u8]>) -> bool {
    match e {
        Expect::None => true,
        Expect::Sha256(w) => sha256 == w,
        Expect::Sha512(w) => sha512 == Some(w),
        Expect::Both(a, b) => sha256 == a && sha512 == Some(b),
        Expect::Apk(_) => false,
    }
}

struct Part {
    file: File,
    offset: u64,
    /// The offset the sidecar records.
    saved: u64,
    total: Option<u64>,
    validator: Option<Validator>,
    /// The host of the hop that sent the body.
    host: String,
    /// The bytes before `offset` came from a sidecar, i.e. an earlier call.
    resumed: bool,
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
        self.host.clear();
        self.resumed = false;
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
    /// Time between checkpoints when fewer than `checkpoint` bytes arrived.
    interval: Duration,
}

impl Downloader {
    pub(crate) fn new(agent: Agent, throttle: Arc<Throttle>, checkpoint: u64) -> Self {
        assert_eq!(
            checkpoint % BLOCK,
            0,
            "checkpoints must sit on hash block boundaries"
        );
        Self {
            agent,
            throttle,
            checkpoint,
            interval: CHECKPOINT_EVERY,
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
        if let Some(from) = &f.reuse
            && Self::adopt(f, from, stop, done)?
        {
            return Ok(());
        }
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
            part.host = host_of(&hop);
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
                        let until = Instant::now() + self.interval;
                        left -= self
                            .copy(
                                &mut body,
                                part,
                                Some(left.min(self.checkpoint)),
                                f,
                                stop,
                                done,
                                Some(until),
                            )
                            .map_err(|e| e.at(&at))?;
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
                    // Recorded for `Fail::Mismatch` only: the 200 path never checkpoints.
                    part.validator = Validator::from_headers(&head);
                    part.total = len;
                    self.copy(&mut body, part, len, f, stop, done, None)
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
            host: String::new(),
            resumed: false,
            h256: Resumable::new(),
            h512: wants512.then(Resumable::new),
        };
        // A part under another URL resumes when both name the same published hash: that hash,
        // checked in `finish` and again at publish, names the bytes, and If-Range still turns a
        // server's different version into a restart rather than a splice.
        let st = read_side(side).filter(|st| {
            st.v == SIDECAR_VERSION
                && (st.url == f.url || (!st.expect.is_empty() && st.expect == f.expect.tag()))
                && st.offset <= len
                && st.offset < st.total
                && st.offset % BLOCK == 0
                && st.sha512.is_some() == wants512
        });
        match st {
            Some(st) => {
                p.offset = st.offset;
                p.saved = st.offset;
                p.total = Some(st.total);
                p.validator = Some(st.validator);
                p.resumed = true;
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

    /// Copies the body into the part: exactly `exact` bytes when given, else to EOF, or stops
    /// at the first block boundary after `until` once it read something. Returns the bytes
    /// read. Errors carry no URL; the caller knows which hop sent the body.
    #[expect(
        clippy::too_many_arguments,
        reason = "one body loop; a struct for its inputs would only be built here"
    )]
    fn copy(
        &self,
        body: &mut impl Read,
        p: &mut Part,
        exact: Option<u64>,
        f: &Fetch,
        stop: &AtomicBool,
        done: &AtomicU64,
        until: Option<Instant>,
    ) -> Result<u64, Fail> {
        let cap = f.size.unwrap_or(f.limit);
        let mut buf = vec![0u8; CHUNK];
        let mut got = 0u64;
        loop {
            // Relaxed: the flag carries no data, it only has to be seen within a chunk or so.
            if stop.load(Ordering::Relaxed) {
                return Err(Fail::Stopped);
            }
            let mut room = exact.map_or(CHUNK as u64, |e| e - got).min(CHUNK as u64);
            // Only once something was read: at an aligned start with the deadline gone, a cut
            // here would return 0 bytes and the caller would checkpoint in a loop.
            if got > 0 && until.is_some_and(|t| Instant::now() >= t) {
                let align = (BLOCK - p.offset % BLOCK) % BLOCK;
                if align == 0 {
                    return Ok(got);
                }
                room = room.min(align);
            }
            if room == 0 {
                return Ok(got);
            }
            let room = usize::try_from(room).unwrap_or(CHUNK);
            let n = body
                .read(&mut buf[..room])
                .map_err(|e| retry(format!("read: {e}")))?;
            if n == 0 {
                return match exact {
                    Some(e) if got < e => Err(retry(format!("body ended at {got} of {e} bytes"))),
                    _ => Ok(got),
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
            expect: f.expect.tag(),
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
            Expect::Apk(q) => {
                // The part is read whole even when resumed: the midstate covers only SHA-256.
                p.file.sync_data().map_err(Fail::Disk)?;
                crate::mirror::alpine::apk_holds(&p.file, q).map_err(Fail::Disk)?
            }
            e => sums_match(e, &sha256, sha512.as_deref()),
        };
        if !ok {
            remove(side)?;
            remove(&f.part())?;
            let msg = format!("{}: checksum mismatch", f.url);
            // A body fetched whole over TLS is what upstream serves. A resumed one may be a
            // splice of two versions behind a careless server: one more try, from zero.
            if p.resumed {
                return Err(retry(msg));
            }
            return Err(Fail::Mismatch {
                msg,
                seen: Seen {
                    validator: p.validator,
                    len: p.total,
                    host: p.host,
                },
            });
        }
        p.file.sync_data().map_err(Fail::Disk)?;
        drop(p.file);
        std::fs::rename(f.part(), &f.dest).map_err(Fail::Disk)?;
        remove(&suffixed(side, ".tmp"))?;
        remove(side)
    }

    /// Takes `from` as the download when its bytes prove to be the expected ones: hard linked
    /// (or copied where links are impossible) to `<dest>.reuse`, read back while hashing and
    /// renamed to `dest` only on a match. `Ok(false)` sends the caller to the network. Tried
    /// only while no `.part` exists: a bad candidate is read again only after a download of the
    /// same file failed verification and took its `.part` with it.
    fn adopt(f: &Fetch, from: &Path, stop: &AtomicBool, done: &AtomicU64) -> Result<bool, Fail> {
        if matches!(f.expect, Expect::None | Expect::Apk(_)) || f.part().exists() {
            return Ok(false);
        }
        let tmp = suffixed(&f.dest, ".reuse");
        remove(&tmp)?;
        let Ok(src) = platform::open_regular(from) else {
            return Ok(false);
        };
        let Ok(len) = src.metadata().map(|m| m.len()) else {
            return Ok(false);
        };
        if f.size.is_some_and(|s| s != len) || len > f.size.unwrap_or(f.limit) {
            return Ok(false);
        }
        // `hard_link` does not follow a final symlink on Linux, and `open_regular` then refuses
        // what it made; either way the bytes read are the ones `dest` will hold.
        let (mut reader, mut writer) = if std::fs::hard_link(from, &tmp).is_ok() {
            if let Ok(r) = platform::open_regular(&tmp) {
                (r, None)
            } else {
                remove(&tmp)?;
                return Ok(false);
            }
        } else {
            // Not `link_or_copy`: its `fs::copy` cannot be stopped.
            (src, Some(File::create_new(&tmp).map_err(Fail::Disk)?))
        };
        let mut h256 = Resumable::<S256>::new();
        let mut h512 =
            matches!(f.expect, Expect::Sha512(_) | Expect::Both(..)).then(Resumable::<S512>::new);
        let mut buf = vec![0u8; CHUNK];
        let mut got = 0u64;
        let give_up = |got: u64| {
            done.fetch_sub(got, Ordering::Relaxed);
            remove(&tmp)
        };
        loop {
            // Relaxed: the flag carries no data, as in `copy`.
            if stop.load(Ordering::Relaxed) {
                give_up(got)?;
                return Err(Fail::Stopped);
            }
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => {
                    give_up(got)?;
                    return Ok(false);
                }
            };
            if let Some(w) = &mut writer
                && let Err(e) = w.write_all(&buf[..n])
            {
                give_up(got)?;
                return Err(Fail::Disk(e));
            }
            h256.update(&buf[..n]);
            if let Some(h) = &mut h512 {
                h.update(&buf[..n]);
            }
            got += n as u64;
            done.fetch_add(n as u64, Ordering::Relaxed);
            if got > len {
                break;
            }
        }
        if got != len {
            give_up(got)?;
            return Ok(false);
        }
        if let Some(w) = &writer
            && let Err(e) = w.sync_data()
        {
            give_up(got)?;
            return Err(Fail::Disk(e));
        }
        let sha512 = h512.map(Resumable::finish);
        if !sums_match(&f.expect, &h256.finish(), sha512.as_deref()) {
            give_up(got)?;
            tracing::info!(
                "{}: reuse of {} did not match, downloading",
                f.url,
                from.display()
            );
            return Ok(false);
        }
        drop(writer);
        if let Err(e) = std::fs::rename(&tmp, &f.dest) {
            give_up(got)?;
            return Err(Fail::Disk(e));
        }
        Ok(true)
    }

    /// What the server says now about `url`, from a one-byte ranged GET whose body is dropped
    /// unread: `None` for any failure or status other than 200 and 206. Not throttled.
    pub(crate) fn probe(&self, url: &str) -> Option<Seen> {
        let (resp, hop) = Self::call(url, Duration::from_secs(30), |hop| {
            self.agent.get(hop).header("Range", "bytes=0-0")
        })
        .ok()?;
        let head = resp.headers();
        let len = match resp.status().as_u16() {
            206 => content_range(head).map(|(_, _, t)| t),
            200 => head
                .get("content-length")
                .and_then(|v| v.to_str().ok()?.parse().ok()),
            _ => return None,
        };
        Some(Seen {
            validator: Validator::from_headers(head),
            len,
            host: host_of(&hop),
        })
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
        let body = self.doc_retried(url, false)?.into_body();
        self.read_limited(body, url, limit)
    }

    /// Like `get` but one request that refuses any redirect: for a document whose host must not
    /// be able to send us elsewhere (the Fedora metalink).
    pub(crate) fn get_direct(&self, url: &str, limit: u64) -> anyhow::Result<Vec<u8>> {
        let resp = self
            .agent
            .get(url)
            .config()
            .timeout_global(Some(Duration::from_secs(120)))
            .build()
            .call()
            .map_err(|e| anyhow::anyhow!("{url}: {e}"))?;
        match resp.status().as_u16() {
            200 => self.read_limited(resp.into_body(), url, limit),
            s @ (301 | 302 | 303 | 307 | 308) => {
                anyhow::bail!("{url}: redirect (HTTP {s}) refused")
            }
            s => anyhow::bail!("{url}: HTTP {s}"),
        }
    }

    fn read_limited(&self, body: ureq::Body, url: &str, limit: u64) -> anyhow::Result<Vec<u8>> {
        let mut body = body.into_reader().take(limit + 1);
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

    pub(crate) fn agent(&self) -> Agent {
        self.agent.clone()
    }

    pub(crate) fn throttle(&self) -> Arc<Throttle> {
        self.throttle.clone()
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
            reuse: None,
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

    fn retry_progressed(err: &Fail) -> bool {
        matches!(
            err,
            Fail::Retry {
                progressed: true,
                ..
            }
        )
    }

    #[test]
    fn a_slow_attempt_still_checkpoints_by_time() {
        let tmp = TempDir::new();
        let data = body(3 * CP + 77, 1);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        let mut d = dl(0);
        d.interval = Duration::ZERO;
        let f = fetch(&srv, tmp.path(), "t.iso", &data);
        let done = AtomicU64::new(0);
        let die_at = 5 * CP / 2 + 1000;
        srv.set(|b| b.die_at = Some(die_at));
        let err = d.fetch(&f, &AtomicBool::new(false), &done).unwrap_err();
        assert!(retry_progressed(&err), "{err}");
        let off = sidecar(&f).offset;
        assert!(off.is_multiple_of(BLOCK));
        assert!(off > 0 && off <= die_at, "offset {off}");
        assert!(die_at - off <= CHUNK as u64 + BLOCK, "offset {off}");
        assert!(std::fs::metadata(f.part()).unwrap().len() >= off);
        assert_eq!(done.load(Ordering::Relaxed), 0);
        srv.clear_log();

        d.fetch(&f, &AtomicBool::new(false), &done).unwrap();
        assert_eq!(std::fs::read(&f.dest).unwrap(), data);
        let hits = srv.hits();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].range, Some(format!("bytes={off}-")));
        assert_eq!(hits[0].if_range.as_deref(), Some("\"v1\""));
        assert_eq!(srv.served(), data.len() as u64 - off);
        assert_eq!(done.load(Ordering::Relaxed), data.len() as u64);
    }

    #[test]
    fn time_checkpoints_land_on_block_boundaries() {
        for (len, die_at) in [
            (CP + 5, 100_001),
            (CP, 128 * 1000),
            (CP, 128 * 1000 + 1),
            (CP + 127, CP - 1),
        ] {
            let case = format!("len {len} die_at {die_at}");
            let tmp = TempDir::new();
            let data = body(len, 2);
            let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
            let mut d = Downloader::new(
                loopback_agent(RootCerts::new_with_certs(&[])),
                Arc::new(Throttle::new(0)),
                1 << 30,
            );
            d.interval = Duration::ZERO;
            let f = fetch(&srv, tmp.path(), "b.iso", &data);
            srv.set(|b| b.die_at = Some(die_at));
            let done = AtomicU64::new(0);
            let err = d.fetch(&f, &AtomicBool::new(false), &done).unwrap_err();
            assert!(retry_progressed(&err), "{case}: {err}");
            let off = sidecar(&f).offset;
            assert!(
                off.is_multiple_of(BLOCK) && off <= die_at,
                "{case}: offset {off}"
            );
            d.fetch(&f, &AtomicBool::new(false), &done).unwrap();
            assert_eq!(std::fs::read(&f.dest).unwrap(), data, "{case}");
        }
    }

    #[test]
    fn no_time_checkpoint_spins_at_an_aligned_start() {
        // Guards the `got > 0` rule in `copy`: without it an aligned start with the deadline
        // gone returns 0 bytes forever and this test hangs.
        let tmp = TempDir::new();
        let data = body(2 * CP, 3);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        let mut d = dl(0);
        d.interval = Duration::ZERO;
        let f = fetch(&srv, tmp.path(), "s.iso", &data);
        d.fetch(&f, &AtomicBool::new(false), &AtomicU64::new(0))
            .unwrap();
        assert_eq!(std::fs::read(&f.dest).unwrap(), data);
        assert_eq!(srv.hits().len(), 1);
        assert!(!f.part().exists() && !f.sidecar().exists());
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
        for ranges in [true, false] {
            let tmp = TempDir::new();
            let data = body(100_000, 7);
            let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
            srv.set(|b| b.ranges = ranges);
            let mut f = fetch(&srv, tmp.path(), "e.bin", &data);
            f.expect = Expect::Sha512([0; 64]);
            let done = AtomicU64::new(0);
            let err = dl(0).fetch(&f, &AtomicBool::new(false), &done).unwrap_err();
            let Fail::Mismatch { msg, seen } = &err else {
                panic!("ranges {ranges}: {err}");
            };
            assert!(msg.contains("checksum mismatch"), "ranges {ranges}: {msg}");
            assert_eq!(
                seen,
                &Seen {
                    validator: Some(Validator::Etag("\"v1\"".into())),
                    len: Some(100_000),
                    host: "127.0.0.1".into(),
                },
                "ranges {ranges}"
            );
            assert_eq!(done.load(Ordering::Relaxed), 0);
            assert!(!f.dest.exists() && !f.part().exists() && !f.sidecar().exists());
        }
    }

    #[test]
    fn a_resumed_part_that_mismatches_retries_from_zero() {
        let tmp = TempDir::new();
        let data = body(5 * CP, 1);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        let d = dl(0);
        let f = fetch(&srv, tmp.path(), "a.iso", &data);
        let done = AtomicU64::new(0);
        interrupted(&srv, &d, &f, &done);
        // Another version under the same ETag behind a server that ignores If-Range: the
        // resumed part becomes a splice.
        srv.set(|b| {
            b.body = body(5 * CP, 2);
            b.if_range = false;
        });
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
        assert!(!f.part().exists() && !f.sidecar().exists());
        srv.clear_log();
        let err = d.fetch(&f, &AtomicBool::new(false), &done).unwrap_err();
        assert!(matches!(err, Fail::Mismatch { .. }), "{err}");
        assert_eq!(srv.hits()[0].range.as_deref(), Some("bytes=0-"));

        // A resumed part that a 200 resets inside the call was fetched whole after all.
        let g = fetch(&srv, tmp.path(), "b.iso", &data);
        srv.set(|b| {
            b.body = data.clone();
            b.if_range = true;
        });
        interrupted(&srv, &d, &g, &done);
        srv.set(|b| {
            b.body = body(5 * CP, 3);
            b.ranges = false;
        });
        let err = d.fetch(&g, &AtomicBool::new(false), &done).unwrap_err();
        assert!(matches!(err, Fail::Mismatch { .. }), "{err}");
        assert_eq!(done.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn probe_reads_the_validator_and_length() {
        let data = body(5000, 4);
        let mirror = Server::start("127.0.0.2", Behaviour::new(data.clone()));
        let srv = Server::start("127.0.0.1", Behaviour::new(data));
        srv.set(|b| {
            b.replies.insert(
                "lm".into(),
                (
                    200,
                    "Last-Modified: Wed, 21 Oct 2025 07:28:00 GMT\r\n".into(),
                ),
            );
            b.replies.insert("gone".into(), (404, String::new()));
            b.redirects.insert("moved".into(), mirror.url("x"));
        });
        let d = dl(0);
        let etag = Some(Validator::Etag("\"v1\"".into()));
        let seen = |validator: Option<Validator>, len: u64, host: &str| Seen {
            validator,
            len: Some(len),
            host: host.into(),
        };
        assert_eq!(
            d.probe(&srv.url("a")),
            Some(seen(etag.clone(), 5000, "127.0.0.1"))
        );
        assert_eq!(srv.hits()[0].range.as_deref(), Some("bytes=0-0"));
        let lm = Validator::LastModified("Wed, 21 Oct 2025 07:28:00 GMT".into());
        assert_eq!(
            d.probe(&srv.url("lm")),
            Some(seen(Some(lm), 0, "127.0.0.1"))
        );
        assert_eq!(d.probe(&srv.url("gone")), None);
        assert_eq!(
            d.probe(&srv.url("moved")),
            Some(seen(etag.clone(), 5000, "127.0.0.2"))
        );
        srv.set(|b| b.ranges = false);
        assert_eq!(d.probe(&srv.url("a")), Some(seen(etag, 5000, "127.0.0.1")));
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
    fn get_direct_refuses_a_redirect() {
        let srv = Server::start("127.0.0.1", Behaviour::new(b"doc".to_vec()));
        srv.set(|b| {
            b.redirects
                .insert("moved".into(), "http://127.0.0.1:9/other".into());
        });
        let d = dl(0);
        assert_eq!(d.get_direct(&srv.url("doc"), 16).unwrap(), b"doc");
        let err = d.get_direct(&srv.url("moved"), 16).unwrap_err().to_string();
        assert!(err.contains("redirect (HTTP 302) refused"), "{err}");
        assert_eq!(srv.hits().len(), 2);
        let err = d.get_direct(&srv.url("doc"), 2).unwrap_err().to_string();
        assert!(err.contains("larger than 2 bytes"), "{err}");
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
                reuse: None,
            };
            assert_eq!(f.host(), want, "{url}");
        }
    }

    #[test]
    fn expect_tag() {
        let (a, b, q) = ([0xABu8; 32], [0x0Fu8; 64], [0x1Cu8; 20]);
        let cases = [
            (Expect::None, String::new()),
            (Expect::Sha256(a), format!("sha256:{}", "ab".repeat(32))),
            (Expect::Sha512(b), format!("sha512:{}", "0f".repeat(64))),
            (
                Expect::Both(a, b),
                format!("sha256:{} sha512:{}", "ab".repeat(32), "0f".repeat(64)),
            ),
            (Expect::Apk(q), format!("apk-q1:{}", "1c".repeat(20))),
        ];
        for (e, want) in cases {
            assert_eq!(e.tag(), want, "{e:?}");
        }
        assert_ne!(Expect::Sha256(a).tag(), Expect::Both(a, b).tag());
    }

    #[test]
    fn a_moved_url_resumes_when_the_hash_is_published() {
        let tmp = TempDir::new();
        let data = body(5 * CP + 999, 4);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        let d = dl(0);
        let old = Fetch {
            url: srv.url("old/a.iso"),
            ..fetch(&srv, tmp.path(), "a.iso", &data)
        };
        let done = AtomicU64::new(0);
        interrupted(&srv, &d, &old, &done);

        let new = Fetch {
            url: srv.url("new/a.iso"),
            ..old.clone()
        };
        d.fetch(&new, &AtomicBool::new(false), &done).unwrap();
        assert_eq!(std::fs::read(&new.dest).unwrap(), data);
        let hits = srv.hits();
        assert_eq!(hits.len(), 1);
        assert!(hits[0].path.ends_with("new/a.iso"), "{}", hits[0].path);
        assert_eq!(hits[0].range.as_deref(), Some("bytes=2097152-"));
        assert_eq!(hits[0].if_range.as_deref(), Some("\"v1\""));
        assert_eq!(srv.served(), data.len() as u64 - 2 * CP);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "one table and the files each case needs"
    )]
    fn resume_rule_across_urls() {
        let data = body(1000, 6);
        let both = Expect::Both(
            sha2::Sha256::digest(&data).into(),
            sha2::Sha512::digest(&data).into(),
        );
        let mid256 = {
            let mut h = Resumable::<S256>::new();
            h.update(&data[..128]);
            h.midstate().unwrap().0
        };
        let mid512 = {
            let mut h = Resumable::<S512>::new();
            h.update(&data[..128]);
            h.midstate().unwrap().0
        };
        let (same, moved) = ("https://a.example/x.iso", "https://b.example/x.iso");
        let zeros = format!("sha256:{}", "00".repeat(32));
        // (case, sidecar url, sidecar expect, sidecar has sha512, fetch expect, symlink, kept)
        let cases: [(&str, &str, String, bool, Expect, bool, bool); 7] = [
            (
                "no expect, same url",
                same,
                String::new(),
                true,
                both.clone(),
                false,
                true,
            ),
            (
                "no expect, new url",
                moved,
                String::new(),
                true,
                both.clone(),
                false,
                false,
            ),
            (
                "expect == tag, new url",
                moved,
                both.tag(),
                true,
                both.clone(),
                false,
                true,
            ),
            (
                "a different expect",
                moved,
                zeros,
                true,
                both.clone(),
                false,
                false,
            ),
            (
                "Expect::None, new url",
                moved,
                String::new(),
                false,
                Expect::None,
                false,
                false,
            ),
            (
                "sha512 presence differs",
                moved,
                both.tag(),
                false,
                both.clone(),
                false,
                false,
            ),
            (
                "sidecar is a symlink",
                same,
                String::new(),
                true,
                both.clone(),
                true,
                false,
            ),
        ];
        for (case, url, expect, has512, fexpect, link, kept) in cases {
            if link && !cfg!(unix) {
                continue;
            }
            let tmp = TempDir::new();
            let f = Fetch {
                url: same.into(),
                dest: tmp.path().join("x.iso"),
                size: Some(1000),
                limit: u64::MAX,
                expect: fexpect,
                reuse: None,
            };
            std::fs::write(f.part(), &data[..256]).unwrap();
            let st = PartState {
                v: SIDECAR_VERSION,
                url: url.into(),
                validator: Validator::Etag("\"v1\"".into()),
                offset: 128,
                total: 1000,
                sha256: mid256,
                sha512: has512.then_some(mid512),
                expect,
            };
            let json = serde_json::to_vec(&st).unwrap();
            if link {
                let real = tmp.path().join("real.json");
                std::fs::write(&real, &json).unwrap();
                #[cfg(unix)]
                std::os::unix::fs::symlink(&real, f.sidecar()).unwrap();
            } else {
                std::fs::write(f.sidecar(), &json).unwrap();
            }
            let p = Downloader::open(&f, &f.sidecar()).unwrap();
            assert_eq!(p.offset, if kept { 128 } else { 0 }, "{case}");
        }
    }

    #[test]
    fn old_sidecar_json_still_parses() {
        let old = br#"{"v":1,"url":"https://a.example/x","validator":{"etag":"\"v1\""},"offset":128,"total":1000,"sha256":[1,2,3,4,5,6,7,8],"sha512":null}"#;
        let st: PartState = serde_json::from_slice(old).unwrap();
        assert!(st.expect.is_empty() && st.offset == 128);

        let tmp = TempDir::new();
        let data = body(3 * CP, 7);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        let f = fetch(&srv, tmp.path(), "n.iso", &data);
        interrupted(&srv, &dl(0), &f, &AtomicU64::new(0));
        let json = String::from_utf8(std::fs::read(f.sidecar()).unwrap()).unwrap();
        assert!(json.contains("\"expect\":\"sha256:"), "{json}");
        assert_eq!(
            part_expect(&f.sidecar()).map(|(t, _)| t),
            Some(f.expect.tag())
        );
    }

    /// A fetch of `data` whose reuse candidate is `held` (written when given).
    fn reusing(srv: &Server, dir: &Path, data: &[u8], held: Option<&[u8]>) -> Fetch {
        let cand = dir.join("held.iso");
        if let Some(b) = held {
            std::fs::write(&cand, b).unwrap();
        }
        Fetch {
            reuse: Some(cand),
            ..fetch(srv, dir, "r.iso", data)
        }
    }

    #[test]
    fn adopt_links_a_matching_file() {
        let tmp = TempDir::new();
        let data = body(300_000, 8);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        srv.set(|b| b.status = Some(404));
        let f = reusing(&srv, tmp.path(), &data, Some(&data));
        let done = AtomicU64::new(0);
        dl(0).fetch(&f, &AtomicBool::new(false), &done).unwrap();
        assert_eq!(std::fs::read(&f.dest).unwrap(), data);
        assert!(srv.hits().is_empty());
        assert_eq!(done.load(Ordering::Relaxed), data.len() as u64);
        assert!(!suffixed(&f.dest, ".reuse").exists() && !f.part().exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let ino = |p: &Path| std::fs::metadata(p).unwrap().ino();
            assert_eq!(ino(&f.dest), ino(f.reuse.as_ref().unwrap()));
        }
    }

    #[test]
    fn adopt_falls_back_to_the_network() {
        let data = body(200_000, 9);
        let wrong = body(200_000, 10);
        let cases: [(&str, Option<&[u8]>, bool, bool); 5] = [
            ("same size, wrong bytes", Some(&wrong), false, false),
            ("wrong size", Some(&data[..1000]), false, false),
            ("a symlink to a matching file", None, true, false),
            ("missing", None, false, false),
            ("Expect::None", Some(&data), false, true),
        ];
        for (case, held, link, none) in cases {
            if link && !cfg!(unix) {
                continue;
            }
            let tmp = TempDir::new();
            let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
            let mut f = reusing(&srv, tmp.path(), &data, held);
            let cand = f.reuse.clone().unwrap();
            if link {
                let real = tmp.path().join("real.iso");
                std::fs::write(&real, &data).unwrap();
                #[cfg(unix)]
                std::os::unix::fs::symlink(&real, &cand).unwrap();
            }
            if none {
                f.expect = Expect::None;
            }
            let before = std::fs::read(&cand).ok();
            let done = AtomicU64::new(0);
            dl(0).fetch(&f, &AtomicBool::new(false), &done).unwrap();
            assert_eq!(std::fs::read(&f.dest).unwrap(), data, "{case}");
            assert_eq!(srv.hits().len(), 1, "{case}");
            assert_eq!(std::fs::read(&cand).ok(), before, "{case}");
            assert!(!suffixed(&f.dest, ".reuse").exists(), "{case}");
            assert_eq!(done.load(Ordering::Relaxed), data.len() as u64, "{case}");
        }
    }

    /// The copy branch (FAT/exFAT, where links fail): the candidate sits on another filesystem,
    /// so `hard_link` gets EXDEV. Skipped where `/dev/shm` is missing or on the same device.
    #[cfg(target_os = "linux")]
    #[test]
    fn adopt_copies_when_a_link_is_impossible() {
        use std::os::unix::fs::MetadataExt;
        let tmp = TempDir::new();
        let dev = |p: &Path| std::fs::metadata(p).map(|m| m.dev()).ok();
        let shm = Path::new("/dev/shm");
        if dev(shm).is_none_or(|d| Some(d) == dev(tmp.path())) {
            eprintln!("skipped: no /dev/shm on another filesystem");
            return;
        }
        let other = shm.join(format!("preserver-test-{}-adopt", std::process::id()));
        std::fs::create_dir_all(&other).unwrap();
        let data = body(300_000, 13);
        let wrong = body(300_000, 14);
        // (case, candidate bytes, stop, network hits)
        let cases: [(&str, &[u8], bool, usize); 3] = [
            ("matching", &data, false, 0),
            ("same size, wrong bytes", &wrong, false, 1),
            ("stopped", &data, true, 0),
        ];
        for (case, held, stop, hits) in cases {
            let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
            let cand = other.join("held.iso");
            std::fs::write(&cand, held).unwrap();
            let f = Fetch {
                reuse: Some(cand.clone()),
                ..fetch(&srv, tmp.path(), "c.iso", &data)
            };
            let _ = std::fs::remove_file(&f.dest);
            let done = AtomicU64::new(0);
            let got = dl(0).fetch(&f, &AtomicBool::new(stop), &done);
            assert!(!suffixed(&f.dest, ".reuse").exists(), "{case}");
            assert_eq!(std::fs::read(&cand).unwrap(), held, "{case}");
            assert_eq!(srv.hits().len(), hits, "{case}");
            if stop {
                assert!(matches!(got, Err(Fail::Stopped)), "{case}");
                assert!(!f.dest.exists(), "{case}");
                assert_eq!(done.load(Ordering::Relaxed), 0, "{case}");
                continue;
            }
            got.unwrap();
            assert_eq!(std::fs::read(&f.dest).unwrap(), data, "{case}");
            assert_eq!(done.load(Ordering::Relaxed), data.len() as u64, "{case}");
            assert_ne!(dev(&f.dest), dev(&cand), "{case}: a copy, not a link");
        }
        std::fs::remove_dir_all(&other).unwrap();
    }

    #[test]
    fn adopt_is_skipped_once_a_part_exists() {
        let tmp = TempDir::new();
        let data = body(200_000, 11);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        let f = reusing(&srv, tmp.path(), &data, Some(&data));
        std::fs::write(f.part(), b"left by an earlier attempt").unwrap();
        d_fetch(&f).unwrap();
        assert_eq!(std::fs::read(&f.dest).unwrap(), data);
        assert_eq!(srv.hits().len(), 1);
    }

    #[test]
    fn adopt_honours_the_stop_flag() {
        let tmp = TempDir::new();
        let data = body(200_000, 12);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        let f = reusing(&srv, tmp.path(), &data, Some(&data));
        let done = AtomicU64::new(0);
        let err = dl(0).fetch(&f, &AtomicBool::new(true), &done).unwrap_err();
        assert!(matches!(err, Fail::Stopped), "{err}");
        assert!(!f.dest.exists() && !suffixed(&f.dest, ".reuse").exists());
        assert_eq!(done.load(Ordering::Relaxed), 0);
        assert!(srv.hits().is_empty());
    }
}
