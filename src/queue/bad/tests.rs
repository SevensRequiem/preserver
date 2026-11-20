use super::*;
use crate::net::client::loopback_agent;
use crate::net::download::Expect;
use crate::net::testserver::{Behaviour, Server, body};
use crate::net::throttle::Throttle;
use crate::testutil::TempDir;
use sha2::Digest;
use std::sync::Arc;
use ureq::tls::RootCerts;

fn dl() -> Downloader {
    Downloader::new(
        loopback_agent(RootCerts::new_with_certs(&[])),
        Arc::new(Throttle::new(0)),
        1 << 20,
    )
}

fn fetch(srv: &Server, dir: &Path, name: &str, data: &[u8]) -> Fetch {
    Fetch {
        url: srv.url(name),
        dest: dir.join(name),
        size: Some(data.len() as u64),
        limit: u64::MAX,
        expect: Expect::Sha256(sha2::Sha256::digest(data).into()),
        reuse: None,
    }
}

/// An entry for `f` (and `extra` side URLs) with what the server answers now.
fn entry(d: &Downloader, f: &Fetch, extra: &[String]) -> Entry {
    let mut urls = vec![f.url.clone()];
    urls.extend_from_slice(extra);
    let mut e = Entry::new(urls, f.expect.tag(), f.size, "checksum mismatch");
    e.seen = e.urls.iter().map(|u| d.probe(u).unwrap()).collect();
    e
}

/// Writes the ledger as is: `save` would drop another build's entries.
fn write_raw(set_dir: &Path, entries: Vec<Entry>) {
    std::fs::create_dir_all(set_dir.join(".preserver")).unwrap();
    let json = serde_json::to_vec(&Ledger {
        v: VERSION,
        entries,
    })
    .unwrap();
    std::fs::write(set_dir.join(".preserver/bad.json"), json).unwrap();
}

fn bad(set_dir: &Path, known: &[&String]) -> Bad {
    Bad {
        set_dir: set_dir.to_path_buf(),
        known: known.iter().map(|u| (*u).clone()).collect(),
    }
}

#[test]
fn the_ledger_round_trips_and_bad_files_read_as_empty() {
    let tmp = TempDir::new();
    let set = tmp.path();
    assert_eq!(load(set), Vec::<Entry>::new());
    let now = Timestamp::now();
    let mut entries: Vec<Entry> = (0..300i64)
        .map(|i| {
            let mut e = Entry::new(vec![format!("https://h/{i}")], String::new(), None, "r");
            e.since = now - jiff::SignedDuration::from_secs(i);
            e
        })
        .collect();
    entries[1].build = "0.0.0".into();
    save(set, entries.clone()).unwrap();
    let back = load(set);
    assert_eq!(back.len(), CAP);
    entries.remove(1);
    entries.truncate(CAP);
    assert_eq!(back, entries);

    for junk in [&b"{not json"[..], br#"{"v":2,"entries":[]}"#] {
        std::fs::write(set.join(".preserver/bad.json"), junk).unwrap();
        assert_eq!(load(set), Vec::<Entry>::new());
    }
    // A long reason is cut.
    assert_eq!(
        Entry::new(vec![], String::new(), None, &"x".repeat(500))
            .reason
            .len(),
        200
    );
}

#[test]
fn record_into_keeps_the_date_of_the_same_bytes() {
    let old = Timestamp::from_second(1_000_000_000).unwrap();
    let mut entries = vec![Entry::new(vec!["u".into()], "sha256:a".into(), None, "r")];
    entries[0].since = old;
    record_into(
        &mut entries,
        Entry::new(vec!["u".into()], "sha256:a".into(), None, "r2"),
    );
    assert_eq!((entries.len(), entries[0].since), (1, old));
    assert_eq!(entries[0].reason, "r2");
    record_into(
        &mut entries,
        Entry::new(vec!["u".into()], "sha256:b".into(), None, "r3"),
    );
    assert_eq!(entries.len(), 1);
    assert!(entries[0].since > old);
}

type Twist = fn(&Server, &Server, &mut Fetch, &mut Entry);

#[test]
fn held_only_while_every_probe_sees_the_same() {
    let cases: [(&str, Twist, bool); 9] = [
        ("unchanged", |_, _, _, _| {}, true),
        (
            "etag",
            |s, _, _, _| s.set(|b| b.etag = Some("\"v2\"".into())),
            false,
        ),
        ("len", |s, _, _, _| s.set(|b| b.body.push(0)), false),
        (
            "host",
            |s, m, _, _| {
                s.set(|b| {
                    b.redirects.insert("a.bin".into(), m.url("a.bin"));
                });
            },
            false,
        ),
        (
            "expect",
            |_, _, f, _| f.expect = Expect::Sha256([1; 32]),
            false,
        ),
        ("size", |_, _, f, _| f.size = Some(1), false),
        ("build", |_, _, _, e| e.build = "0.0.0".into(), false),
        (
            "404",
            |s, _, _, _| {
                s.set(|b| {
                    b.replies.insert("a.bin".into(), (404, String::new()));
                });
            },
            false,
        ),
        (
            "reuse",
            |_, _, f, _| f.reuse = Some(PathBuf::from("/nonexistent")),
            false,
        ),
    ];
    let d = dl();
    for (name, twist, want) in cases {
        let tmp = TempDir::new();
        let data = body(3000, 5);
        let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
        let mirror = Server::start("127.0.0.2", Behaviour::new(data.clone()));
        let mut f = fetch(&srv, tmp.path(), "a.bin", &data);
        let mut e = entry(&d, &f, &[]);
        twist(&srv, &mirror, &mut f, &mut e);
        write_raw(tmp.path(), vec![e]);
        srv.clear_log();
        let got = held(&bad(tmp.path(), &[]), std::slice::from_ref(&f), &d, &|| {
            false
        });
        let msg = got.into_iter().next().flatten();
        assert_eq!(msg.is_some(), want, "{name}: {msg:?}");
        if let Some(m) = msg {
            assert!(m.starts_with("skipped ") && m.contains("since "), "{m}");
            assert!(m.ends_with("upstream unchanged"), "{m}");
        }
        if name == "reuse" {
            assert!(srv.hits().is_empty(), "reuse probed");
        }
    }
}

#[test]
fn side_urls_outside_the_plan_are_never_probed() {
    let tmp = TempDir::new();
    let data = body(3000, 6);
    let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
    let d = dl();
    let f = fetch(&srv, tmp.path(), "a.bin", &data);
    let sig = srv.url("a.bin.sig");
    write_raw(tmp.path(), vec![entry(&d, &f, std::slice::from_ref(&sig))]);
    srv.clear_log();
    let got = held(&bad(tmp.path(), &[]), std::slice::from_ref(&f), &d, &|| {
        false
    });
    assert_eq!(got, [None]);
    assert!(srv.hits().is_empty());
    let got = held(
        &bad(tmp.path(), &[&sig]),
        std::slice::from_ref(&f),
        &d,
        &|| false,
    );
    assert!(got[0].is_some());
    let paths: Vec<String> = srv.hits().into_iter().map(|h| h.path).collect();
    assert_eq!(paths, ["a.bin", "a.bin.sig"]);
}

#[test]
fn a_server_without_validators_is_held_and_says_so() {
    let tmp = TempDir::new();
    let data = body(3000, 7);
    let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
    srv.set(|b| b.etag = None);
    let d = dl();
    let f = fetch(&srv, tmp.path(), "a.bin", &data);
    write_raw(tmp.path(), vec![entry(&d, &f, &[])]);
    let got = held(&bad(tmp.path(), &[]), std::slice::from_ref(&f), &d, &|| {
        false
    });
    let m = got[0].as_deref().unwrap();
    assert!(m.ends_with("upstream sends no validator"), "{m}");
}

#[test]
fn a_dead_host_is_probed_once() {
    let tmp = TempDir::new();
    let data = body(3000, 8);
    let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
    let d = dl();
    let fs = [
        fetch(&srv, tmp.path(), "a.bin", &data),
        fetch(&srv, tmp.path(), "b.bin", &data),
    ];
    write_raw(tmp.path(), fs.iter().map(|f| entry(&d, f, &[])).collect());
    srv.set(|b| b.status = Some(503));
    srv.clear_log();
    assert_eq!(
        held(&bad(tmp.path(), &[]), &fs, &d, &|| false),
        [None, None]
    );
    assert_eq!(srv.hits().len(), 1);
}

#[test]
fn update_drops_verified_files_and_adds_mismatches() {
    let tmp = TempDir::new();
    let data = body(3000, 9);
    let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
    let d = dl();
    let fs = [
        fetch(&srv, tmp.path(), "a.bin", &data),
        fetch(&srv, tmp.path(), "b.bin", &data),
    ];
    let b = bad(tmp.path(), &[]);
    let seen = d.probe(&fs[1].url).unwrap();
    update(&b, &fs, &[], &[(1, seen.clone())]);
    let got = load(tmp.path());
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].urls, [fs[1].url.clone()]);
    assert_eq!(got[0].seen, [seen]);
    assert_eq!(got[0].expect, fs[1].expect.tag());
    update(&b, &fs, &[1], &[]);
    assert_eq!(load(tmp.path()), Vec::<Entry>::new());
}

#[test]
fn a_stop_ends_the_probes() {
    let tmp = TempDir::new();
    let data = body(3000, 10);
    let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
    let d = dl();
    let fs = [
        fetch(&srv, tmp.path(), "a.bin", &data),
        fetch(&srv, tmp.path(), "b.bin", &data),
    ];
    write_raw(tmp.path(), fs.iter().map(|f| entry(&d, f, &[])).collect());
    srv.clear_log();
    let asked = std::cell::Cell::new(0);
    let stop = || {
        asked.set(asked.get() + 1);
        asked.get() > 1
    };
    let got = held(&bad(tmp.path(), &[]), &fs, &d, &stop);
    assert!(got[0].is_some() && got[1].is_none(), "{got:?}");
    assert_eq!(srv.hits().len(), 1);
}
