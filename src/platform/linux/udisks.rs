use crate::config::DriveId;
use crate::platform::FsInfo;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use zbus::MatchRule;
use zbus::blocking::{Connection, MessageIterator};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

const UDISKS: &str = "org.freedesktop.UDisks2";
const BLOCK: &str = "org.freedesktop.UDisks2.Block";
const FILESYSTEM: &str = "org.freedesktop.UDisks2.Filesystem";
const DRIVE: &str = "org.freedesktop.UDisks2.Drive";

type Interfaces = HashMap<String, HashMap<String, OwnedValue>>;
type Objects = HashMap<OwnedObjectPath, Interfaces>;

fn objects(bus: &Connection) -> Result<Objects> {
    let reply = bus.call_method(
        Some(UDISKS),
        "/org/freedesktop/UDisks2",
        Some("org.freedesktop.DBus.ObjectManager"),
        "GetManagedObjects",
        &(),
    )?;
    Ok(reply.body().deserialize()?)
}

fn prop<T: TryFrom<OwnedValue>>(ifs: &Interfaces, iface: &str, name: &str) -> Option<T> {
    ifs.get(iface)?.get(name)?.try_clone().ok()?.try_into().ok()
}

/// udisks hands out paths as NUL-terminated byte strings.
fn c_string(mut bytes: Vec<u8>) -> String {
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn filesystems(objs: &Objects) -> Vec<(&OwnedObjectPath, FsInfo)> {
    let mut out: Vec<_> = objs
        .iter()
        .filter(|(_, ifs)| ifs.contains_key(FILESYSTEM))
        .map(|(path, ifs)| {
            let removable = prop::<OwnedObjectPath>(ifs, BLOCK, "Drive")
                .and_then(|drive| prop(objs.get(&drive)?, DRIVE, "Removable"))
                .unwrap_or(false);
            let info = FsInfo {
                device: c_string(prop(ifs, BLOCK, "Device").unwrap_or_default()),
                id: prop(ifs, BLOCK, "IdUUID").unwrap_or_default(),
                label: prop(ifs, BLOCK, "IdLabel").unwrap_or_default(),
                fstype: prop(ifs, BLOCK, "IdType").unwrap_or_default(),
                size: prop(ifs, BLOCK, "Size").unwrap_or_default(),
                mount: prop::<Vec<Vec<u8>>>(ifs, FILESYSTEM, "MountPoints")
                    .and_then(|m| m.into_iter().next())
                    .map(|m| PathBuf::from(c_string(m))),
                removable,
            };
            (path, info)
        })
        .collect();
    out.sort_by(|a, b| a.1.device.cmp(&b.1.device));
    out
}

pub(crate) fn list_filesystems() -> Result<Vec<FsInfo>> {
    let objs = objects(&Connection::system()?)?;
    Ok(filesystems(&objs)
        .into_iter()
        .map(|(_, info)| info)
        .collect())
}

/// Mounts the filesystem with this id and returns where it is mounted.
/// It never asks for authentication: backups run unattended.
pub(crate) fn mount(id: &DriveId) -> Result<PathBuf> {
    let bus = Connection::system()?;
    let objs = objects(&bus)?;
    let (path, info) = filesystems(&objs)
        .into_iter()
        .find(|(_, info)| id.matches(&info.id))
        .with_context(|| format!("no filesystem with id {id}"))?;
    if let Some(at) = info.mount {
        return Ok(at);
    }
    let options = HashMap::from([("auth.no_user_interaction", Value::from(true))]);
    let reply = bus.call_method(Some(UDISKS), path, Some(FILESYSTEM), "Mount", &(options,))?;
    Ok(PathBuf::from(reply.body().deserialize::<String>()?))
}

/// A filesystem appeared, or one was mounted or unmounted. One plug-in sends several of these;
/// the daemon's lanes coalesce the wake-ups.
fn is_drive_signal(msg: &zbus::Message) -> bool {
    let header = msg.header();
    let (Some(iface), Some(member)) = (header.interface(), header.member()) else {
        return false;
    };
    match (iface.as_str(), member.as_str()) {
        ("org.freedesktop.DBus.ObjectManager", "InterfacesAdded") => msg
            .body()
            .deserialize::<(OwnedObjectPath, Interfaces)>()
            .is_ok_and(|(_, ifs)| ifs.contains_key(FILESYSTEM)),
        ("org.freedesktop.DBus.Properties", "PropertiesChanged") => msg
            .body()
            .deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>()
            .is_ok_and(|(i, changed, _)| i == FILESYSTEM && changed.contains_key("MountPoints")),
        _ => false,
    }
}

/// Calls `on_change` from a thread of its own whenever udisks reports a drive event.
pub(crate) fn watch_drives(on_change: impl Fn() + Send + 'static) {
    watch(Connection::system, on_change);
}

/// Survives a udisks or system bus restart: on a lost or failed connection it warns once and
/// tries again every 30 s, and after a gap it calls `on_change`, since a plug-in may be missed.
fn watch(
    connect: impl Fn() -> zbus::Result<Connection> + Send + 'static,
    on_change: impl Fn() + Send + 'static,
) {
    let subscribe = move || -> zbus::Result<MessageIterator> {
        // Every udisks signal, filtered here: InterfacesAdded comes from the manager object,
        // PropertiesChanged from the block devices, both under this path.
        let rule = MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(UDISKS)?
            .path_namespace("/org/freedesktop/UDisks2")?
            .build();
        MessageIterator::for_match_rule(rule, &connect()?, None)
    };
    std::thread::spawn(move || {
        let mut failing = false;
        loop {
            match subscribe() {
                Ok(signals) => {
                    if std::mem::take(&mut failing) {
                        tracing::info!("drive events: watching udisks again");
                        on_change();
                    }
                    for msg in signals {
                        match msg {
                            Ok(m) if is_drive_signal(&m) => on_change(),
                            Ok(_) => {}
                            Err(e) => tracing::debug!("drive events: {e}"),
                        }
                    }
                    tracing::warn!("drive events: the system bus connection closed");
                    failing = true;
                }
                Err(e) if !failing => {
                    tracing::warn!("drive events unavailable, retrying every 30 s: {e}");
                    failing = true;
                }
                Err(_) => {}
            }
            std::thread::sleep(Duration::from_secs(30));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use zbus::zvariant::ObjectPath;

    type Changed<'a> = HashMap<&'a str, Value<'a>>;

    fn signal<B: serde::Serialize + zbus::zvariant::DynamicType>(
        path: &str,
        iface: &str,
        member: &str,
        body: &B,
    ) -> zbus::Message {
        zbus::Message::signal(path, iface, member)
            .unwrap()
            .build(body)
            .unwrap()
    }

    fn added(ifaces: &[&'static str]) -> zbus::Message {
        let ifs: HashMap<&str, Changed> = ifaces.iter().map(|i| (*i, HashMap::new())).collect();
        signal(
            "/org/freedesktop/UDisks2",
            "org.freedesktop.DBus.ObjectManager",
            "InterfacesAdded",
            &(
                ObjectPath::from_static_str_unchecked(
                    "/org/freedesktop/UDisks2/block_devices/sdb1",
                ),
                ifs,
            ),
        )
    }

    fn changed(iface: &str, props: &[&'static str]) -> zbus::Message {
        let changed: Changed = props.iter().map(|p| (*p, Value::from(0u32))).collect();
        signal(
            "/org/freedesktop/UDisks2/block_devices/sdb1",
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            &(iface, changed, Vec::<String>::new()),
        )
    }

    #[test]
    fn drive_signals() {
        let cases = [
            ("new filesystem", added(&[BLOCK, FILESYSTEM]), true),
            ("block without a filesystem", added(&[BLOCK]), false),
            (
                "mount points changed",
                changed(FILESYSTEM, &["MountPoints"]),
                true,
            ),
            (
                "other filesystem property",
                changed(FILESYSTEM, &["Size"]),
                false,
            ),
            (
                "mount points of another interface",
                changed(BLOCK, &["MountPoints"]),
                false,
            ),
            (
                "another signal",
                signal(
                    "/org/freedesktop/UDisks2",
                    "org.freedesktop.DBus.ObjectManager",
                    "InterfacesRemoved",
                    &(
                        ObjectPath::from_static_str_unchecked("/x"),
                        vec![FILESYSTEM],
                    ),
                ),
                false,
            ),
            (
                "wrong body",
                signal(
                    "/org/freedesktop/UDisks2",
                    "org.freedesktop.DBus.ObjectManager",
                    "InterfacesAdded",
                    &FILESYSTEM,
                ),
                false,
            ),
        ];
        for (name, msg, want) in cases {
            assert_eq!(is_drive_signal(&msg), want, "{name}");
        }
    }

    /// Needs unix sockets and a `dbus-daemon`, so it only runs by hand outside the Claude
    /// sandbox: `PRESERVER_DBUS_TEST=1 cargo test watcher_sees_a_plug_in`.
    #[test]
    fn watcher_sees_a_plug_in() {
        if std::env::var_os("PRESERVER_DBUS_TEST").is_none() {
            return;
        }
        let tmp = crate::testutil::TempDir::new();
        let sock = tmp.path().join("bus");
        let conf = tmp.path().join("bus.conf");
        // No service directories: nothing can be activated, so no real service ever starts.
        std::fs::write(
            &conf,
            format!(
                "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN\" \
                 \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n\
                 <busconfig><type>session</type><listen>unix:path={}</listen>\
                 <policy context=\"default\"><allow send_destination=\"*\" eavesdrop=\"true\"/>\
                 <allow eavesdrop=\"true\"/><allow own=\"*\"/></policy></busconfig>\n",
                sock.display()
            ),
        )
        .unwrap();
        let mut bus = std::process::Command::new("dbus-daemon")
            .arg(format!("--config-file={}", conf.display()))
            .arg("--nofork")
            .spawn()
            .unwrap();
        let addr = format!("unix:path={}", sock.display());
        let start = std::time::Instant::now();
        while !sock.exists() {
            assert!(start.elapsed() < Duration::from_secs(5), "no bus socket");
            std::thread::sleep(Duration::from_millis(20));
        }

        let udisks = zbus::blocking::connection::Builder::address(addr.as_str())
            .unwrap()
            .build()
            .unwrap();
        udisks.request_name(UDISKS).unwrap();
        let (tx, rx) = mpsc::channel();
        let watch_addr = addr.clone();
        watch(
            move || zbus::blocking::connection::Builder::address(watch_addr.as_str())?.build(),
            move || {
                let _ = tx.send(());
            },
        );
        // The watcher subscribes on its own thread: keep announcing until it has.
        let mut seen = false;
        for _ in 0..50 {
            let ifs: HashMap<&str, Changed> = HashMap::from([(FILESYSTEM, HashMap::new())]);
            udisks
                .emit_signal(
                    None::<&str>,
                    "/org/freedesktop/UDisks2",
                    "org.freedesktop.DBus.ObjectManager",
                    "InterfacesAdded",
                    &(
                        ObjectPath::from_static_str_unchecked(
                            "/org/freedesktop/UDisks2/block_devices/sdb1",
                        ),
                        ifs,
                    ),
                )
                .unwrap();
            if rx.recv_timeout(Duration::from_millis(100)).is_ok() {
                seen = true;
                break;
            }
        }
        let _ = bus.kill();
        let _ = bus.wait();
        assert!(seen, "no drive event within 5 s");
    }

    #[test]
    fn c_string_drops_the_terminator() {
        assert_eq!(c_string(b"/dev/sda1\0".to_vec()), "/dev/sda1");
        assert_eq!(c_string(b"/dev/sda1".to_vec()), "/dev/sda1");
        assert_eq!(c_string(Vec::new()), "");
    }
}
