use crate::config::DriveId;
use crate::platform::FsInfo;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use zbus::blocking::Connection;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_string_drops_the_terminator() {
        assert_eq!(c_string(b"/dev/sda1\0".to_vec()), "/dev/sda1");
        assert_eq!(c_string(b"/dev/sda1".to_vec()), "/dev/sda1");
        assert_eq!(c_string(Vec::new()), "");
    }
}
