#![cfg(unix)]

use super::*;
use crate::testutil::TempDir;
use std::os::unix::fs::symlink;

fn one() -> Vec<Entry> {
    vec![Entry::new(
        vec!["https://h/a".into()],
        String::new(),
        None,
        "r",
    )]
}

#[test]
fn links_are_never_read_and_a_save_replaces_them() {
    let tmp = TempDir::new();
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    save(&elsewhere, one()).unwrap();
    let target = elsewhere.join(".preserver/bad.json");
    let before = std::fs::read(&target).unwrap();

    let set = tmp.path().join("set");
    std::fs::create_dir_all(set.join(".preserver")).unwrap();
    symlink(&target, set.join(".preserver/bad.json")).unwrap();
    assert_eq!(load(&set), Vec::<Entry>::new());
    save(&set, Vec::new()).unwrap();
    assert!(
        !std::fs::symlink_metadata(set.join(".preserver/bad.json"))
            .unwrap()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&target).unwrap(), before);

    let linked = tmp.path().join("linked");
    std::fs::create_dir_all(&linked).unwrap();
    symlink(elsewhere.join(".preserver"), linked.join(".preserver")).unwrap();
    assert_eq!(load(&linked), Vec::<Entry>::new());
    assert!(save(&linked, one()).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), before);
}
