//! Targeted edits of config.toml that keep every comment and every other byte. No TOML writer:
//! an edit rewrites only the lines of one assignment or one `[[local]]` block, then proves
//! itself by parsing the result, which must equal the old file's table with exactly that edit
//! applied and must still load as a `Config`. Anything it cannot prove is refused, unwritten.

use crate::config::Config;
use crate::paths::Paths;
use anyhow::{Context, Result, bail};
use toml::{Table, Value};

#[cfg_attr(
    not(any(test, feature = "gui")),
    expect(
        dead_code,
        reason = "the GUI edits [schedule]; the CLI only sets transport"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Place {
    Top(&'static str),
    Schedule(&'static str),
    Local(usize, &'static str),
}

#[cfg_attr(
    not(any(test, feature = "gui")),
    expect(
        dead_code,
        reason = "the GUI makes these edits; the CLI only sets transport"
    )
)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Edit {
    Set(Place, Value),
    Unset(Place),
    AddLocal(Table),
    RemoveLocal(usize),
}

const REFUSED: &str =
    "cannot make this change without touching other settings; edit config.toml by hand";

/// A table header's name with whitespace and a trailing comment dropped: `[schedule]`, `[[local]]`.
fn header(line: &str) -> Option<String> {
    let t = line.trim_start();
    if !t.starts_with('[') {
        return None;
    }
    let t = t.split('#').next().unwrap_or_default();
    Some(t.chars().filter(|c| !c.is_whitespace()).collect())
}

/// The line range of a section's body: the top level, `[schedule]` or the i-th `[[local]]`.
/// The range starts after the header, so an empty body is `h+1..h+1`.
fn section(lines: &[&str], place: Place) -> Option<(usize, usize)> {
    let headers: Vec<(usize, String)> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| Some((i, header(l)?)))
        .collect();
    let end_after = |h: usize| {
        headers
            .iter()
            .map(|(i, _)| *i)
            .find(|i| *i > h)
            .unwrap_or(lines.len())
    };
    let named = |name: &str, n: usize| {
        headers
            .iter()
            .filter(|(_, h)| h == name)
            .nth(n)
            .map(|(i, _)| (i + 1, end_after(*i)))
    };
    match place {
        Place::Top(_) => Some((0, headers.first().map_or(lines.len(), |(i, _)| *i))),
        Place::Schedule(_) => named("[schedule]", 0),
        Place::Local(i, _) => named("[[local]]", i),
    }
}

fn key_of(place: Place) -> &'static str {
    match place {
        Place::Top(k) | Place::Schedule(k) | Place::Local(_, k) => k,
    }
}

fn parses_to(text: &str, key: &str) -> Option<Value> {
    toml::from_str::<Table>(text).ok()?.remove(key)
}

/// The assignment of `key` in `range`: its first and last line, and the text kept after the
/// value on the last line (spacing, comment and line end).
fn assignment(lines: &[&str], range: (usize, usize), key: &str) -> Option<(usize, usize, String)> {
    let start = (range.0..range.1).find(|&i| {
        lines[i]
            .trim_start()
            .strip_prefix(key)
            .is_some_and(|rest| rest.trim_start().starts_with('='))
    })?;
    let end = (start..range.1).find(|&i| parses_to(&lines[start..=i].concat(), key).is_some())?;
    let value = parses_to(&lines[start..=end].concat(), key)?;
    let head = lines[start..end].concat();
    let last = lines[end];
    let newline = &last[last.trim_end_matches(['\n', '\r']).len()..];
    // The first `#` before which the line still reads as the same value starts the comment.
    let tail = last
        .match_indices('#')
        .map(|(p, _)| p)
        .find(|&p| parses_to(&format!("{head}{}", &last[..p]), key).as_ref() == Some(&value))
        .map_or_else(
            || newline.to_string(),
            |p| {
                let before = &last[..p];
                format!("{}{}", &before[before.trim_end().len()..], &last[p..])
            },
        );
    Some((start, end, tail))
}

/// Inserts `line` after the last line of `range` that is neither blank nor a comment, so a
/// comment block above the next header stays with it.
fn insert(lines: &mut Vec<String>, range: (usize, usize), line: String) {
    let at = (range.0..range.1)
        .rev()
        .find(|&i| {
            let t = lines[i].trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .map_or(range.0, |i| i + 1);
    if at > 0 && !lines[at - 1].ends_with('\n') {
        lines[at - 1].push('\n');
    }
    lines.insert(at, line);
}

fn append(lines: &mut Vec<String>, block: String) {
    if let Some(last) = lines.last_mut().filter(|l| !l.ends_with('\n')) {
        last.push('\n');
    }
    lines.push(block);
}

fn local_block(t: &Table) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("\n[[local]]\n");
    let first = ["name", "path"];
    let keys = first
        .iter()
        .copied()
        .filter(|k| t.contains_key(*k))
        .chain(t.keys().map(String::as_str).filter(|k| !first.contains(k)));
    for k in keys {
        let _ = writeln!(out, "{k} = {}", t[k]);
    }
    out
}

/// The old table with the edit applied: what the edited text must parse to.
fn expected(mut table: Table, edit: &Edit) -> Result<Table> {
    fn locals(table: &mut Table) -> Option<&mut Vec<Value>> {
        table.get_mut("local")?.as_array_mut()
    }
    match edit {
        Edit::Set(Place::Top(key), value) => {
            table.insert((*key).into(), value.clone());
        }
        Edit::Unset(Place::Top(key)) => {
            table.remove(*key);
        }
        Edit::Set(Place::Schedule(key), value) => {
            let sched = table
                .entry("schedule")
                .or_insert_with(|| Value::Table(Table::new()));
            sched
                .as_table_mut()
                .context(REFUSED)?
                .insert((*key).into(), value.clone());
        }
        Edit::Unset(Place::Schedule(key)) => {
            if let Some(sched) = table.get_mut("schedule").and_then(Value::as_table_mut) {
                sched.remove(*key);
            }
        }
        Edit::Set(Place::Local(idx, key), value) => {
            let folder = locals(&mut table).and_then(|list| list.get_mut(*idx)?.as_table_mut());
            folder
                .context("no such local folder")?
                .insert((*key).into(), value.clone());
        }
        Edit::Unset(Place::Local(idx, key)) => {
            let folder = locals(&mut table).and_then(|list| list.get_mut(*idx)?.as_table_mut());
            folder.context("no such local folder")?.remove(*key);
        }
        Edit::AddLocal(folder) => match table.get_mut("local") {
            Some(list) => list
                .as_array_mut()
                .context(REFUSED)?
                .push(Value::Table(folder.clone())),
            None => {
                table.insert(
                    "local".into(),
                    Value::Array(vec![Value::Table(folder.clone())]),
                );
            }
        },
        Edit::RemoveLocal(idx) => {
            let list = locals(&mut table).context("no such local folder")?;
            if *idx >= list.len() {
                bail!("no such local folder");
            }
            list.remove(*idx);
            if list.is_empty() {
                table.remove("local");
            }
        }
    }
    Ok(table)
}

/// The config text with one edit made, every other byte as it was.
pub(crate) fn apply(text: &str, edit: &Edit) -> Result<String> {
    Config::parse(text).context("config.toml does not load")?;
    let old: Table = toml::from_str(text)?;
    let mut lines: Vec<String> = text.split_inclusive('\n').map(str::to_string).collect();
    let view: Vec<&str> = text.split_inclusive('\n').collect();
    match edit {
        Edit::Set(place, v) => {
            let key = key_of(*place);
            match section(&view, *place) {
                Some(range) => match assignment(&view, range, key) {
                    Some((start, end, tail)) => {
                        let (lead, _) = view[start].split_once('=').context(REFUSED)?;
                        lines.splice(start..=end, [format!("{lead}= {v}{tail}")]);
                    }
                    None => insert(&mut lines, range, format!("{key} = {v}\n")),
                },
                None if matches!(place, Place::Schedule(_)) => {
                    append(&mut lines, format!("\n[schedule]\n{key} = {v}\n"));
                }
                None => bail!("no such local folder"),
            }
        }
        Edit::Unset(place) => {
            if let Some((start, end, _)) =
                section(&view, *place).and_then(|r| assignment(&view, r, key_of(*place)))
            {
                lines.drain(start..=end);
            }
        }
        Edit::AddLocal(f) => append(&mut lines, local_block(f)),
        Edit::RemoveLocal(i) => {
            let (body, end) =
                section(&view, Place::Local(*i, "")).context("no such local folder")?;
            // Comment lines right above the next header describe that header.
            let mut keep_from = end;
            if end < view.len() {
                while keep_from > body && view[keep_from - 1].trim_start().starts_with('#') {
                    keep_from -= 1;
                }
            }
            lines.drain(body - 1..keep_from);
        }
    }
    let new = lines.concat();
    let want = expected(old, edit)?;
    if toml::from_str::<Table>(&new).ok() != Some(want) {
        bail!(REFUSED);
    }
    Config::parse(&new)?;
    Ok(new)
}

/// Makes every edit to `config.toml` and writes the file once, or not at all. The edits were
/// made against the file as some form loaded it: `loaded` refuses unless the file still says
/// that, since an index-based folder edit on a changed file would hit another folder.
#[cfg_attr(
    not(any(test, feature = "gui")),
    expect(
        dead_code,
        reason = "the GUI's Settings page saves; the CLI only sets transport"
    )
)]
pub(crate) fn save(
    paths: &Paths,
    edits: &[Edit],
    loaded: impl FnOnce(&Config) -> Result<()>,
) -> Result<()> {
    crate::config::rewrite(paths, |text| {
        loaded(&Config::parse(text)?)?;
        edits.iter().try_fold(text.to_string(), |t, e| apply(&t, e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# preserver settings
owners = [
  \"alice\",   # me
  \"some-org\",
]
primary_uuid = \"0123abcd-2d54\"
reserve_percent = 20 # keep room

# folders to archive
[[local]]
name = \"docs\"
path = \"/home/u/docs\" # the important one

# second folder
[[local]]
name = \"pics\"
path = \"/home/u/pics\"

# third
[[local]]
name = \"code\"
path = \"/home/u/code\"
";

    fn s(v: &str) -> Value {
        Value::String(v.into())
    }

    fn folder(name: &str, path: &str) -> Table {
        let mut t = Table::new();
        t.insert("name".into(), s(name));
        t.insert("path".into(), s(path));
        t
    }

    #[test]
    fn edits_touch_only_their_lines() {
        let cases: Vec<(&str, Edit, String)> = vec![
            (
                "existing top key keeps its comment",
                Edit::Set(Place::Top("reserve_percent"), Value::Integer(30)),
                SAMPLE.replace(
                    "reserve_percent = 20 # keep room",
                    "reserve_percent = 30 # keep room",
                ),
            ),
            (
                "missing top key goes after the last top-level assignment",
                Edit::Set(Place::Top("bandwidth_mbit"), Value::Integer(5)),
                SAMPLE.replace("# keep room\n", "# keep room\nbandwidth_mbit = 5\n"),
            ),
            (
                "multi-line owners become one line",
                Edit::Set(Place::Top("owners"), Value::Array(vec![s("bob")])),
                SAMPLE.replace(
                    "owners = [\n  \"alice\",   # me\n  \"some-org\",\n]\n",
                    "owners = [\"bob\"]\n",
                ),
            ),
            (
                "schedule table appended after the [[local]] blocks",
                Edit::Set(Place::Schedule("local"), s("01:30")),
                format!("{SAMPLE}\n[schedule]\nlocal = \"01:30\"\n"),
            ),
            (
                "folder path keeps its comment",
                Edit::Set(Place::Local(0, "path"), s("/srv/docs")),
                SAMPLE.replace("\"/home/u/docs\" # the", "\"/srv/docs\" # the"),
            ),
            (
                "origin is added to its own block",
                Edit::Set(Place::Local(1, "origin"), s("google")),
                SAMPLE.replace(
                    "path = \"/home/u/pics\"\n",
                    "path = \"/home/u/pics\"\norigin = \"google\"\n",
                ),
            ),
            (
                "add a folder",
                Edit::AddLocal(folder("music", "/m")),
                format!("{SAMPLE}\n[[local]]\nname = \"music\"\npath = \"/m\"\n"),
            ),
            (
                "remove the first folder, the next one's comment stays",
                Edit::RemoveLocal(0),
                SAMPLE.replace(
                    "[[local]]\nname = \"docs\"\npath = \"/home/u/docs\" # the important one\n\n",
                    "",
                ),
            ),
            (
                "remove the middle folder",
                Edit::RemoveLocal(1),
                SAMPLE.replace(
                    "[[local]]\nname = \"pics\"\npath = \"/home/u/pics\"\n\n",
                    "",
                ),
            ),
            (
                "remove the last folder",
                Edit::RemoveLocal(2),
                SAMPLE.replace("[[local]]\nname = \"code\"\npath = \"/home/u/code\"\n", ""),
            ),
            (
                "unset a key that is not there changes nothing",
                Edit::Unset(Place::Schedule("public")),
                SAMPLE.to_string(),
            ),
        ];
        for (name, edit, want) in cases {
            let got = apply(SAMPLE, &edit).unwrap_or_else(|e| panic!("{name}: {e:#}"));
            assert_eq!(got, want, "{name}");
            if matches!(edit, Edit::Set(..) | Edit::Unset(_)) {
                assert_eq!(apply(&got, &edit).unwrap(), got, "{name}: idempotent");
            }
        }
    }

    #[test]
    fn schedule_set_and_unset_inside_the_table() {
        let text = format!("{SAMPLE}\n[schedule]\npersonal = \"24:00:00\" # daily-ish\n");
        let got = apply(
            &text,
            &Edit::Set(Place::Schedule("personal"), s("12:00:00")),
        )
        .unwrap();
        assert_eq!(got, text.replace("24:00:00", "12:00:00"));
        let got = apply(&got, &Edit::Set(Place::Schedule("public"), s("03:00"))).unwrap();
        assert!(got.ends_with("# daily-ish\npublic = \"03:00\"\n"), "{got}");
        let got = apply(&got, &Edit::Unset(Place::Schedule("personal"))).unwrap();
        assert!(got.ends_with("\n[schedule]\npublic = \"03:00\"\n"), "{got}");
        let got = apply(&got, &Edit::Unset(Place::Schedule("public"))).unwrap();
        assert_eq!(got, format!("{SAMPLE}\n[schedule]\n"));
        let c = Config::parse(&got).unwrap();
        assert!(c.schedule.personal.is_none() && c.schedule.public.is_none());
    }

    #[test]
    fn refusals_leave_nothing_half_done() {
        let dotted = format!("schedule.personal = \"1:00:00\"\n{SAMPLE}");
        let inline = format!("schedule = {{ personal = \"1:00:00\" }}\n{SAMPLE}");
        let cases: Vec<(&str, String, Edit)> = vec![
            (
                "reserve over 90",
                SAMPLE.into(),
                Edit::Set(Place::Top("reserve_percent"), Value::Integer(95)),
            ),
            (
                "relative path",
                SAMPLE.into(),
                Edit::Set(Place::Local(0, "path"), s("docs")),
            ),
            (
                "duplicate folder name",
                SAMPLE.into(),
                Edit::AddLocal(folder("docs", "/x")),
            ),
            (
                "bad schedule",
                SAMPLE.into(),
                Edit::Set(Place::Schedule("local"), s("25:00")),
            ),
            (
                "unknown schedule key",
                SAMPLE.into(),
                Edit::Set(Place::Schedule("weekly"), s("01:00")),
            ),
            (
                "bad origin",
                SAMPLE.into(),
                Edit::Set(Place::Local(0, "origin"), s("Google Drive")),
            ),
            (
                "dotted schedule key at top level",
                dotted,
                Edit::Set(Place::Schedule("personal"), s("2:00:00")),
            ),
            (
                "schedule as an inline table",
                inline,
                Edit::Set(Place::Schedule("personal"), s("2:00:00")),
            ),
            ("no such folder", SAMPLE.into(), Edit::RemoveLocal(3)),
            (
                "a key line inside a multi-line string",
                format!("note = \"\"\"\nbandwidth_mbit = 1\n\"\"\"\n{SAMPLE}"),
                Edit::Set(Place::Top("bandwidth_mbit"), Value::Integer(2)),
            ),
            (
                "broken config",
                "owners = [\n".into(),
                Edit::Set(Place::Top("bandwidth_mbit"), Value::Integer(2)),
            ),
        ];
        for (name, text, edit) in cases {
            assert!(apply(&text, &edit).is_err(), "{name}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_once_or_not_at_all() {
        let tmp = crate::testutil::TempDir::new();
        let paths = crate::testutil::paths(tmp.path());
        std::fs::create_dir_all(&paths.cfg).unwrap();
        let file = paths.cfg.join("config.toml");
        std::fs::write(&file, SAMPLE).unwrap();
        let any = |_: &Config| Ok(());
        let ok = [
            Edit::Set(Place::Top("bandwidth_mbit"), Value::Integer(5)),
            Edit::RemoveLocal(2),
        ];
        save(&paths, &ok, any).unwrap();
        let c = Config::load(&paths.cfg).unwrap();
        assert_eq!((c.bandwidth_mbit, c.local.len()), (5, 2));
        let before = std::fs::read_to_string(&file).unwrap();
        let bad = [
            Edit::Set(Place::Top("bandwidth_mbit"), Value::Integer(9)),
            Edit::Set(Place::Top("reserve_percent"), Value::Integer(99)),
        ];
        assert!(save(&paths, &bad, any).is_err());
        let stale = |c: &Config| {
            anyhow::ensure!(c.local.len() == 3, "changed since it was loaded");
            Ok(())
        };
        let e = save(&paths, &ok[..1], stale).unwrap_err();
        assert!(e.to_string().contains("changed"), "{e:#}");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    }
}
