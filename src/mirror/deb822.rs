//! deb822 control files (`Release`, `Packages`, `Sources`): stanzas of `Key: value` lines
//! separated by blank lines, a value continuing on lines that start with a space or a tab.
//! Read from any `BufRead` one stanza at a time, so a decompressed `Packages` is never held
//! whole. The input is untrusted: a malformed line is an error, never skipped.

use anyhow::{Context, Result, bail, ensure};
use std::io::{BufRead, Read};

/// No line of a control file is anywhere near this: a `Description` or a long `Depends`.
const MAX_LINE: usize = 1 << 20;

/// One stanza: fields in file order, names unique ignoring case. A continuation line is kept
/// as its own line of the value, joined by `\n` with its leading whitespace removed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Stanza(pub Vec<(String, String)>);

impl Stanza {
    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub(crate) struct Stanzas<R> {
    r: R,
    line: Vec<u8>,
    n: u64,
    failed: bool,
}

pub(crate) fn parse<R: BufRead>(r: R) -> Stanzas<R> {
    Stanzas {
        r,
        line: Vec::new(),
        n: 0,
        failed: false,
    }
}

impl<R: BufRead> Stanzas<R> {
    /// The next line number and the line without its `\n`, or `None` at the end of the input.
    fn next_line(&mut self) -> Result<Option<(u64, &str)>> {
        self.line.clear();
        let got = (&mut self.r)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut self.line)
            .context("reading a control file")?;
        if got == 0 {
            return Ok(None);
        }
        self.n += 1;
        if self.line.last() == Some(&b'\n') {
            self.line.pop();
        }
        ensure!(self.line.len() <= MAX_LINE, "line {} is too long", self.n);
        let line = std::str::from_utf8(&self.line)
            .with_context(|| format!("line {} is not UTF-8", self.n))?;
        Ok(Some((self.n, line)))
    }

    fn stanza(&mut self) -> Result<Option<Stanza>> {
        let mut fields: Vec<(String, String)> = Vec::new();
        while let Some((n, line)) = self.next_line()? {
            if line.is_empty() {
                if fields.is_empty() {
                    continue;
                }
                break;
            }
            if line.starts_with([' ', '\t']) {
                let more = line.trim_matches([' ', '\t']);
                let Some((_, value)) = fields.last_mut() else {
                    bail!("line {n}: continuation before any field");
                };
                ensure!(!more.is_empty(), "line {n}: empty continuation line");
                if !value.is_empty() {
                    value.push('\n');
                }
                value.push_str(more);
                continue;
            }
            let Some((name, value)) = line.split_once(':') else {
                bail!("line {n}: no colon");
            };
            ensure!(
                !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "line {n}: bad field name {name:?}"
            );
            ensure!(
                !fields.iter().any(|(k, _)| k.eq_ignore_ascii_case(name)),
                "line {n}: field {name} twice in one stanza"
            );
            fields.push((name.to_owned(), value.trim_matches([' ', '\t']).to_owned()));
        }
        Ok((!fields.is_empty()).then_some(Stanza(fields)))
    }
}

impl<R: BufRead> Iterator for Stanzas<R> {
    type Item = Result<Stanza>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let s = self.stanza().transpose();
        self.failed = matches!(s, Some(Err(_)));
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    fn all(text: &[u8]) -> Result<Vec<Stanza>> {
        parse(Cursor::new(text)).collect()
    }

    fn stanza(fields: &[(&str, &str)]) -> Stanza {
        Stanza(
            fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
    }

    #[test]
    fn parses_stanzas() {
        let cases: [(&str, &[u8], Vec<Stanza>); 8] = [
            ("empty", b"", vec![]),
            ("only blanks", b"\n\n\n", vec![]),
            (
                "one stanza, no final newline",
                b"Suite: stable\nCodename:trixie",
                vec![stanza(&[("Suite", "stable"), ("Codename", "trixie")])],
            ),
            (
                "folded value",
                b"SHA256:\n aa 1 a/b\n\tbb  2 c\nDate: x\n",
                vec![stanza(&[("SHA256", "aa 1 a/b\nbb  2 c"), ("Date", "x")])],
            ),
            (
                "first line and continuation",
                b"Description: one\n two\n",
                vec![stanza(&[("Description", "one\ntwo")])],
            ),
            (
                "blank lines between stanzas",
                b"\nA: 1\n\n\nA: 2\nB: 3\n\n",
                vec![stanza(&[("A", "1")]), stanza(&[("A", "2"), ("B", "3")])],
            ),
            (
                "spaces around the value",
                b"A:  \t x y \t\n",
                vec![stanza(&[("A", "x y")])],
            ),
            (
                "colon in the value",
                b"Date: Sat, 01 Jan 2026 10:00:00 UTC\n",
                vec![stanza(&[("Date", "Sat, 01 Jan 2026 10:00:00 UTC")])],
            ),
        ];
        for (name, text, want) in cases {
            assert_eq!(all(text).unwrap(), want, "{name}");
        }
    }

    #[test]
    fn refuses_malformed_input() {
        let long = format!("A: {}\n", "x".repeat(MAX_LINE));
        let cases: [(&str, &[u8]); 9] = [
            ("no colon", b"A: 1\nnonsense\n"),
            ("empty name", b": 1\n"),
            ("space in name", b"A B: 1\n"),
            ("continuation first", b" lost\nA: 1\n"),
            ("blank continuation", b"A: 1\n \t\nB: 2\n"),
            ("duplicate field", b"Suite: a\nsuite: b\n"),
            ("not UTF-8", b"A: \xff\n"),
            ("line too long", long.as_bytes()),
            ("error in a later stanza", b"A: 1\n\nbad\n"),
        ];
        for (name, text) in cases {
            assert!(all(text).is_err(), "{name}");
        }
    }

    #[test]
    fn an_error_ends_the_iteration() {
        let mut it = parse(Cursor::new(&b"A: 1\n\nbad\n\nB: 2\n"[..]));
        assert!(it.next().unwrap().is_ok());
        assert!(it.next().unwrap().is_err());
        assert!(it.next().is_none());
    }

    fn render(stanzas: &[Stanza]) -> String {
        let mut out = String::new();
        for s in stanzas {
            for (k, v) in &s.0 {
                let mut lines = v.split('\n');
                out.extend([k, ": ", lines.next().unwrap_or(""), "\n"]);
                for l in lines {
                    out.extend([" ", l, "\n"]);
                }
            }
            out.push('\n');
        }
        out
    }

    fn arb_stanzas() -> impl proptest::strategy::Strategy<Value = Vec<Stanza>> {
        use proptest::prelude::*;
        let field = (
            "[A-Za-z][A-Za-z0-9-]{0,8}",
            proptest::collection::vec("[!-~]([ -~]{0,20}[!-~])?", 1..4),
        )
            .prop_map(|(k, lines)| (k, lines.join("\n")));
        proptest::collection::vec(
            proptest::collection::vec(field, 1..5).prop_filter_map("unique names", |f| {
                let mut seen = std::collections::HashSet::new();
                f.iter()
                    .all(|(k, _)| seen.insert(k.to_ascii_lowercase()))
                    .then_some(Stanza(f))
            }),
            0..4,
        )
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        #[test]
        fn render_then_parse_is_the_identity(stanzas in arb_stanzas()) {
            proptest::prop_assert_eq!(all(render(&stanzas).as_bytes()).unwrap(), stanzas);
        }

        #[test]
        fn a_one_byte_reader_gives_the_same_result(text in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..200)) {
            let whole = all(&text).map_err(|e| e.to_string());
            let slow = parse(BufReader::with_capacity(1, Cursor::new(&text)))
                .collect::<Result<Vec<_>>>()
                .map_err(|e| e.to_string());
            proptest::prop_assert_eq!(whole, slow);
        }

        #[test]
        fn text_like_input_never_panics(text in "([A-Za-z: \t\n.-]|\n){0,300}") {
            let _ = all(text.as_bytes());
        }
    }
}
