use regex::Regex;
use std::sync::LazyLock;

#[expect(clippy::expect_used, reason = "constant patterns")]
static GNU: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([0-9a-fA-F]{64}|[0-9a-fA-F]{128})\s+\*?(\S+)$").expect("constant regex")
});
#[expect(clippy::expect_used, reason = "constant patterns")]
static BSD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^SHA(?:256|512) \((\S+)\) = ([0-9a-fA-F]{64}|[0-9a-fA-F]{128})$")
        .expect("constant regex")
});

fn base(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The published hash for `name`: GNU and BSD style sum lines, or a file that is one bare hash.
/// Only sha256 and sha512 lengths are accepted, never 32-hex md5 or 40-hex sha1.
pub(crate) fn find_sum<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let mut bare = None;
    for line in text.lines().map(str::trim) {
        if let Some(m) = GNU.captures(line)
            && base(m.get(2)?.as_str()) == name
        {
            return Some(m.get(1)?.as_str());
        }
        if let Some(m) = BSD.captures(line)
            && base(m.get(1)?.as_str()) == name
        {
            return Some(m.get(2)?.as_str());
        }
        if matches!(line.len(), 64 | 128) && line.bytes().all(|b| b.is_ascii_hexdigit()) {
            bare = Some(line);
        }
    }
    bare
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sum_formats() {
        let a = "a".repeat(64);
        let b = "b".repeat(128);
        let md5 = "c".repeat(32);
        let sha1 = "d".repeat(40);
        let cases = [
            (
                "gnu",
                format!("{a}  f.iso\n{b}  other\n"),
                "f.iso",
                Some(&a),
            ),
            (
                "gnu binary mark",
                format!("{a} *f.iso\n"),
                "f.iso",
                Some(&a),
            ),
            (
                "gnu with a path",
                format!("{b}  ./dir/f.iso\n"),
                "f.iso",
                Some(&b),
            ),
            ("bsd", format!("SHA256 (f.iso) = {a}\n"), "f.iso", Some(&a)),
            (
                "bsd sha512",
                format!("SHA512 (f.iso) = {b}\r\n"),
                "f.iso",
                Some(&b),
            ),
            ("bare", format!("{a}\n"), "f.iso", Some(&a)),
            ("other name only", format!("{a}  g.iso\n"), "f.iso", None),
            ("md5 line", format!("{md5}  f.iso\n"), "f.iso", None),
            ("sha1 line", format!("{sha1}  f.iso\n"), "f.iso", None),
            ("bare md5", format!("{md5}\n"), "f.iso", None),
            (
                "comment and blank",
                format!("# sums\n\n{a}  f.iso\n"),
                "f.iso",
                Some(&a),
            ),
        ];
        for (name, text, file, want) in cases {
            assert_eq!(find_sum(&text, file), want.map(String::as_str), "{name}");
        }
    }
}
