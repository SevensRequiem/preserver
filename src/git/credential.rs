use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::process::{Command, Stdio};

/// The file name under which git starts this binary as its credential helper.
pub const HELPER: &str = "preserver-credential";

/// Set only on the `git fetch` child, which passes it on to the helper.
pub(crate) const TOKEN_ENV: &str = "PRESERVER_GH_TOKEN";

/// Asks the gh CLI for its token. It travels by pipe and environment only.
pub(crate) fn token() -> Result<String> {
    let out = Command::new("gh")
        .args(["auth", "token", "--hostname", "github.com"])
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .context("run gh")?;
    if !out.status.success() {
        bail!("gh auth token: {}", out.status);
    }
    let token = String::from_utf8(out.stdout)
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic()))
        .context("gh auth token printed no usable token")?;
    Ok(token)
}

/// The answer to git's credential request: the token, and only for github.com over https.
fn reply(request: &str, token: &str) -> Option<String> {
    let has = |line: &str| request.lines().any(|l| l == line);
    (has("protocol=https") && has("host=github.com"))
        .then(|| format!("username=x-access-token\npassword={token}\n"))
}

/// git credential helper protocol: `get` reads the request on stdin and prints the credential.
///
/// # Errors
/// Fails when stdin or stdout fails.
pub fn helper_main(mut args: impl Iterator<Item = OsString>) -> Result<()> {
    if args.next().is_none_or(|op| op != "get") {
        return Ok(());
    }
    let mut request = String::new();
    std::io::stdin()
        .take(64 * 1024)
        .read_to_string(&mut request)?;
    let Ok(token) = std::env::var(TOKEN_ENV) else {
        return Ok(());
    };
    if let Some(answer) = reply(&request, &token) {
        std::io::stdout().write_all(answer.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_goes_only_to_github_over_https() {
        let cases = [
            ("github https", "protocol=https\nhost=github.com\n\n", true),
            (
                "with a path",
                "protocol=https\nhost=github.com\npath=o/r.git\n",
                true,
            ),
            ("plain http", "protocol=http\nhost=github.com\n", false),
            ("other host", "protocol=https\nhost=example.com\n", false),
            (
                "lookalike host",
                "protocol=https\nhost=github.com.example.com\n",
                false,
            ),
            (
                "host with a port",
                "protocol=https\nhost=github.com:8443\n",
                false,
            ),
            (
                "host hidden in a path",
                "protocol=https\nhost=example.com\npath=host=github.com\n",
                false,
            ),
            ("empty", "", false),
        ];
        for (name, request, answered) in cases {
            let got = reply(request, "tok");
            assert_eq!(got.is_some(), answered, "{name}");
            if let Some(got) = got {
                assert_eq!(got, "username=x-access-token\npassword=tok\n", "{name}");
            }
        }
    }
}
