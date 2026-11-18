//! Effective global `sshd_config` settings, resolved from files only.
//!
//! Mirrors how sshd reads its configuration: the first value seen for a
//! keyword wins, `Include` is expanded in place, and anything inside a
//! `Match` block is conditional and therefore not part of the global result.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use super::{read_error, read_text, Observation};
use crate::engine::Context;

const MAIN_CONFIG: &str = "/etc/ssh/sshd_config";
const CONFIG_DIR: &str = "/etc/ssh";
const MAX_INCLUDE_DEPTH: usize = 16;

pub(crate) fn lookup(ctx: &Context, key: &str) -> Observation {
    let main = ctx.resolve(MAIN_CONFIG);
    let mut settings = HashMap::new();
    match parse_file(ctx, &main, 0, &mut settings) {
        Ok(()) => {}
        Err(Failure::MainMissing) => {
            return Observation::NotApplicable(format!(
                "{MAIN_CONFIG} does not exist (OpenSSH server not installed)"
            ));
        }
        Err(Failure::Read(path, error)) => return read_error(&path, &error),
        Err(Failure::TooDeep) => {
            return Observation::Error(format!(
                "sshd_config Include nesting exceeds {MAX_INCLUDE_DEPTH} levels"
            ));
        }
    }
    match settings.remove(&key.to_ascii_lowercase()) {
        Some(value) => Observation::Value(value),
        None => Observation::Absent(format!("{key} is not set in sshd_config")),
    }
}

enum Failure {
    MainMissing,
    Read(PathBuf, io::Error),
    TooDeep,
}

fn parse_file(
    ctx: &Context,
    path: &Path,
    depth: usize,
    settings: &mut HashMap<String, String>,
) -> Result<(), Failure> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(Failure::TooDeep);
    }
    let text = match read_text(path) {
        Ok(text) => text,
        Err(e) if depth == 0 && e.kind() == io::ErrorKind::NotFound => {
            return Err(Failure::MainMissing);
        }
        Err(e) => return Err(Failure::Read(path.to_owned(), e)),
    };

    let mut in_match = false;
    for line in text.lines() {
        let Some((keyword, value)) = split_directive(line) else {
            continue;
        };
        match keyword.as_str() {
            "match" => in_match = !value.eq_ignore_ascii_case("all"),
            _ if in_match => {}
            "include" => {
                for pattern in value.split_whitespace() {
                    for included in expand_include(ctx, pattern)? {
                        parse_file(ctx, &included, depth + 1, settings)?;
                    }
                }
            }
            _ => {
                settings.entry(keyword).or_insert(value);
            }
        }
    }
    Ok(())
}

/// Splits `Keyword value` or `Keyword=value`; returns a lowercase keyword.
fn split_directive(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let keyword = line[..end].to_ascii_lowercase();
    let rest = line[end..].trim_start_matches(|c: char| c.is_whitespace() || c == '=');
    // Trailing comments are accepted by current OpenSSH releases.
    let rest = match rest.find(" #").or_else(|| rest.find("\t#")) {
        Some(index) if !rest.starts_with('"') => &rest[..index],
        _ => rest,
    };
    let value = rest.trim().trim_matches('"').to_owned();
    if keyword.is_empty() {
        return None;
    }
    Some((keyword, value))
}

/// Expands one `Include` pattern to existing files, sorted like sshd does.
fn expand_include(ctx: &Context, pattern: &str) -> Result<Vec<PathBuf>, Failure> {
    let pattern = pattern.trim_matches('"');
    let absolute = if pattern.starts_with('/') {
        pattern.to_owned()
    } else {
        format!("{CONFIG_DIR}/{pattern}")
    };
    let Some((dir, file_pattern)) = absolute.rsplit_once('/') else {
        return Ok(Vec::new());
    };
    // Only the final component may be a wildcard here; the directory part is
    // escaped so an audited root containing glob characters stays literal.
    let dir = ctx.resolve(if dir.is_empty() { "/" } else { dir });
    let full = format!(
        "{}/{}",
        glob::Pattern::escape(&dir.to_string_lossy()),
        file_pattern
    );
    let Ok(paths) = glob::glob(&full) else {
        return Ok(Vec::new());
    };
    let mut files = Vec::new();
    for entry in paths {
        match entry {
            Ok(path) if path.is_file() => files.push(path),
            Ok(_) => {}
            Err(e) => {
                let path = e.path().to_owned();
                return Err(Failure::Read(path, e.into()));
            }
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn root_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("tempdir");
        for (path, content) in files {
            let full = root.path().join(path.trim_start_matches('/'));
            fs::create_dir_all(full.parent().expect("parent")).expect("mkdir");
            fs::write(full, content).expect("write");
        }
        root
    }

    fn value(root: &tempfile::TempDir, key: &str) -> Observation {
        lookup(&Context::offline_root(root.path()), key)
    }

    #[test]
    fn directive_forms() {
        assert_eq!(
            split_directive("PermitRootLogin no"),
            Some(("permitrootlogin".into(), "no".into()))
        );
        assert_eq!(
            split_directive("  Port=2222  # custom"),
            Some(("port".into(), "2222".into()))
        );
        assert_eq!(
            split_directive("Banner \"/etc/issue net\""),
            Some(("banner".into(), "/etc/issue net".into()))
        );
        assert_eq!(split_directive("# PasswordAuthentication yes"), None);
        assert_eq!(split_directive("   "), None);
    }

    #[test]
    fn first_value_wins_across_includes() {
        let root = root_with(&[
            (
                "/etc/ssh/sshd_config",
                "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\nX11Forwarding yes\n",
            ),
            (
                "/etc/ssh/sshd_config.d/10-hardening.conf",
                "PasswordAuthentication no\n",
            ),
            (
                "/etc/ssh/sshd_config.d/50-cloud.conf",
                "PasswordAuthentication yes\n",
            ),
        ]);
        assert_eq!(
            value(&root, "PasswordAuthentication"),
            Observation::Value("no".into())
        );
        assert_eq!(
            value(&root, "x11forwarding"),
            Observation::Value("yes".into())
        );
    }

    #[test]
    fn relative_include_and_match_blocks() {
        let root = root_with(&[
            (
                "/etc/ssh/sshd_config",
                "Include extra.conf\nMatch User backup\n  PermitRootLogin yes\nMatch all\nMaxAuthTries 3\n",
            ),
            ("/etc/ssh/extra.conf", "Match Address 10.0.0.0/8\nPasswordAuthentication yes\n"),
        ]);
        // Conditional values are not global settings.
        assert!(matches!(
            value(&root, "PermitRootLogin"),
            Observation::Absent(_)
        ));
        assert!(matches!(
            value(&root, "PasswordAuthentication"),
            Observation::Absent(_)
        ));
        // A Match in an included file ends with that file; `Match all` resets.
        assert_eq!(value(&root, "MaxAuthTries"), Observation::Value("3".into()));
    }

    #[test]
    fn missing_server_is_not_applicable() {
        let root = root_with(&[("/etc/hostname", "box\n")]);
        assert!(matches!(
            value(&root, "PermitRootLogin"),
            Observation::NotApplicable(_)
        ));
    }
}
