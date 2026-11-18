use std::io;

use super::{read_error, read_text, Observation};
use crate::engine::Context;
use crate::model::{compile_pattern, parse_mode};

pub(crate) fn sysctl(ctx: &Context, key: &str) -> Observation {
    if ctx.is_offline() {
        return Observation::NotApplicable(
            "kernel parameters are runtime state and cannot be read from an offline root".into(),
        );
    }
    let path = ctx.resolve(&format!("/proc/sys/{}", key.replace('.', "/")));
    match read_text(&path) {
        Ok(text) => Observation::Value(text.trim().to_owned()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            Observation::NotApplicable(format!("sysctl {key} does not exist on this kernel"))
        }
        Err(e) => read_error(&path, &e),
    }
}

pub(crate) fn file_match(ctx: &Context, path: &str, pattern: &str) -> Observation {
    let regex = match compile_pattern(pattern) {
        Ok(regex) => regex,
        Err(e) => return Observation::Error(format!("pattern does not compile: {e}")),
    };
    let resolved = ctx.resolve(path);
    let text = match read_text(&resolved) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Observation::Absent(format!("{path} does not exist"));
        }
        Err(e) => return read_error(&resolved, &e),
    };
    match regex.captures(&text) {
        Some(captures) => {
            let hit = captures.get(1).or_else(|| captures.get(0));
            Observation::Value(hit.map_or("", |m| m.as_str()).trim().to_owned())
        }
        None => Observation::Absent(format!("no line in {path} sets this")),
    }
}

#[cfg(unix)]
pub(crate) fn file_mode(
    ctx: &Context,
    path: &str,
    max_mode: &str,
    owner_uid: Option<u32>,
) -> Observation {
    use std::os::unix::fs::MetadataExt;

    let Some(max) = parse_mode(max_mode) else {
        return Observation::Error(format!("invalid max_mode `{max_mode}`"));
    };
    let resolved = ctx.resolve(path);
    let metadata = match std::fs::metadata(&resolved) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Observation::NotApplicable(format!("{path} does not exist"));
        }
        Err(e) => return read_error(&resolved, &e),
    };

    let mode = metadata.mode() & 0o7777;
    let uid = metadata.uid();
    let mode_ok = mode & !max == 0;
    let owner_ok = owner_uid.is_none_or(|expected| expected == uid);

    let mut expected = format!("mode {max:04o} or stricter");
    if let Some(owner) = owner_uid {
        expected.push_str(&format!(", owner uid {owner}"));
    }
    Observation::Verdict {
        pass: mode_ok && owner_ok,
        observed: format!("mode {mode:04o}, owner uid {uid}"),
        expected,
    }
}

#[cfg(not(unix))]
pub(crate) fn file_mode(
    _ctx: &Context,
    _path: &str,
    max_mode: &str,
    _owner_uid: Option<u32>,
) -> Observation {
    let _ = parse_mode(max_mode);
    Observation::Error("POSIX file modes cannot be read on this platform".into())
}
