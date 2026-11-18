//! Read-only probes. A probe never executes a program and never writes.

use std::io;
use std::path::Path;

pub(crate) mod fs;
pub(crate) mod registry;
pub(crate) mod sshd;

/// Largest text file a probe will load.
const MAX_TEXT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Observation {
    /// The setting has this value.
    Value(String),
    /// The setting is not configured; the rule's `default` (if any) applies.
    Absent(String),
    /// The probe decided pass/fail itself.
    #[cfg_attr(not(unix), allow(dead_code))]
    Verdict {
        pass: bool,
        observed: String,
        expected: String,
    },
    NotApplicable(String),
    Error(String),
}

pub(crate) fn read_error(path: &Path, error: &io::Error) -> Observation {
    if error.kind() == io::ErrorKind::PermissionDenied {
        Observation::Error(format!(
            "permission denied reading {}; re-run with elevated privileges",
            path.display()
        ))
    } else {
        Observation::Error(format!("cannot read {}: {error}", path.display()))
    }
}

/// Reads a text file with a size cap. Invalid UTF-8 is replaced, not rejected.
pub(crate) fn read_text(path: &Path) -> io::Result<String> {
    let size = std::fs::metadata(path)?.len();
    if size > MAX_TEXT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file is larger than {MAX_TEXT_BYTES} bytes"),
        ));
    }
    let bytes = std::fs::read(path)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
