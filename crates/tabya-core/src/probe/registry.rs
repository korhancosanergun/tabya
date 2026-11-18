use super::Observation;
use crate::model::Hive;

#[cfg(windows)]
pub(crate) fn read(hive: Hive, key: &str, value: &str) -> Observation {
    use std::io::ErrorKind;
    use winreg::enums::{
        RegType, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY,
    };
    use winreg::RegKey;

    let (root, hive_name) = match hive {
        Hive::Hklm => (HKEY_LOCAL_MACHINE, "HKLM"),
        Hive::Hkcu => (HKEY_CURRENT_USER, "HKCU"),
    };
    let location = format!("{hive_name}\\{key}\\{value}");
    let denied = || {
        Observation::Error(format!(
            "access denied reading {location}; re-run from an elevated prompt"
        ))
    };

    let subkey = match RegKey::predef(root).open_subkey_with_flags(key, KEY_READ | KEY_WOW64_64KEY)
    {
        Ok(subkey) => subkey,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Observation::Absent(format!("{hive_name}\\{key} does not exist"));
        }
        Err(e) if e.kind() == ErrorKind::PermissionDenied => return denied(),
        Err(e) => return Observation::Error(format!("cannot open {hive_name}\\{key}: {e}")),
    };

    let raw = match subkey.get_raw_value(value) {
        Ok(raw) => raw,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Observation::Absent(format!("{location} is not set"));
        }
        Err(e) if e.kind() == ErrorKind::PermissionDenied => return denied(),
        Err(e) => return Observation::Error(format!("cannot read {location}: {e}")),
    };

    let text = match raw.vtype {
        RegType::REG_DWORD => subkey.get_value::<u32, _>(value).map(|n| n.to_string()),
        RegType::REG_QWORD => subkey.get_value::<u64, _>(value).map(|n| n.to_string()),
        RegType::REG_SZ | RegType::REG_EXPAND_SZ => subkey.get_value::<String, _>(value),
        other => {
            return Observation::Error(format!(
                "{location} has unsupported registry type {other:?}"
            ));
        }
    };
    match text {
        Ok(text) => Observation::Value(text),
        Err(e) => Observation::Error(format!("cannot decode {location}: {e}")),
    }
}

#[cfg(not(windows))]
pub(crate) fn read(_hive: Hive, _key: &str, _value: &str) -> Observation {
    Observation::Error("the Windows registry cannot be read on this platform".into())
}
