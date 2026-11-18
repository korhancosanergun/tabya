use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use regex::RegexBuilder;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(format!(
                "unknown severity `{other}` (expected info, low, medium, high or critical)"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Linux,
    Windows,
}

impl Platform {
    /// Platform of the running binary, if tabya has rules for it.
    pub fn current() -> Option<Platform> {
        if cfg!(target_os = "linux") {
            Some(Platform::Linux)
        } else if cfg!(windows) {
            Some(Platform::Windows)
        } else {
            None
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::Windows => "windows",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Hive {
    Hklm,
    Hkcu,
}

/// A YAML scalar kept as text, so rule authors can write `equals: 0`,
/// `equals: "0"` or `equals: no` interchangeably.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scalar(pub String);

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ScalarVisitor;

        impl Visitor<'_> for ScalarVisitor {
            type Value = Scalar;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string, integer or boolean")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Scalar, E> {
                Ok(Scalar(v.to_owned()))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Scalar, E> {
                Ok(Scalar(v.to_string()))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Scalar, E> {
                Ok(Scalar(v.to_string()))
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Scalar, E> {
                // YAML 1.1 style `yes`/`no` never reach here with serde_yaml_ng
                // (they stay strings); only literal true/false do.
                Ok(Scalar(v.to_string()))
            }
        }

        deserializer.deserialize_any(ScalarVisitor)
    }
}

/// What a check's observed value must satisfy. All given constraints must hold.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expect {
    #[serde(default)]
    pub equals: Option<Scalar>,
    #[serde(default)]
    pub one_of: Option<Vec<Scalar>>,
    #[serde(default)]
    pub at_least: Option<i64>,
    #[serde(default)]
    pub at_most: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Check {
    /// Kernel parameter read from `/proc/sys`.
    Sysctl { key: String, expect: Expect },
    /// Effective global `sshd_config` keyword (first value wins, `Include`
    /// followed, `Match` blocks ignored).
    SshdConfig {
        key: String,
        expect: Expect,
        #[serde(default)]
        default: Option<Scalar>,
    },
    /// File permission bits must not exceed `max_mode` (octal).
    FileMode {
        path: String,
        max_mode: String,
        #[serde(default)]
        owner_uid: Option<u32>,
    },
    /// First match of `pattern` in a text file; capture group 1 (or the
    /// whole match) is the observed value.
    FileMatch {
        path: String,
        pattern: String,
        expect: Expect,
        #[serde(default)]
        default: Option<Scalar>,
    },
    /// Windows registry value (64-bit view).
    Registry {
        hive: Hive,
        key: String,
        value: String,
        expect: Expect,
        #[serde(default)]
        default: Option<Scalar>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub platform: Platform,
    #[serde(default)]
    pub rationale: Option<String>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    pub check: Check,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    rules: Vec<Rule>,
}

#[derive(Debug)]
pub enum RuleError {
    Parse(String),
    Invalid { id: String, reason: String },
    DuplicateId(String),
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleError::Parse(msg) => write!(f, "cannot parse rule file: {msg}"),
            RuleError::Invalid { id, reason } => write!(f, "rule `{id}` is invalid: {reason}"),
            RuleError::DuplicateId(id) => write!(f, "duplicate rule id `{id}`"),
        }
    }
}

impl std::error::Error for RuleError {}

/// Parses one YAML rule file and validates every rule in it.
pub fn parse_rules(yaml: &str) -> Result<Vec<Rule>, RuleError> {
    let file: RuleFile =
        serde_yaml_ng::from_str(yaml).map_err(|e| RuleError::Parse(e.to_string()))?;
    for rule in &file.rules {
        rule.validate()?;
    }
    ensure_unique_ids(&file.rules)?;
    Ok(file.rules)
}

pub(crate) fn ensure_unique_ids(rules: &[Rule]) -> Result<(), RuleError> {
    let mut seen = HashSet::new();
    for rule in rules {
        if !seen.insert(rule.id.as_str()) {
            return Err(RuleError::DuplicateId(rule.id.clone()));
        }
    }
    Ok(())
}

/// Parses an octal permission string such as `0640` or `640`.
pub(crate) fn parse_mode(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 4 {
        return None;
    }
    u32::from_str_radix(text, 8).ok()
}

pub(crate) fn compile_pattern(pattern: &str) -> Result<regex::Regex, regex::Error> {
    RegexBuilder::new(pattern).multi_line(true).build()
}

fn is_absolute_unix_path(path: &str) -> bool {
    path.starts_with('/') && !path.split('/').any(|part| part == "..")
}

impl Rule {
    fn invalid(&self, reason: impl Into<String>) -> RuleError {
        RuleError::Invalid {
            id: self.id.clone(),
            reason: reason.into(),
        }
    }

    fn validate(&self) -> Result<(), RuleError> {
        let id_ok = !self.id.is_empty()
            && self
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !id_ok {
            return Err(self.invalid("id must be non-empty ASCII letters, digits, `-` or `_`"));
        }
        if self.title.trim().is_empty() {
            return Err(self.invalid("title must not be empty"));
        }

        let (expect, required) = match &self.check {
            Check::Sysctl { key, expect } => {
                let key_ok = !key.is_empty()
                    && key
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
                if !key_ok {
                    return Err(self
                        .invalid("sysctl key may only contain letters, digits, `.`, `_` and `-`"));
                }
                (Some(expect), Platform::Linux)
            }
            Check::SshdConfig { key, expect, .. } => {
                if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return Err(self.invalid("sshd_config key must be a single keyword"));
                }
                (Some(expect), Platform::Linux)
            }
            Check::FileMode { path, max_mode, .. } => {
                if !is_absolute_unix_path(path) {
                    return Err(self.invalid("path must be absolute and must not contain `..`"));
                }
                if parse_mode(max_mode).is_none() {
                    return Err(self.invalid("max_mode must be an octal mode such as 0640"));
                }
                (None, Platform::Linux)
            }
            Check::FileMatch {
                path,
                pattern,
                expect,
                ..
            } => {
                if !is_absolute_unix_path(path) {
                    return Err(self.invalid("path must be absolute and must not contain `..`"));
                }
                compile_pattern(pattern)
                    .map_err(|e| self.invalid(format!("pattern does not compile: {e}")))?;
                (Some(expect), Platform::Linux)
            }
            Check::Registry {
                key, value, expect, ..
            } => {
                if key.trim().is_empty() || value.trim().is_empty() {
                    return Err(self.invalid("registry key and value must not be empty"));
                }
                (Some(expect), Platform::Windows)
            }
        };

        if self.platform != required {
            return Err(self.invalid(format!(
                "this check type only exists on {}",
                required.as_str()
            )));
        }
        if let Some(expect) = expect {
            if expect.is_empty() {
                return Err(
                    self.invalid("expect needs at least one of equals, one_of, at_least, at_most")
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_accept_numbers_and_strings() {
        let yaml = r#"
rules:
  - id: T-1
    title: demo
    severity: high
    platform: linux
    check:
      type: sysctl
      key: kernel.randomize_va_space
      expect: { equals: 2 }
  - id: T-2
    title: demo
    severity: low
    platform: linux
    check:
      type: sshd_config
      key: PermitRootLogin
      default: prohibit-password
      expect: { one_of: ["no", prohibit-password] }
"#;
        let rules = parse_rules(yaml).expect("valid rules");
        assert_eq!(rules.len(), 2);
        match &rules[0].check {
            Check::Sysctl { expect, .. } => {
                assert_eq!(expect.equals, Some(Scalar("2".into())));
            }
            other => panic!("unexpected check {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicates_unknown_fields_and_bad_input() {
        let dup = r#"
rules:
  - { id: A, title: t, severity: low, platform: linux, check: { type: sysctl, key: a.b, expect: { equals: 1 } } }
  - { id: A, title: t, severity: low, platform: linux, check: { type: sysctl, key: a.c, expect: { equals: 1 } } }
"#;
        assert!(matches!(parse_rules(dup), Err(RuleError::DuplicateId(_))));

        let unknown = r#"
rules:
  - { id: A, title: t, severity: low, platform: linux, check: { type: sysctl, key: a.b, expect: { equals: 1 }, run: "id" } }
"#;
        assert!(matches!(parse_rules(unknown), Err(RuleError::Parse(_))));

        let traversal = r#"
rules:
  - { id: A, title: t, severity: low, platform: linux, check: { type: file_mode, path: /etc/../shadow, max_mode: "0640" } }
"#;
        assert!(matches!(
            parse_rules(traversal),
            Err(RuleError::Invalid { .. })
        ));

        let wrong_platform = r#"
rules:
  - { id: A, title: t, severity: low, platform: windows, check: { type: sysctl, key: a.b, expect: { equals: 1 } } }
"#;
        assert!(matches!(
            parse_rules(wrong_platform),
            Err(RuleError::Invalid { .. })
        ));

        let empty_expect = r#"
rules:
  - { id: A, title: t, severity: low, platform: linux, check: { type: sysctl, key: a.b, expect: {} } }
"#;
        assert!(matches!(
            parse_rules(empty_expect),
            Err(RuleError::Invalid { .. })
        ));
    }

    #[test]
    fn mode_parsing() {
        assert_eq!(parse_mode("0640"), Some(0o640));
        assert_eq!(parse_mode("600"), Some(0o600));
        assert_eq!(parse_mode("0888"), None);
        assert_eq!(parse_mode("00640"), None);
        assert_eq!(parse_mode(""), None);
    }
}
