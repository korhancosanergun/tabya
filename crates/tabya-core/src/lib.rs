//! Rule model, read-only probes and evaluation engine behind the `tabya`
//! hardening auditor.
//!
//! Rules are plain data (YAML). Every check type only reads state from the
//! host: files, `/proc/sys` and, on Windows, the registry. No check runs a
//! command and nothing on the audited system is modified.

mod engine;
mod expect;
mod model;
mod probe;
pub mod report;

pub use engine::{audit, Context, Finding, Status};
pub use model::{parse_rules, Check, Expect, Hive, Platform, Rule, RuleError, Scalar, Severity};

/// Built-in baseline for Ubuntu hosts.
pub const BUILTIN_UBUNTU: &str = include_str!("../rules/ubuntu.yaml");
/// Built-in baseline for Windows 11 hosts.
pub const BUILTIN_WINDOWS11: &str = include_str!("../rules/windows11.yaml");

/// Parses and validates every built-in rule file.
pub fn builtin_rules() -> Result<Vec<Rule>, RuleError> {
    let mut rules = parse_rules(BUILTIN_UBUNTU)?;
    rules.extend(parse_rules(BUILTIN_WINDOWS11)?);
    model::ensure_unique_ids(&rules)?;
    Ok(rules)
}
