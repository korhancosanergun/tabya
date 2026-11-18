//! End-to-end audit of fixture filesystem trees with the built-in Ubuntu rules.

#![cfg(unix)]

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tabya_core::report::Summary;
use tabya_core::{audit, builtin_rules, Context, Status};

fn write(root: &Path, path: &str, mode: u32, content: &str) {
    let full = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(full.parent().expect("parent")).expect("mkdir");
    fs::write(&full, content).expect("write");
    fs::set_permissions(&full, fs::Permissions::from_mode(mode)).expect("chmod");
}

fn statuses(root: &Path) -> HashMap<String, Status> {
    let rules = builtin_rules().expect("built-in rules are valid");
    audit(&rules, &Context::offline_root(root))
        .into_iter()
        .map(|finding| (finding.id, finding.status))
        .collect()
}

#[test]
fn builtin_rules_load() {
    let rules = builtin_rules().expect("built-in rules are valid");
    assert!(rules.len() >= 50, "unexpectedly few rules: {}", rules.len());
}

#[test]
fn hardened_tree_passes_file_based_checks() {
    let root = tempfile::tempdir().expect("tempdir");
    let r = root.path();
    write(
        r,
        "/etc/ssh/sshd_config",
        0o600,
        "Include /etc/ssh/sshd_config.d/*.conf\nX11Forwarding yes\n",
    );
    write(
        r,
        "/etc/ssh/sshd_config.d/10-hardening.conf",
        0o600,
        "PasswordAuthentication no\nPermitRootLogin no\nX11Forwarding no\nMaxAuthTries 3\n",
    );
    write(
        r,
        "/etc/shadow",
        0o640,
        "root:!:19000:0:99999:7:::\nkorhan:$y$j9T$abc:19000::::::\n",
    );
    write(
        r,
        "/etc/login.defs",
        0o644,
        "# comment\nPASS_MAX_DAYS\t90\nUMASK 027\n",
    );
    write(
        r,
        "/etc/apt/apt.conf.d/20auto-upgrades",
        0o644,
        "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n",
    );
    write(r, "/etc/ufw/ufw.conf", 0o644, "ENABLED=yes\nLOGLEVEL=low\n");

    let status = statuses(r);
    for id in [
        "UBU-SSH-001",
        "UBU-SSH-002",
        "UBU-SSH-003",
        "UBU-SSH-004",
        "UBU-SSH-005",
        "UBU-ACC-001",
        "UBU-ACC-002",
        "UBU-ACC-003",
        "UBU-UPD-001",
        "UBU-FW-001",
    ] {
        assert_eq!(status[id], Status::Pass, "{id}");
    }
    // Runtime kernel state is not part of a filesystem tree.
    assert_eq!(status["UBU-KRN-001"], Status::NotApplicable);
    // Files absent from the tree are not judged.
    assert_eq!(status["UBU-PERM-006"], Status::NotApplicable);
    // No Windows rule is evaluated against a Linux root.
    assert!(status.keys().all(|id| id.starts_with("UBU-")));
}

#[test]
fn weak_tree_fails_the_matching_checks() {
    let root = tempfile::tempdir().expect("tempdir");
    let r = root.path();
    write(
        r,
        "/etc/ssh/sshd_config",
        0o644,
        "PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\n",
    );
    write(
        r,
        "/etc/shadow",
        0o644,
        "root:!:19000::::::\nguest::19000::::::\n",
    );
    write(
        r,
        "/etc/login.defs",
        0o644,
        "PASS_MAX_DAYS 99999\nUMASK 022\n",
    );
    write(r, "/etc/ufw/ufw.conf", 0o644, "ENABLED=no\n");

    let rules = builtin_rules().expect("built-in rules are valid");
    let findings = audit(&rules, &Context::offline_root(r));
    let status: HashMap<&str, Status> = findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding.status))
        .collect();

    for id in [
        "UBU-SSH-001",
        "UBU-SSH-002",
        "UBU-SSH-003",
        "UBU-SSH-005", // unset, default of 6 is above the limit
        "UBU-PERM-001",
        "UBU-PERM-005",
        "UBU-ACC-001",
        "UBU-ACC-002",
        "UBU-ACC-003",
        "UBU-UPD-001", // file missing
        "UBU-FW-001",
    ] {
        assert_eq!(status[id], Status::Fail, "{id}");
    }

    let empty_password = findings
        .iter()
        .find(|finding| finding.id == "UBU-ACC-001")
        .expect("finding");
    assert_eq!(empty_password.observed.as_deref(), Some("guest"));

    let summary = Summary::of(&findings);
    assert_eq!(
        summary.total,
        summary.passed + summary.failed + summary.errors + summary.not_applicable
    );
    assert!(summary.failed >= 11);
}
