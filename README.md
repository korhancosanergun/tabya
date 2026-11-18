# tabya

**Read-only host hardening auditor for Ubuntu and Windows 11, in one static Rust binary.**

*Tabya* is the Turkish word for a bastion: the fortified position you check before the attack comes.

tabya compares a machine's security-relevant settings against a baseline and tells you what to fix. Rules are plain YAML, so the baseline is easy to read, review and extend.

```console
$ sudo tabya audit --only-failed
tabya 0.1.0 · linux baseline · this host

 FAIL  medium    UBU-FS-003    Setuid programs do not write core dumps
         observed: 2
         expected: equals "0"
         fix: Set fs.suid_dumpable = 0 in /etc/sysctl.d/.
 FAIL  medium    UBU-SSH-005   SSH limits authentication attempts per connection
         observed: 6
         expected: at most 4
         detail: MaxAuthTries is not set in sshd_config; built-in default assumed
         fix: Set `MaxAuthTries 4` (or lower) in /etc/ssh/sshd_config.d/ and reload ssh.
 ...

34 checks: 22 passed, 12 failed, 0 unreadable, 0 not applicable · score 64%
```

## Design

- **Read-only.** Probes read files, `/proc/sys` and the Windows registry. tabya never changes the audited system.
- **No command execution.** No check type can run a program, so a rule file cannot make tabya execute anything. Unknown fields in a rule file are rejected.
- **Honest results.** A check that cannot read its target (usually missing privileges) is reported as unreadable, not as a pass or a fail.
- **One binary, two platforms.** The same rule format and report cover Ubuntu and Windows 11.
- **Offline audits.** `--root DIR` audits a mounted disk image, container rootfs or backup without booting it.
- **No `unsafe`** in tabya's own code (`unsafe_code = "forbid"` as a workspace lint).

## Status

Version 0.1 is an early release.

| Platform | Built-in rules | State |
| --- | --- | --- |
| Ubuntu | 34 | Exercised on Ubuntu 26.04 and covered by fixture-based tests. |
| Windows 11 | 22 | Builds and lints for `x86_64-pc-windows`. Rules are registry reads and have not yet been validated on a real Windows 11 machine. |

The built-in baseline is inspired by widely used hardening guidance (CIS Benchmarks, Microsoft security baselines, kernel documentation). It is **not** a certified benchmark assessment.

## Install

```console
cargo install --git https://github.com/korhancosanergun/tabya tabya
```

Built and tested with Rust 1.97. The declared minimum (1.82) is not yet tested in CI.

## Usage

```console
tabya audit                       # audit this host, text report
tabya audit --only-failed         # hide passed and not-applicable checks
tabya audit --format json -o report.json
tabya audit --min-severity high   # only high and critical rules
tabya audit --fail-on high        # exit 1 only for high/critical failures
tabya audit --root /mnt/image     # audit an offline Linux filesystem tree
tabya audit --rules my-rules.yaml # add your own rules
tabya list                        # show every rule
```

Run with `sudo` on Ubuntu, or from an elevated terminal on Windows, for a complete result: some targets (for example `/etc/shadow`) are only readable with privileges.

Exit status: `0` no failure at or above `--fail-on` (default `low`), `1` at least one such failure, `2` usage or rule file error. `--fail-on never` always exits `0` after a successful run, which is useful for scheduled reporting.

## Writing rules

```yaml
rules:
  - id: ACME-SSH-001
    title: SSH listens on the management port
    severity: medium          # info | low | medium | high | critical
    platform: linux           # linux | windows
    rationale: Why this matters.
    remediation: What to change.
    check:
      type: sshd_config
      key: Port
      default: 22             # value assumed when the setting is absent
      expect: { equals: 2222 }
```

`expect` accepts `equals`, `one_of`, `at_least` and `at_most`; all given constraints must hold. Text compares case-insensitively.

| Check type | Platform | Reads |
| --- | --- | --- |
| `sysctl` | linux | A kernel parameter under `/proc/sys`. |
| `sshd_config` | linux | The effective global value of a keyword: first value wins, `Include` is followed, `Match` blocks are ignored. |
| `file_mode` | linux | Permission bits (must not exceed `max_mode`) and optionally `owner_uid`. |
| `file_match` | linux | The first match of a regular expression in a text file; capture group 1 is the observed value. |
| `registry` | windows | One `HKLM`/`HKCU` value (DWORD, QWORD or string) from the 64-bit view. |

## Limitations

- `sshd_config` is resolved from files. Values that only apply inside `Match` blocks are not evaluated.
- In `--root` mode, kernel parameters are reported as not applicable (they are runtime state), and absolute symlinks inside the tree resolve against the host filesystem.
- Windows checks cover registry-backed settings only. Settings that live elsewhere (audit policy, BitLocker state, local accounts) are not covered yet.

## Roadmap

- Validation of the Windows 11 baseline on real hardware, then signed release binaries.
- SARIF and HTML reports.
- More check types: listening sockets, service state, Windows audit policy.
- Per-rule waivers with a required justification.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
