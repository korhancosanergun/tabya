# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/korhancosanergun/tabya/security/advisories/new)
instead of opening a public issue.

Include the tabya version, the platform, and the smallest rule file or
filesystem layout that reproduces the problem.

## What counts

tabya is often run with elevated privileges against rule files and, in
`--root` mode, against filesystem trees that may not be trusted. Reports in
these areas are especially welcome:

- a rule file or audited tree that makes tabya write, delete or execute anything;
- a rule file or audited tree that crashes tabya or makes it hang;
- a check that reports a pass for a setting that is actually insecure.

A built-in rule that is too strict or too lax for a given environment is a
normal bug: please open a regular issue.
