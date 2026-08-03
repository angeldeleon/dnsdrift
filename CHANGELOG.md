# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-08-02

Initial release.

### Added

- Nine checks: `spf`, `dmarc`, `dkim`, `mx`, `dnssec`, `caa`, `cname`
  (dangling-CNAME / subdomain-takeover), `tls`, and `ct` (Certificate
  Transparency).
- Snapshot/diff drift engine reporting policy downgrades, MX changes, DNSSEC
  being disabled, new CAA issuers, redirected DMARC `rua`, newly-dangling
  CNAMEs, certificate issuer changes, and previously-unseen hostnames in CT.
- `scan`, `check`, and `validate` CLI commands with CI-friendly exit codes.
- Markdown, JSON, and SARIF output. SARIF feeds GitHub code scanning.
- Slack and generic webhook notifications, with URLs read from the environment.
- Optional, opt-in LLM summarisation that cannot affect findings or exit codes.
- Example GitHub Actions workflow for scheduled monitoring with committed state.

[Unreleased]: https://github.com/angeldeleon/dnsdrift/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/angeldeleon/dnsdrift/releases/tag/v0.1.0
