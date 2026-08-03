# Changelog

Notable changes to dnsdrift, newest first. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-02

First release.

Snapshots the public DNS, email-authentication and TLS posture of a list of
domains, then reports what changed since the previous run. Nine checks (SPF,
DMARC, DKIM, MX, DNSSEC, CAA, dangling CNAME, TLS, Certificate Transparency),
Markdown/JSON/SARIF output, Slack and webhook alerting, and a GitHub Actions
workflow for scheduled monitoring.

See the [README](README.md) for what each check covers and where the known
limitations are.

[0.1.0]: https://github.com/angeldeleon/dnsdrift/releases/tag/v0.1.0
