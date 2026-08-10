# Changelog

Notable changes to dnsdrift, newest first. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **The monitor workflow died on the exit codes it existed to route.** Actions
  runs a `run:` block under `bash -e`, and `set -uo pipefail` adds flags without
  clearing the inherited errexit. A scan exiting 1 (findings) or 2 (degraded)
  therefore killed the step at the `dnsdrift scan` line: the exit code was never
  recorded, and neither of the two steps keyed on it ever ran, so every outcome
  looked like one generic step failure. The step now clears errexit, records the
  code unconditionally, and succeeds on its own so the steps below can turn that
  code into a job result.
- **The SARIF uploaded to code scanning contained no drift.** It came from a
  second `dnsdrift scan`, which diffed against the baseline the first run had
  just saved — so every posture finding survived and every change since the last
  scan was silently absent from the Security tab. New `--extra-output
  FORMAT:PATH` renders any number of additional formats from the one scan, and
  the workflow uses `--extra-output sarif:findings.sarif`.
- **Markdown reports let attacker-chosen text build a link.** Certificate
  issuers and subjects belong to whoever holds the host being scanned, and in a
  takeover that is the attacker. `_md()` escaped angle brackets but not `[` and
  `]`, so an issuer of `Example CA [renew now](https://attacker.example)`
  rendered as a hyperlink carrying the report's credibility. Both brackets are
  now escaped.
- **A prompt injection could forge a report section.** The AI summary is prose
  no code parses, but it was rendered with its line structure intact, so a
  summariser talked into replying `## Changes since last scan (0)` produced a
  heading that read as part of the deterministic report. Line-leading markup —
  headings, bullets, quotes, table rows, rules, fences — is now escaped. Ordinary
  paragraphs are unaffected.
- **Report files inherited the process umask.** The JSON rendering embeds the
  whole snapshot, the same domain and mail-routing inventory the state file is
  kept at `0600` for. Reports are now written `0600` too, and an existing
  world-readable file from an earlier run is tightened rather than reused.
- **`v=spf1` was matched as a prefix.** RFC 7208 §4.5 requires a space or the
  end of the record after the version tag. Without that check an unrelated
  `v=spf1000` TXT record counted as a second SPF record, and the domain was
  reported as unprotected on the strength of it.
- **Takeover-provider matching ignored label boundaries.** A plain `endswith`
  matched `notgithub.io` against `github.io`, promoting a dangling record nobody
  could claim to CRITICAL. Matching is now anchored at a label boundary.
- Dropped the unreachable `SSLv3` branch from the TLS protocol check. The
  inspection socket offers TLS 1.0 as its floor, so that comparison could never
  be true and read as coverage the check did not have.

### Changed

- README and SECURITY.md said GitHub Actions were pinned to mutable version
  tags with SHA pinning "tracked as an open issue". They have been pinned to
  commit SHAs for some time; the claim was stale. A test now asserts both the
  pinning and the absence of the old wording.
- README described the example workflow as scanning daily. Its `schedule:` block
  ships commented out, so that only becomes true once a fork uncomments it; the
  README now says so.

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
