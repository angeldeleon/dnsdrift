# Changelog

Notable changes to dnsdrift, newest first. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

A cross-tool consistency pass. Each of the checks below is one this repository
never claimed to make, which is exactly why nothing caught them: a review that
reads a tool against its own documentation can only find the promises it broke,
not the ones it never made.

### Fixed

- **The state file is opened through a descriptor that refuses a symlink and a
  named pipe.** It was read with `path.exists()` followed by `read_text()` —
  two lookups of the same name, with whoever can write that directory in
  control of what happens in between. The default state path is relative, so on
  CI it lands inside the checked-out repository. A symlink there redirected the
  read and then, through `save()`, the write; a FIFO there blocked the run
  forever, with no timeout and nothing in the log, because nothing was checking
  the file type until after the open. Every open now carries `O_NOFOLLOW` and
  `O_NONBLOCK`, the descriptor is `fstat`ed before a byte is read, and a
  world-readable state file is tightened through the descriptor rather than by
  path. A corrupt file still degrades to "no baseline"; a symlink or a FIFO is
  not a corruption and raises.
- **The report path is no longer followed through a symlink.** Reports are
  written `0600` because the JSON rendering embeds the whole snapshot, but the
  open had no `O_NOFOLLOW` — so a link planted at `-o` on a shared build agent
  redirected that inventory to a file the attacker could read, and the chmod
  that followed tightened *their* target, locking its owner out of it. The open
  refuses the link, and the mode is set through the descriptor rather than by
  path.
- **A bare URL in a DNS record or a certificate subject can no longer become a
  link.** The Markdown escaper covered link *syntax*, and
  `https://attacker.example/dns` uses none of it: GitHub-flavoured Markdown and
  most ticket systems autolink it on sight, putting a live phishing link in a
  finding line that reads as though the scanner wrote it. URL-shaped runs are
  now rendered inside a code span, where no CommonMark implementation
  autolinks. Escaping could not fix this one — the autolinker matches the shape
  of the text, not a metacharacter. A backtick is escaped for the same reason,
  so a crafted value cannot close a span this renderer opened. Parentheses are
  still left alone deliberately: without an unescaped `[` they are inert, and
  escaping them would print `SPF permits all senders \(+all\)` on findings
  this repository writes itself.
- **Evidence is redacted and bounded where the finding is serialised**, rather
  than at each of the four sinks that render it. A TXT record is somewhere
  people really do leave a service token they were told to paste in, and the
  webhook payload carried the record set verbatim: a hundred 4 KiB records is
  inside every per-record cap the resolver enforces and still produces a request
  the receiver drops.
- **Every serialised collection has a cap.** The JSON report serialised every
  finding and every snapshot, and the generic webhook serialised every finding
  at or above the threshold — so a large scan produced a document nobody could
  open and a request nobody accepted, which made the run that found the most the
  one that reported least. Counts and totals stay whole above the cap, so a
  consumer can always tell it is looking at a subset.
- **The Markdown report caps what it asks a human to read**, and says how many
  findings it left out.
- **Slack alerts put untrusted text where mrkdwn is not interpreted.** The
  finding title and detail interpolate record contents and certificate subjects
  — attacker-chosen for any domain you do not control — into an mrkdwn field,
  where a value of `*RESOLVED* :white_check_mark:` formats itself inside the
  alert. Slack mrkdwn has no backslash escape, so escaping was never going to be
  the control: those two fields now go in a `plain_text` block with emoji
  expansion off, and the domain and check name sit in a code span whose closing
  backtick cannot be forged.
- **The state file's temporary sibling is chmodded through its descriptor**
  rather than by name.

### Added

- A `security invariants` CI job, matching the other tools in this family: no
  write path into a domain, every `os.open` carrying `O_NOFOLLOW` and every read
  `O_NONBLOCK`, every declared check implemented *and* diffed, a failed lookup
  never reported as an absent record, and no live link, tag, autolink or
  credential shape surviving into any report format.

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
