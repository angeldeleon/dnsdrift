# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub's [private vulnerability reporting](https://github.com/angeldeleon/dnsdrift/security/advisories/new) rather than opening a public issue.

Include what you can: affected version, reproduction steps, and impact. I aim to acknowledge within 72 hours and to ship a fix or a mitigation plan within 30 days for confirmed issues. Credit in the advisory unless you'd rather not be named.

## Threat model

`dnsdrift` typically runs in CI with network egress and a webhook secret in its environment, pointed at domains that include ones the operator does not control. That shapes what it defends against:

| Threat | Mitigation |
|---|---|
| **SSRF via webhook URL** — config or env points a webhook at `169.254.169.254` or an internal service | Every outbound URL is validated and its host resolved before connecting; loopback, RFC1918, link-local, CGNAT, reserved, multicast and IPv4-mapped-IPv6 equivalents are all refused (`validation.assert_public_http_url`) |
| **SSRF via redirect** — an allowed public URL 302s to the metadata service | Redirects are followed manually, capped at 3 hops, and **re-validated at every hop** (`httpclient.safe_request`) |
| **Credential forwarding via redirect** — a 302 from an API host carries your API key onward | Credential-bearing headers are dropped when a redirect crosses origins, and 301/302/303 downgrade to GET and drop the body, so the findings payload is not replayed |
| **DNS rebinding into the TLS check** | The inspection socket connects to the address already confirmed public, with the hostname supplied only as SNI — the name is never re-resolved between check and connect |
| **Internal DNS read via `settings.resolvers`** | Resolver addresses must be public unless `allow_internal_resolvers: true` is set explicitly |
| **SSRF via config domain** — a config entry aims the TLS check at an internal host | `resolve_public_ips` runs before the socket is opened; internal resolution aborts the check |
| **Injection via domain name** — a crafted config value alters a DNS query or an outbound URL | Domains are validated against a strict label grammar and IDNA-encoded, not escaped. IP literals, wildcards, schemes, ports, credentials, whitespace and reserved suffixes are rejected (`validation.normalize_domain`) |
| **Code execution via config** — a YAML file instantiates Python objects | `yaml.safe_load` only; config size is capped; unknown keys are a hard error |
| **Secret leakage into logs or reports** | Secrets are read from the environment, never stored in config or state. A logging filter redacts credential-shaped strings, and `httpx`'s URL-logging is suppressed |
| **Secret leakage into a committed config** | A `*_url_env` field containing `://` is rejected outright, so pasting a webhook URL where an env var name belongs fails loudly |
| **Prompt injection via DNS records** (when the AI layer is enabled) | The model runs after all findings and the exit code are final and cannot change them. Its output is prose that no code parses. Input is fenced and framed as untrusted. The summary is rendered with line-leading markup escaped, so a coerced reply cannot open a heading, list or table and pass itself off as a section of the deterministic report |
| **Resource exhaustion** — a hostile domain returns enormous answers | Per-RRset record caps, per-record length caps, an 8 MiB HTTP response cap enforced **while streaming** (a chunked response cannot buffer past it first), a 5 MiB config cap, a 50 MiB state cap, and a bounded worker pool. Every serialised collection is capped as well — findings and snapshots in the JSON report, findings in the webhook and Slack payloads, keys, items, depth and value length inside an evidence blob — with the totals kept whole above the cap so a consumer can tell it is reading a subset |
| **State corruption** — an interrupted run truncates the baseline, silently disabling drift detection | Atomic write: temp file in the same directory, `fsync`, `0600` set through the descriptor, then `os.replace` |
| **File redirection at the state or report path** — a symlink planted where the tool writes | Every open goes through a file descriptor with `O_NOFOLLOW`, and the descriptor is `fstat`ed for a regular file before anything is read. The mode is set with `fchmod` on that descriptor, never `chmod` on the path, so the tool cannot be made to tighten somebody else's file and lock its owner out |
| **A named pipe at the state path stalls every run** | Reads also carry `O_NONBLOCK`, because opening a FIFO blocks *inside* `os.open` — before any regular-file check can refuse it — and a hung scheduled scan reports nothing and logs nothing. Blocking mode is restored once the descriptor is known to be a regular file |
| **Alert-channel injection** — a crafted DNS record or certificate SAN forges a line in your Slack alert or Markdown report | Certificate fields are sanitised at extraction; control characters are collapsed and angle brackets escaped in both renderers, so a newline cannot forge a fake "all checks passed" line. The Markdown renderer escapes `[`, `]` and the backtick, so an issuer name of `Example CA [renew now](https://attacker.example)` cannot borrow the report's credibility for a link and cannot close a code span the renderer opened. Parentheses and emphasis markers are deliberately not escaped: without an unescaped `[` they are inert, and escaping them would print `\(+all\)` at the reader on findings this tool writes itself |
| **Autolinking** — a record needs no Markdown syntax at all to put a live link in a report | A URL-shaped run is rendered inside a code span, where no CommonMark implementation autolinks. Escaping cannot address this: the autolinker matches the shape of the text rather than a metacharacter |
| **Slack markup that escaping cannot stop** — mrkdwn has no backslash escape, so a title of `*RESOLVED* :white_check_mark:` formats itself inside the alert | The two fields that interpolate record contents — the finding title and detail — are sent in a `plain_text` block with emoji expansion off, where Slack interprets no markup. The domain and check name sit in a code span, with the one character that could close it early replaced |
| **A credential in a published record reaching a report or a webhook** | Evidence is redacted at the point a finding is serialised, not at each sink: a key whose name matches a credential shape keeps its name and loses its value. A finding that never holds a secret cannot leak one however it is rendered, including through the next output format somebody adds |
| **False findings from partial data** — a truncated RRset or a failed lookup read as "the record was removed" | Truncated answers and partially-failed multi-lookup checks set an error and are not persisted; only NXDOMAIN counts as a dangling CNAME; a scan where most checks failed exits 2 rather than reporting clean |

### Explicitly out of scope

- **DNS spoofing of scan results.** `dnsdrift` trusts its resolver. Set `settings.resolvers` to a validating resolver you control if that matters to you.
- **Time-of-check/time-of-use on the HTTP client.** DNS can change between validation and connection. The TLS check pins the validated address at connect time; the HTTP client does not, so a rebinding attack against a webhook host remains theoretically possible. The guard raises the bar substantially against accidental and opportunistic SSRF without claiming to be airtight.
- **The scanned domains' security.** This is a read-only observer. It does not attempt to fix anything.

## The one deliberate exception

`checks/tls.py` opens its inspection socket with `check_hostname=False` and `verify_mode=CERT_NONE`.

This is necessary, not an oversight. An expired, self-signed, or hostname-mismatched certificate is precisely what the check exists to report — and a verifying context aborts the handshake in exactly those cases, so the tool could never see the certificate it needs to warn you about.

The compensating controls:

- The socket sends **no application data**. Handshake, read peer certificate, close.
- Nothing read over it is trusted, parsed as code, or forwarded anywhere.
- Certificate validity is asserted afterward in code, from the certificate itself, rather than delegated to the handshake.
- It is confined to that one function. `httpclient.py`, which carries real data to webhooks and APIs, always verifies and cannot be configured otherwise.

## Supply chain

- Dependencies are minimal and widely audited: `dnspython`, `PyYAML`, `httpx`, `cryptography`.
- CI runs `pip-audit` against the dependency tree on every push and on a weekly schedule.
- Workflow `permissions` are minimal and declared explicitly per job — the default is `contents: read`, and jobs opt in to more.
- Dependabot is enabled for both pip and GitHub Actions.
- GitHub Actions are pinned to **commit SHAs**, with the readable tag kept in a trailing comment. A tag is mutable and an action runs with the job's token and its secrets, so a tag on its own is not a pin. Dependabot still proposes the upgrades — it rewrites the SHA and the comment together.

## Running it safely

- Give the CI job the narrowest network egress you can.
- Store webhook URLs and API keys as CI secrets; never put them in `domains.yml`.
- If you commit the state file for baseline persistence (as the example workflow does), remember it contains an inventory of your domains, mail routing, and certificate metadata. That is not secret, but it is a useful map for an attacker. Use a private repository. The same applies to the JSON rendering of a report, which embeds the whole snapshot; both the state file and every report file are written `0600` rather than at the process umask, through a descriptor that refuses to follow a symlink.
- Keep `ai.enabled: false` unless you have accepted sending your domain inventory to a third-party API.
