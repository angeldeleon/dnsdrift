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
| **Prompt injection via DNS records** (when the AI layer is enabled) | The model runs after all findings and the exit code are final and cannot change them. Its output is prose that no code parses. Input is fenced and framed as untrusted |
| **Resource exhaustion** — a hostile domain returns enormous answers | Per-RRset record caps, per-record length caps, an 8 MiB HTTP response cap enforced **while streaming** (a chunked response cannot buffer past it first), a 5 MiB config cap, a 50 MiB state cap, and a bounded worker pool |
| **State corruption** — an interrupted run truncates the baseline, silently disabling drift detection | Atomic write: temp file in the same directory, `fsync`, `chmod 0600`, then `os.replace` |
| **Alert-channel injection** — a crafted DNS record or certificate SAN forges a line in your Slack alert or Markdown report | Certificate fields are sanitised at extraction; control characters are collapsed and angle brackets escaped in both the Slack and Markdown renderers, so a newline cannot forge a fake "all checks passed" line |
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
- GitHub Actions are currently pinned to **major version tags**, not commit SHAs. Tags are mutable, so this is weaker than SHA pinning; moving to SHAs is tracked as an open issue and is a welcome contribution.

## Running it safely

- Give the CI job the narrowest network egress you can.
- Store webhook URLs and API keys as CI secrets; never put them in `domains.yml`.
- If you commit the state file for baseline persistence (as the example workflow does), remember it contains an inventory of your domains, mail routing, and certificate metadata. That is not secret, but it is a useful map for an attacker. Use a private repository.
- Keep `ai.enabled: false` unless you have accepted sending your domain inventory to a third-party API.
