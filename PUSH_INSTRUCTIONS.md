# Pushing this to GitHub

The repo is already initialised and committed on branch `main`. You just need
to create the remote and push.

## 1. Create the repo

With the GitHub CLI:

```bash
gh repo create dnsdrift --public \
  --description "Agentless drift detection for DNS, email authentication and TLS posture. Tells you what CHANGED, not just what's wrong."
```

Or create it in the web UI at https://github.com/new — name it `dnsdrift`,
**do not** initialise it with a README, .gitignore, or license (this repo
already has all three).

## 2. Push

```bash
cd dnsdrift
git remote add origin git@github.com:angeldeleon/dnsdrift.git
git push -u origin main
```

## 3. Set the repo topics

These are what make it findable:

```bash
gh repo edit angeldeleon/dnsdrift --add-topic dns,dmarc,spf,dkim,dnssec,tls,\
security,certificate-transparency,subdomain-takeover,attack-surface,\
email-security,python,security-tools
```

## 4. Turn on the free security features

Settings → Code security, or:

```bash
gh api -X PATCH repos/angeldeleon/dnsdrift \
  -f security_and_analysis='{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}'
```

Also enable **Private vulnerability reporting** (Settings → Code security).
`SECURITY.md` already points people there.

## 5. Verify CI

Push triggers `.github/workflows/ci.yml`, which runs tests on Python
3.10–3.13, ruff, mypy, bandit, pip-audit, and an end-to-end smoke test that
scans a real domain and confirms the drift loop works.

## Before you publish to PyPI

`pyproject.toml` is ready, but the name `dnsdrift` may be taken. Check
https://pypi.org/project/dnsdrift/ first, then:

```bash
pip install build twine
python -m build
twine upload dist/*
```

If the name is taken, change `name` in `pyproject.toml` and the badge URLs in
`README.md`.

## Suggested first issues to open

Opening a few good-first-issues makes the repo look alive and invites help:

1. **Pin GitHub Actions to commit SHAs** — currently pinned to major version
   tags. `SECURITY.md` is honest about this and flags it as a known gap.
2. **Expand the subdomain-takeover provider list** — `_TAKEOVER_PRONE_SUFFIXES`
   in `checks/dns_hygiene.py`. One line per provider, real value.
3. **Add a `--diff-only` flag** to suppress posture findings and report only
   changes, for teams that have already accepted their baseline.
4. **Resolve SPF `include:` chains** to get an exact DNS-lookup count instead
   of the current static approximation (needs a recursion cap).
