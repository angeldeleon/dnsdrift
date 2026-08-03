# Getting this onto GitHub

The repo is already a git repository with 3 commits on branch `main`. Nothing
needs to be created or initialised — you only need to authenticate and push.

Target: https://github.com/angeldeleon/dnsdrift (already created, empty).

---

## Read this first: the workflow-scope trap

This repo contains `.github/workflows/`. GitHub **rejects** a push containing
workflow files unless your credential has the `workflow` scope. With a classic
personal access token that lacks it, you get:

```
! [remote rejected] main -> main (refusing to allow a Personal Access Token
  to create or update workflow .github/workflows/ci.yml without `workflow` scope)
```

`gh auth login` grants this automatically. SSH keys are unaffected. A
hand-made PAT needs the box ticked. This is the most likely thing to waste
your time, which is why it's at the top.

---

## Option 1 — GitHub CLI (recommended)

Handles auth and scopes for you.

```bash
# macOS
brew install gh

gh auth login          # GitHub.com → HTTPS → login with a web browser
```

Then, from inside the unzipped `dnsdrift` folder:

```bash
cd dnsdrift
gh auth setup-git
git remote add origin https://github.com/angeldeleon/dnsdrift.git
git push -u origin main
```

## Option 2 — SSH

Set up a key once and never think about tokens again.

```bash
ssh-keygen -t ed25519 -C "iammrangeldeleon@gmail.com"     # accept the defaults
cat ~/.ssh/id_ed25519.pub                                  # copy this
```

Paste it at https://github.com/settings/ssh/new, then:

```bash
ssh -T git@github.com    # expect: "Hi angeldeleon! You've successfully authenticated"
cd dnsdrift
git remote add origin git@github.com:angeldeleon/dnsdrift.git
git push -u origin main
```

## Option 3 — Personal access token over HTTPS

Create one at https://github.com/settings/tokens with **both `repo` and
`workflow`** scopes, then:

```bash
cd dnsdrift
git remote add origin https://github.com/angeldeleon/dnsdrift.git
git push -u origin main
# Username: angeldeleon
# Password: paste the token (not your GitHub password)
```

---

## If git isn't configured at all

```bash
git config --global user.name "Angel De Leon"
git config --global user.email "iammrangeldeleon@gmail.com"
```

The 3 existing commits already carry that name and email, so the history is
attributed to you either way.

## Verify before pushing

```bash
cd dnsdrift
git log --oneline    # expect 3 commits
git status           # expect "nothing to commit, working tree clean"
```

After the push, the repo should show 41 files and CI should start within a
minute under the Actions tab.

---

## After the push

### Topics — this is what makes it findable

```bash
gh repo edit angeldeleon/dnsdrift \
  --add-topic dns --add-topic dmarc --add-topic spf --add-topic dkim \
  --add-topic dnssec --add-topic tls --add-topic security \
  --add-topic certificate-transparency --add-topic subdomain-takeover \
  --add-topic attack-surface --add-topic email-security --add-topic python
```

### Description

```bash
gh repo edit angeldeleon/dnsdrift \
  --description "Detects changes to the DNS, email auth and TLS posture of your domains. Diffs against a baseline, so it reports what changed rather than what is merely imperfect."
```

### Free security features

Settings → Code security. Enable **secret scanning**, **push protection**, and
**private vulnerability reporting**. `SECURITY.md` already directs reporters to
the last one, so it should be on before anyone reads it.

### Watch the first CI run

```bash
gh run watch
```

Seven jobs: tests on Python 3.10–3.13, lint/types, security scan, and an
end-to-end smoke test. The smoke test scans `example.com` for real, so a red
result there means network egress, not broken code.

---

## Optional: publish to PyPI

Check https://pypi.org/project/dnsdrift/ first — the name may be taken.

```bash
pip install build twine
python -m build
twine upload dist/*
```

If the name is taken, change `name` in `pyproject.toml` and the badge URLs in
`README.md`.

## Optional: open a few issues

A repo with open issues reads as a live project rather than a code dump. These
are real gaps, already documented in the README's Limitations section:

1. **Pin GitHub Actions to commit SHAs** — currently pinned to version tags.
2. **Expand the subdomain-takeover provider list** — `_TAKEOVER_PRONE_SUFFIXES`
   in `checks/dns_hygiene.py`. One line per provider. Good first issue.
3. **Resolve SPF `include:` chains** for an exact lookup count instead of the
   current static approximation. Needs a recursion cap.
4. **Add `--diff-only`** to suppress posture findings and report only changes.
5. **Pin the resolved IP at connect time** to close the TOCTOU window in the
   SSRF guard.
