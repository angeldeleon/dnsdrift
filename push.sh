#!/usr/bin/env bash
# One-shot: push this repo to GitHub and configure it.
#
# Requires the GitHub CLI, authenticated:
#     brew install gh && gh auth login
#
# Using gh matters here: this repo contains .github/workflows/, and GitHub
# rejects pushes touching those unless the credential carries the `workflow`
# scope. gh grants it; a hand-made PAT usually does not.

set -euo pipefail

REPO="angeldeleon/dnsdrift"

command -v gh >/dev/null || { echo "gh not found. See PUSH_INSTRUCTIONS.md for the SSH and PAT routes."; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Not logged in. Run: gh auth login"; exit 1; }

echo "==> Configuring git credentials for HTTPS"
gh auth setup-git

echo "==> Setting remote"
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/${REPO}.git"

echo "==> Pushing $(git rev-list --count HEAD) commit(s) on $(git branch --show-current)"
git push -u origin main

echo "==> Setting description and topics"
gh repo edit "$REPO" \
  --description "Detects changes to the DNS, email auth and TLS posture of your domains. Diffs against a baseline, so it reports what changed rather than what is merely imperfect." \
  --add-topic dns --add-topic dmarc --add-topic spf --add-topic dkim \
  --add-topic dnssec --add-topic tls --add-topic security \
  --add-topic certificate-transparency --add-topic subdomain-takeover \
  --add-topic attack-surface --add-topic email-security --add-topic python

echo "==> Enabling secret scanning and push protection"
# Non-fatal: unavailable on some plan/visibility combinations.
gh api -X PATCH "repos/${REPO}" \
  -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled' \
  >/dev/null 2>&1 && echo "    enabled" || echo "    skipped (enable manually under Settings -> Code security)"

echo
echo "Done: https://github.com/${REPO}"
echo "Still to do by hand: enable Private vulnerability reporting (Settings -> Code security)."
echo "Watch CI with: gh run watch"
