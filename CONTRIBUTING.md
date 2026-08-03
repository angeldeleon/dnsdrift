# Contributing

Thanks for considering it. Issues and pull requests are both welcome.

## Setup

```bash
git clone https://github.com/angeldeleon/dnsdrift
cd dnsdrift
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Before opening a PR

```bash
ruff check .          # lint, including security rules
ruff format .         # formatting
mypy                  # types
bandit -r src/ -c pyproject.toml
pytest                # no network required
```

CI runs all of these plus `pip-audit`. The default `pytest` run makes no network calls; tests that do are marked `@pytest.mark.network` and are excluded in CI.

## Good first contributions

- **A subdomain-takeover provider fingerprint.** `_TAKEOVER_PRONE_SUFFIXES` in `checks/dns_hygiene.py` is a list of hosting suffixes whose dangling CNAMEs are commonly claimable. Adding one is a one-line change with real value. Please link evidence that the target name is claimable.
- **A DKIM selector.** `DEFAULT_DKIM_SELECTORS` in `config.py`. If a mail platform you use publishes under a selector not on the list, add it.
- **A new check.** The registry makes this a single decorated function — see below.

## Adding a check

1. Write a function in `src/dnsdrift/checks/` decorated with `@register("name")`, taking a `CheckContext` and returning a `CheckResult`.
2. Add the name to `ALL_CHECKS` in `config.py`.
3. Optionally add a `@rule("name")` drift handler in `drift.py`.
4. Add tests in `tests/test_checks.py` using the `FakeResolver` stub. No network.

Three things the codebase is strict about, and a review will catch:

**Observations must be deterministic.** Whatever a check puts in `observations` gets persisted and diffed against the next run. Sort anything unordered, and leave out anything that changes on its own — timestamps, per-renewal certificate serials, response ordering. A field that varies run-to-run produces a drift finding on every single scan, and a tool that cries wolf every morning gets muted inside a week.

**A failed lookup is not a missing record.** Three states, never two: the record exists, it definitively does not, or you could not find out. Collapsing the third into the second is what makes a monitoring tool produce confident false alarms — a SERVFAIL at a CDN becoming a CRITICAL "subdomain takeover", say. There are regression tests for exactly this.

How to express each case:

- **Whole check failed** (single lookup, no usable data): set `CheckResult.error` and emit an `OPERATIONAL` finding. Observations are discarded and the previous baseline is left alone.
- **Some of many speculative lookups failed** (DKIM probes 16 selectors, CNAME probes 15 names): record the observations *and* a list naming what was indeterminate — `selectors_errored`, `unresolved`. The drift rule excludes exactly those from its comparison. Do not fail the whole check: a domain with one persistently flaky probe would then never build a baseline, silently disabling that check's drift detection forever.
- **True but incomplete** (TLS knows the host is down but nothing about its certificate): set `partial=True`. The scanner merges the observation over the previous baseline instead of replacing it, so fields you could not determine survive.

**Severity should mean something.** `CRITICAL` is for exploitable-right-now (`+all`, a dangling CNAME on a claimable provider, an expired certificate). `HIGH` is for a serious gap or a real downgrade. Reserve `INFO` for things that are worth recording but never worth waking anyone up. If everything is high, nothing is.

## Security

Please do not open a public issue for a security vulnerability — see [SECURITY.md](SECURITY.md) for private reporting.

Changes touching `validation.py`, `httpclient.py`, or the TLS inspection socket get a closer read, and need tests. The SSRF guard in particular has a large parametrised test suite; if you extend it, extend those too.

## Style

- Comments explain *why*, not *what*. If a line needs a comment saying what it does, the line probably needs rewriting instead.
- No new dependencies without a strong reason. This is a security tool; every dependency is attack surface someone else maintains.
- No `subprocess`, no `eval`, no dynamic imports.

## License

Contributions are licensed under Apache 2.0, matching the project.
