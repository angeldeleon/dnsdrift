"""Command-line interface.

Exit codes are the contract with CI:

* ``0`` — scan completed, nothing at or above the fail-on threshold
* ``1`` — scan completed, findings at or above the threshold
* ``2`` — the scan could not run (bad config, unwritable state, no domains)

Keeping "found problems" (1) distinct from "could not check" (2) matters: a
pipeline that treats them the same will eventually go green because the scanner
broke, which is the worst possible failure mode for a monitoring tool.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .ai import summarize
from .config import ALL_CHECKS, Config, DomainConfig, Settings, load_config
from .logging_setup import configure_logging
from .models import ScanReport, Severity
from .notify import notify
from .report import render
from .scanner import scan
from .store import DEFAULT_STATE_PATH, SnapshotStore, StateError
from .validation import ValidationError

log = logging.getLogger("dnsdrift")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dnsdrift",
        description=(
            "Agentless drift detection for DNS, email authentication and TLS posture. "
            "Read-only: it makes DNS queries and one TLS handshake per host, nothing else."
        ),
    )
    parser.add_argument("--version", action="version", version=f"dnsdrift {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="count", default=0, help="increase log verbosity")
    common.add_argument("-q", "--quiet", action="store_true", help="only log errors")

    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser(
        "scan", parents=[common], help="scan every domain in a config file and report drift"
    )
    scan_parser.add_argument("-c", "--config", required=True, help="path to the YAML config file")
    scan_parser.add_argument(
        "-o", "--output", default="-", help="write the report here ('-' for stdout, the default)"
    )
    scan_parser.add_argument(
        "-f",
        "--format",
        default="markdown",
        choices=("markdown", "md", "json", "sarif"),
        help="report format (default: markdown)",
    )
    scan_parser.add_argument(
        "--state",
        default=str(DEFAULT_STATE_PATH),
        help=f"snapshot baseline file (default: {DEFAULT_STATE_PATH})",
    )
    scan_parser.add_argument(
        "--no-save",
        action="store_true",
        help="do not update the baseline (useful for a dry run)",
    )
    scan_parser.add_argument(
        "--fail-on",
        default=None,
        choices=[s.value for s in Severity],
        help="minimum severity that sets exit code 1; overrides the config",
    )
    scan_parser.add_argument("--no-notify", action="store_true", help="skip webhook and Slack delivery")
    scan_parser.add_argument(
        "--no-ai", action="store_true", help="skip LLM summarisation even if enabled in config"
    )
    scan_parser.set_defaults(func=cmd_scan)

    check_parser = sub.add_parser(
        "check", parents=[common], help="run a one-off scan of a single domain, without state"
    )
    check_parser.add_argument("domain", help="the domain to check")
    check_parser.add_argument(
        "-f", "--format", default="markdown", choices=("markdown", "md", "json", "sarif")
    )
    check_parser.add_argument(
        "--checks",
        default=",".join(ALL_CHECKS),
        help=f"comma-separated checks to run (default: all — {', '.join(ALL_CHECKS)})",
    )
    check_parser.add_argument("--fail-on", default=None, choices=[s.value for s in Severity])
    check_parser.set_defaults(func=cmd_check)

    validate_parser = sub.add_parser(
        "validate", parents=[common], help="validate a config file without scanning"
    )
    validate_parser.add_argument("-c", "--config", required=True)
    validate_parser.set_defaults(func=cmd_validate)

    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
    except ValidationError as exc:
        log.error("config error: %s", exc)
        return EXIT_ERROR

    if args.fail_on:
        config.settings.fail_on = Severity.parse(args.fail_on)

    store = SnapshotStore(args.state)
    try:
        store.load()
    except StateError as exc:
        log.error("cannot read state: %s", exc)
        return EXIT_ERROR

    report = scan(config, store=store)

    if config.ai.enabled and not args.no_ai:
        report.ai_summary = summarize(report, config.ai)

    _write_report(report, args.output, args.format)

    if not args.no_save:
        try:
            store.save(report.snapshots)
        except StateError as exc:
            # A failed save means the next run cannot detect drift, which is
            # serious enough to fail the job rather than silently continue.
            log.error("cannot save state: %s", exc)
            return EXIT_ERROR

    if not args.no_notify:
        for error in notify(report, config.notify, user_agent=config.settings.user_agent):
            log.error("%s", error)

    return _exit_code(report, config.settings.fail_on)


def cmd_check(args: argparse.Namespace) -> int:
    try:
        selected = tuple(c.strip().lower() for c in args.checks.split(",") if c.strip())
        unknown = [c for c in selected if c not in ALL_CHECKS]
        if unknown:
            raise ValidationError(
                f"unknown check(s): {', '.join(unknown)} (available: {', '.join(ALL_CHECKS)})"
            )
        from .validation import normalize_domain

        domain = DomainConfig(name=normalize_domain(args.domain), checks=selected or ALL_CHECKS)
    except ValidationError as exc:
        log.error("%s", exc)
        return EXIT_ERROR

    config = Config(domains=(domain,), settings=Settings())
    report = scan(config, store=None)

    _write_report(report, "-", args.format)

    fail_on = Severity.parse(args.fail_on) if args.fail_on else config.settings.fail_on
    return _exit_code(report, fail_on)


def cmd_validate(args: argparse.Namespace) -> int:
    try:
        config = load_config(args.config)
    except ValidationError as exc:
        log.error("config error: %s", exc)
        return EXIT_ERROR

    print(f"Config is valid: {len(config.domains)} domain(s).")
    for domain in config.domains:
        print(f"  {domain.name}  [{', '.join(domain.checks)}]")

    missing: list[str] = []
    if config.notify.webhook_url_env and not config.notify.webhook_url():
        missing.append(config.notify.webhook_url_env)
    if config.notify.slack_webhook_url_env and not config.notify.slack_webhook_url():
        missing.append(config.notify.slack_webhook_url_env)
    if config.ai.enabled and not config.ai.api_key():
        missing.append(config.ai.api_key_env)

    if missing:
        print()
        print("Referenced but unset environment variable(s): " + ", ".join(missing))

    return EXIT_OK


def _write_report(report: ScanReport, output: str, fmt: str) -> None:
    rendered = render(report, fmt)
    if output == "-":
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")
        return

    path = Path(output).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
    log.info("wrote %s report to %s", fmt, path)


def _exit_code(report: ScanReport, fail_on: Severity) -> int:
    highest = report.max_severity
    if highest is not None and highest >= fail_on:
        log.info("highest severity %s meets the %s threshold", highest.value, fail_on.value)
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(getattr(args, "verbose", 0), quiet=getattr(args, "quiet", False))

    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        log.error("interrupted")
        return EXIT_ERROR
    except ValidationError as exc:
        log.error("%s", exc)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
