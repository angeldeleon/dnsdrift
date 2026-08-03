"""Configuration loading.

Config is YAML, parsed with ``yaml.safe_load`` (never ``load``) so a config
file cannot instantiate arbitrary Python objects. Unknown keys are rejected
rather than ignored, because a silently-ignored typo in a security tool's
config is how a check ends up quietly disabled.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Severity
from .validation import ValidationError, normalize_domain, normalize_selector

# Selectors used by the large mail providers. Absence of a hit here is not
# evidence of absence — DKIM offers no way to enumerate selectors — so the DKIM
# check reports informationally rather than raising a finding on "none found".
DEFAULT_DKIM_SELECTORS: tuple[str, ...] = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "s1",
    "s2",
    "mail",
    "dkim",
    "smtp",
    "zoho",
    "mandrill",
    "everlytickey1",
    "pm",  # Postmark
    "mte1",  # Mailtrap
)

ALL_CHECKS: tuple[str, ...] = (
    "spf",
    "dmarc",
    "dkim",
    "mx",
    "dnssec",
    "caa",
    "cname",
    "tls",
    "ct",
)

_MAX_DOMAINS = 5000
_ALLOWED_TOP_LEVEL = {"domains", "checks", "settings", "notify", "ai"}


@dataclass(slots=True)
class DomainConfig:
    """One monitored domain."""

    name: str
    dkim_selectors: tuple[str, ...] = DEFAULT_DKIM_SELECTORS
    checks: tuple[str, ...] = ALL_CHECKS
    tls_host: str | None = None  # defaults to the domain itself
    notes: str = ""


@dataclass(slots=True)
class Settings:
    """Global scan behaviour."""

    timeout_seconds: float = 5.0
    max_workers: int = 8
    dns_retries: int = 2
    resolvers: tuple[str, ...] = ()  # empty = system resolvers
    cert_expiry_warn_days: int = 30
    cert_expiry_critical_days: int = 7
    ct_lookback_days: int = 7
    fail_on: Severity = Severity.HIGH
    user_agent: str = "dnsdrift (+https://github.com/angeldeleon/dnsdrift)"


@dataclass(slots=True)
class NotifyConfig:
    """Where to send findings.

    URLs are read from the *environment*, never from the config file itself, so
    that a repository can carry a committed config without carrying a secret
    webhook. The config only names which env var to read.
    """

    webhook_url_env: str | None = None
    slack_webhook_url_env: str | None = None
    min_severity: Severity = Severity.MEDIUM

    def webhook_url(self) -> str | None:
        return _read_env(self.webhook_url_env)

    def slack_webhook_url(self) -> str | None:
        return _read_env(self.slack_webhook_url_env)


@dataclass(slots=True)
class AIConfig:
    """Optional LLM summarisation.

    Disabled by default. The summary is presentational only — see
    ``dnsdrift.ai`` for why it is kept out of the trust path.
    """

    enabled: bool = False
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-5"
    api_key_env: str = "ANTHROPIC_API_KEY"
    max_findings: int = 40

    def api_key(self) -> str | None:
        return _read_env(self.api_key_env)


@dataclass(slots=True)
class Config:
    domains: tuple[DomainConfig, ...]
    settings: Settings = field(default_factory=Settings)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    ai: AIConfig = field(default_factory=AIConfig)


def _read_env(name: str | None) -> str | None:
    if not name:
        return None
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _require_mapping(value: Any, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValidationError(f"{where} must be a mapping, got {type(value).__name__}")
    return value


def _reject_unknown(mapping: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ValidationError(
            f"unknown key(s) in {where}: {', '.join(unknown)} (allowed: {', '.join(sorted(allowed))})"
        )


def _parse_checks(raw: Any, where: str) -> tuple[str, ...]:
    if raw is None:
        return ALL_CHECKS
    if not isinstance(raw, list):
        raise ValidationError(f"{where}.checks must be a list")
    selected: list[str] = []
    for item in raw:
        name = str(item).strip().lower()
        if name not in ALL_CHECKS:
            raise ValidationError(
                f"{where}.checks contains unknown check {item!r} (available: {', '.join(ALL_CHECKS)})"
            )
        if name not in selected:
            selected.append(name)
    if not selected:
        raise ValidationError(f"{where}.checks is empty; omit the key to run all checks")
    return tuple(selected)


def _parse_domain(raw: Any, index: int, default_checks: tuple[str, ...]) -> DomainConfig:
    where = f"domains[{index}]"

    if isinstance(raw, str):
        return DomainConfig(name=normalize_domain(raw), checks=default_checks)

    mapping = _require_mapping(raw, where)
    _reject_unknown(mapping, {"name", "dkim_selectors", "checks", "tls_host", "notes"}, where)

    name = mapping.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValidationError(f"{where}.name is required")
    domain = normalize_domain(name)

    selectors_raw = mapping.get("dkim_selectors")
    if selectors_raw is None:
        selectors = DEFAULT_DKIM_SELECTORS
    else:
        if not isinstance(selectors_raw, list):
            raise ValidationError(f"{where}.dkim_selectors must be a list")
        selectors = tuple(normalize_selector(str(s)) for s in selectors_raw)
        if not selectors:
            raise ValidationError(f"{where}.dkim_selectors is empty; omit the key for defaults")

    tls_host_raw = mapping.get("tls_host")
    tls_host = normalize_domain(str(tls_host_raw)) if tls_host_raw else None

    checks = _parse_checks(mapping.get("checks"), where) if "checks" in mapping else default_checks

    return DomainConfig(
        name=domain,
        dkim_selectors=selectors,
        checks=checks,
        tls_host=tls_host,
        notes=str(mapping.get("notes") or ""),
    )


def _parse_settings(raw: Any) -> Settings:
    mapping = _require_mapping(raw, "settings")
    allowed = {
        "timeout_seconds",
        "max_workers",
        "dns_retries",
        "resolvers",
        "cert_expiry_warn_days",
        "cert_expiry_critical_days",
        "ct_lookback_days",
        "fail_on",
        "user_agent",
    }
    _reject_unknown(mapping, allowed, "settings")

    settings = Settings()

    if "timeout_seconds" in mapping:
        settings.timeout_seconds = _bounded_float(
            mapping["timeout_seconds"], "settings.timeout_seconds", 0.5, 60.0
        )
    if "max_workers" in mapping:
        settings.max_workers = _bounded_int(mapping["max_workers"], "settings.max_workers", 1, 32)
    if "dns_retries" in mapping:
        settings.dns_retries = _bounded_int(mapping["dns_retries"], "settings.dns_retries", 0, 5)
    if "cert_expiry_warn_days" in mapping:
        settings.cert_expiry_warn_days = _bounded_int(
            mapping["cert_expiry_warn_days"], "settings.cert_expiry_warn_days", 1, 365
        )
    if "cert_expiry_critical_days" in mapping:
        settings.cert_expiry_critical_days = _bounded_int(
            mapping["cert_expiry_critical_days"], "settings.cert_expiry_critical_days", 1, 365
        )
    if "ct_lookback_days" in mapping:
        settings.ct_lookback_days = _bounded_int(
            mapping["ct_lookback_days"], "settings.ct_lookback_days", 1, 90
        )
    if "fail_on" in mapping:
        settings.fail_on = Severity.parse(str(mapping["fail_on"]))
    if "user_agent" in mapping:
        ua = str(mapping["user_agent"]).strip()
        if not ua or len(ua) > 200 or any(c in ua for c in "\r\n"):
            raise ValidationError("settings.user_agent must be a single line under 200 characters")
        settings.user_agent = ua

    if "resolvers" in mapping:
        resolvers_raw = mapping["resolvers"]
        if not isinstance(resolvers_raw, list):
            raise ValidationError("settings.resolvers must be a list of IP addresses")
        import ipaddress

        resolvers: list[str] = []
        for item in resolvers_raw:
            try:
                resolvers.append(str(ipaddress.ip_address(str(item).strip())))
            except ValueError as exc:
                raise ValidationError(f"settings.resolvers entry {item!r} is not an IP address") from exc
        settings.resolvers = tuple(resolvers)

    if settings.cert_expiry_critical_days > settings.cert_expiry_warn_days:
        raise ValidationError(
            "settings.cert_expiry_critical_days must be less than or equal to settings.cert_expiry_warn_days"
        )

    return settings


def _parse_notify(raw: Any) -> NotifyConfig:
    mapping = _require_mapping(raw, "notify")
    _reject_unknown(mapping, {"webhook_url_env", "slack_webhook_url_env", "min_severity"}, "notify")

    notify = NotifyConfig()
    for key in ("webhook_url_env", "slack_webhook_url_env"):
        if key in mapping and mapping[key] is not None:
            name = str(mapping[key]).strip()
            # Guard against a config that pastes the URL itself into the field
            # meant to hold an env var *name* — that would commit the secret.
            if "://" in name:
                raise ValidationError(f"notify.{key} must be the NAME of an environment variable, not a URL")
            if not name.replace("_", "").isalnum():
                raise ValidationError(f"notify.{key} is not a valid environment variable name")
            setattr(notify, key, name)

    if "min_severity" in mapping:
        notify.min_severity = Severity.parse(str(mapping["min_severity"]))

    return notify


def _parse_ai(raw: Any) -> AIConfig:
    mapping = _require_mapping(raw, "ai")
    _reject_unknown(mapping, {"enabled", "provider", "model", "api_key_env", "max_findings"}, "ai")

    ai = AIConfig()
    if "enabled" in mapping:
        if not isinstance(mapping["enabled"], bool):
            raise ValidationError("ai.enabled must be true or false")
        ai.enabled = mapping["enabled"]
    if "provider" in mapping:
        provider = str(mapping["provider"]).strip().lower()
        if provider != "anthropic":
            raise ValidationError(f"ai.provider {provider!r} is not supported (only 'anthropic')")
        ai.provider = provider
    if "model" in mapping:
        model = str(mapping["model"]).strip()
        if not model or len(model) > 100:
            raise ValidationError("ai.model must be a non-empty string under 100 characters")
        ai.model = model
    if "api_key_env" in mapping:
        name = str(mapping["api_key_env"]).strip()
        if not name.replace("_", "").isalnum():
            raise ValidationError("ai.api_key_env is not a valid environment variable name")
        ai.api_key_env = name
    if "max_findings" in mapping:
        ai.max_findings = _bounded_int(mapping["max_findings"], "ai.max_findings", 1, 200)
    return ai


def _bounded_int(value: Any, where: str, low: int, high: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{where} must be an integer") from exc
    if not low <= parsed <= high:
        raise ValidationError(f"{where} must be between {low} and {high}")
    return parsed


def _bounded_float(value: Any, where: str, low: float, high: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{where} must be a number") from exc
    if not low <= parsed <= high:
        raise ValidationError(f"{where} must be between {low} and {high}")
    return parsed


def load_config(path: str | Path) -> Config:
    """Load and validate a config file."""
    config_path = Path(path).expanduser()
    if not config_path.is_file():
        raise ValidationError(f"config file not found: {config_path}")

    # Bound the read so a hostile or corrupt file cannot exhaust memory.
    size = config_path.stat().st_size
    if size > 5 * 1024 * 1024:
        raise ValidationError(f"config file is too large ({size} bytes; limit 5 MiB)")

    text = config_path.read_text(encoding="utf-8")
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValidationError(f"config file is not valid YAML: {exc}") from exc

    return parse_config(raw)


def parse_config(raw: Any) -> Config:
    """Validate an already-parsed config document."""
    mapping = _require_mapping(raw, "config")
    if not mapping:
        raise ValidationError("config is empty")
    _reject_unknown(mapping, _ALLOWED_TOP_LEVEL, "config")

    default_checks = _parse_checks(mapping.get("checks"), "config") if "checks" in mapping else ALL_CHECKS

    domains_raw = mapping.get("domains")
    if not isinstance(domains_raw, list) or not domains_raw:
        raise ValidationError("config.domains must be a non-empty list")
    if len(domains_raw) > _MAX_DOMAINS:
        raise ValidationError(f"config.domains has {len(domains_raw)} entries; limit is {_MAX_DOMAINS}")

    domains: list[DomainConfig] = []
    seen: set[str] = set()
    for index, item in enumerate(domains_raw):
        domain = _parse_domain(item, index, default_checks)
        if domain.name in seen:
            raise ValidationError(f"duplicate domain in config: {domain.name}")
        seen.add(domain.name)
        domains.append(domain)

    return Config(
        domains=tuple(domains),
        settings=_parse_settings(mapping.get("settings")),
        notify=_parse_notify(mapping.get("notify")),
        ai=_parse_ai(mapping.get("ai")),
    )
