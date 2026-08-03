"""Config parsing, state persistence, and log redaction."""

from __future__ import annotations

import json
import os
import stat

import pytest
import yaml

from dnsdrift.config import load_config, parse_config
from dnsdrift.logging_setup import redact
from dnsdrift.models import Severity, Snapshot
from dnsdrift.store import SnapshotStore
from dnsdrift.validation import ValidationError


class TestConfigParsing:
    def test_minimal_config(self) -> None:
        config = parse_config({"domains": ["example.com"]})
        assert len(config.domains) == 1
        assert config.domains[0].name == "example.com"
        assert config.settings.fail_on is Severity.HIGH

    def test_full_config(self) -> None:
        config = parse_config(
            {
                "domains": [{"name": "Example.COM", "dkim_selectors": ["s1"], "checks": ["spf", "dmarc"]}],
                "settings": {"timeout_seconds": 3, "max_workers": 4, "fail_on": "medium"},
                "notify": {"slack_webhook_url_env": "SLACK_URL", "min_severity": "high"},
                "ai": {"enabled": True, "model": "claude-sonnet-4-5"},
            }
        )
        assert config.domains[0].name == "example.com"
        assert config.domains[0].checks == ("spf", "dmarc")
        assert config.settings.fail_on is Severity.MEDIUM
        assert config.notify.min_severity is Severity.HIGH
        assert config.ai.enabled is True

    def test_unknown_keys_are_rejected(self) -> None:
        """A typo must fail loudly, not silently disable a check."""
        with pytest.raises(ValidationError, match="unknown key"):
            parse_config({"domains": ["example.com"], "settngs": {}})

    def test_unknown_check_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unknown check"):
            parse_config({"domains": ["example.com"], "checks": ["spf", "telepathy"]})

    def test_duplicate_domains_rejected(self) -> None:
        with pytest.raises(ValidationError, match="duplicate"):
            parse_config({"domains": ["example.com", "EXAMPLE.com"]})

    def test_empty_domains_rejected(self) -> None:
        with pytest.raises(ValidationError):
            parse_config({"domains": []})

    def test_out_of_range_settings_rejected(self) -> None:
        with pytest.raises(ValidationError, match="between"):
            parse_config({"domains": ["example.com"], "settings": {"max_workers": 9999}})

    def test_webhook_url_in_env_field_rejected(self) -> None:
        """Guard against committing a secret into a field meant for a var name."""
        with pytest.raises(ValidationError, match="NAME of an environment variable"):
            parse_config(
                {
                    "domains": ["example.com"],
                    "notify": {"slack_webhook_url_env": "https://hooks.slack.com/services/T/B/x"},
                }
            )

    def test_critical_days_must_not_exceed_warn_days(self) -> None:
        with pytest.raises(ValidationError):
            parse_config(
                {
                    "domains": ["example.com"],
                    "settings": {"cert_expiry_warn_days": 5, "cert_expiry_critical_days": 30},
                }
            )

    def test_yaml_is_loaded_safely(self, tmp_path) -> None:
        """A config must never be able to construct arbitrary Python objects."""
        path = tmp_path / "evil.yml"
        path.write_text("domains: !!python/object/apply:os.system ['echo pwned']\n", encoding="utf-8")
        with pytest.raises(ValidationError):
            load_config(path)

    def test_missing_file(self, tmp_path) -> None:
        with pytest.raises(ValidationError, match="not found"):
            load_config(tmp_path / "nope.yml")

    def test_example_config_is_valid(self) -> None:
        """The shipped example must actually parse."""
        from pathlib import Path

        example = Path(__file__).resolve().parent.parent / "domains.example.yml"
        if example.exists():
            config = load_config(example)
            assert config.domains

    def test_env_vars_are_read_not_stored(self, monkeypatch) -> None:
        monkeypatch.setenv("MY_HOOK", "https://hooks.slack.com/services/T/B/secret")
        config = parse_config({"domains": ["example.com"], "notify": {"slack_webhook_url_env": "MY_HOOK"}})
        assert config.notify.slack_webhook_url_env == "MY_HOOK"
        assert config.notify.slack_webhook_url() == "https://hooks.slack.com/services/T/B/secret"
        # The secret must not appear in the serialised config object itself.
        assert "secret" not in yaml.safe_dump(str(config.notify))


class TestSnapshotStore:
    def test_roundtrip(self, tmp_path) -> None:
        path = tmp_path / "state.json"
        store = SnapshotStore(path)
        snapshot = Snapshot(domain="example.com", collected_at="2026-01-01T00:00:00+00:00")
        snapshot.checks["spf"] = {"record": "v=spf1 -all"}
        store.save([snapshot])

        reloaded = SnapshotStore(path)
        loaded = reloaded.get("example.com")
        assert loaded is not None
        assert loaded.checks["spf"]["record"] == "v=spf1 -all"

    def test_file_permissions_are_restrictive(self, tmp_path) -> None:
        path = tmp_path / "state.json"
        store = SnapshotStore(path)
        store.save([Snapshot(domain="example.com", collected_at="t")])
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_corrupt_state_is_ignored_not_fatal(self, tmp_path) -> None:
        """Losing drift for one run beats a monitor that stops running."""
        path = tmp_path / "state.json"
        path.write_text("{ not json", encoding="utf-8")
        assert SnapshotStore(path).load() == {}

    def test_wrong_version_is_ignored(self, tmp_path) -> None:
        path = tmp_path / "state.json"
        path.write_text(json.dumps({"version": 999, "snapshots": {}}), encoding="utf-8")
        assert SnapshotStore(path).load() == {}

    def test_save_merges_rather_than_replaces(self, tmp_path) -> None:
        path = tmp_path / "state.json"
        store = SnapshotStore(path)
        store.save([Snapshot(domain="a.example.com", collected_at="t")])

        store2 = SnapshotStore(path)
        store2.save([Snapshot(domain="b.example.com", collected_at="t")])

        store3 = SnapshotStore(path)
        assert set(store3.load()) == {"a.example.com", "b.example.com"}

    def test_creates_parent_directory(self, tmp_path) -> None:
        path = tmp_path / "nested" / "deep" / "state.json"
        SnapshotStore(path).save([Snapshot(domain="example.com", collected_at="t")])
        assert path.exists()


class TestRedaction:
    @pytest.mark.parametrize(
        "text",
        [
            "posting to https://hooks.slack.com/services/T00/B00/XXXXXXXXXXXX",
            "key sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
            "token=ghp_abcdefghijklmnopqrstuvwxyz123456",
            "https://example.com/hook?token=supersecretvalue",
            "https://user:hunter2@example.com/path",
            'api_key: "abcdef1234567890"',
        ],
    )
    def test_secrets_are_redacted(self, text: str) -> None:
        result = redact(text)
        for secret in (
            "XXXXXXXXXXXX",
            "abcdefghijklmnopqrstuvwxyz",
            "supersecretvalue",
            "hunter2",
            "abcdef1234567890",
        ):
            assert secret not in result, f"{secret!r} leaked in {result!r}"
        assert "<redacted" in result

    def test_ordinary_text_is_untouched(self) -> None:
        text = "scanned example.com: DMARC policy is p=reject"
        assert redact(text) == text
