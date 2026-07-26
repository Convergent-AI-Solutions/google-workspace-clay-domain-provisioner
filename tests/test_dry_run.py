"""A dry run must change nothing, anywhere.

These tests exist because `--dry-run` previously created a Cloudflare zone and
fetched a Google verification token. The guard has to sit *above* every mutating
call, not beside it, so each test asserts on what was never invoked rather than
on the returned summary.

The fakes fail loudly on any write, so a future refactor that reintroduces a
mutation behind the guard breaks a test instead of a real account.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from google_workspace_clay_provisioner import steps
from google_workspace_clay_provisioner.config import DnsConfig, MailboxConfig
from google_workspace_clay_provisioner.state import (
    STEP_CLAY,
    STEP_DKIM,
    STEP_DNS,
    STEP_VERIFY_OWNERSHIP,
    STEP_VERIFY_RECORDS,
    RunState,
)

SAMPLE_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest" * 3


class RecordingCloudflareClient:
    """Serves reads from a script and records every request.

    Writes are recorded rather than rejected, so a test can assert precisely
    which verb reached the API instead of only that something failed.
    """

    def __init__(self, zones: list[dict[str, Any]] | None = None) -> None:
        self.zones = zones if zones is not None else []
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, path: str, **_: Any) -> tuple[Any, int]:
        self.calls.append((method, path))
        return self._read(path), 200

    def get(self, path: str, **_: Any) -> Any:
        self.calls.append(("GET", path))
        return self._read(path)

    def get_optional(self, path: str, **_: Any) -> Any:
        self.calls.append(("GET", path))
        return self._read(path)

    def post(self, path: str, **_: Any) -> Any:
        self.calls.append(("POST", path))
        return {"id": "should-not-be-used"}

    def put(self, path: str, **_: Any) -> Any:
        self.calls.append(("PUT", path))
        return {"id": "should-not-be-used"}

    def delete(self, path: str, **_: Any) -> Any:
        self.calls.append(("DELETE", path))
        return {}

    def _read(self, path: str) -> Any:
        if path == "/zones":
            return self.zones
        if "/dns_records" in path:
            return []
        return None

    @property
    def writes(self) -> list[tuple[str, str]]:
        """Every request that could change state."""
        return [call for call in self.calls if call[0] in ("POST", "PUT", "DELETE", "PATCH")]


class ExplodingSiteVerification:
    """Any use at all fails the test: a dry run must not touch this API."""

    def webResource(self) -> Any:  # noqa: N802 - mirrors the Google client's name
        raise AssertionError("a dry run must not call the Site Verification API")


class FakeDirectory:
    """Directory API stub reporting an unverified domain."""

    def __init__(self, verified: bool = False) -> None:
        self.verified = verified

    def domains(self) -> Any:
        return self

    def get(self, **_: Any) -> Any:
        return self

    def execute(self) -> dict[str, Any]:
        return {"domainName": "getexample.com", "verified": self.verified}


@pytest.fixture
def state(tmp_path: Path) -> RunState:
    """A fresh run state in a temporary directory."""
    return RunState.load(tmp_path, "getexample.com")


@pytest.fixture
def dns_config() -> DnsConfig:
    """Default record configuration."""
    return DnsConfig()


def test_ownership_verification_never_requests_a_token_in_a_dry_run(state: RunState) -> None:
    """getToken is an authenticated Google call, so a preview must not make it.

    Regression test for the original defect: the token was fetched before the
    dry-run check, so previewing a run needed live Workspace credentials.
    """
    client = RecordingCloudflareClient(zones=[{"id": "zone1", "name": "getexample.com"}])

    outcome = steps.verify_domain_ownership(
        FakeDirectory(),
        ExplodingSiteVerification(),
        client,  # type: ignore[arg-type]
        "account1",
        "getexample.com",
        state,
        dry_run=True,
    )

    assert outcome == "would-verify"
    assert client.writes == []


def test_ownership_verification_does_not_create_a_zone_in_a_dry_run(state: RunState) -> None:
    """The worst case of the original defect: --create-zone really created a zone."""
    client = RecordingCloudflareClient(zones=[])

    steps.verify_domain_ownership(
        FakeDirectory(),
        ExplodingSiteVerification(),
        client,  # type: ignore[arg-type]
        "account1",
        "getexample.com",
        state,
        create_zone=True,
        dry_run=True,
    )

    assert client.writes == []
    assert ("POST", "/zones") not in client.calls


def test_dry_run_preview_says_the_zone_would_be_created(state: RunState) -> None:
    """Refusing to create it is only useful if the operator is told what is missing."""
    client = RecordingCloudflareClient(zones=[])
    lines: list[str] = []

    steps.verify_domain_ownership(
        FakeDirectory(),
        ExplodingSiteVerification(),
        client,  # type: ignore[arg-type]
        "account1",
        "getexample.com",
        state,
        create_zone=True,
        dry_run=True,
        echo=lines.append,
    )

    assert any("would be created" in line for line in lines)


def test_dry_run_preview_warns_when_a_real_run_would_fail(state: RunState) -> None:
    """No zone and no create-zone option means a real run cannot proceed."""
    client = RecordingCloudflareClient(zones=[])
    lines: list[str] = []

    steps.verify_domain_ownership(
        FakeDirectory(),
        ExplodingSiteVerification(),
        client,  # type: ignore[arg-type]
        "account1",
        "getexample.com",
        state,
        create_zone=False,
        dry_run=True,
        echo=lines.append,
    )

    assert any("would fail" in line for line in lines)


def test_ownership_verification_writes_no_state_in_a_dry_run(
    state: RunState, tmp_path: Path
) -> None:
    """A preview that marks a step done would make a later real run skip it."""
    client = RecordingCloudflareClient(zones=[{"id": "zone1", "name": "getexample.com"}])

    steps.verify_domain_ownership(
        FakeDirectory(),
        ExplodingSiteVerification(),
        client,  # type: ignore[arg-type]
        "account1",
        "getexample.com",
        state,
        dry_run=True,
    )

    assert not state.is_done(STEP_VERIFY_OWNERSHIP)
    assert not (tmp_path / "getexample.com.json").exists()


def test_publishing_mail_records_makes_no_write_in_a_dry_run(
    state: RunState, dns_config: DnsConfig
) -> None:
    """MX, SPF and DMARC are previewed against an existing zone, never written."""
    client = RecordingCloudflareClient(zones=[{"id": "zone1", "name": "getexample.com"}])

    specs, outcomes = steps.publish_mail_records(
        client,  # type: ignore[arg-type]
        "account1",
        "getexample.com",
        dns_config,
        state,
        dry_run=True,
    )

    assert client.writes == []
    assert not state.is_done(STEP_DNS)
    assert len(specs) == 3
    assert all(outcome.action.startswith("would-") for outcome in outcomes)


def test_publishing_mail_records_does_not_create_a_zone_in_a_dry_run(
    state: RunState, dns_config: DnsConfig
) -> None:
    """The same zone-creation path as the ownership step, reached from records."""
    client = RecordingCloudflareClient(zones=[])
    lines: list[str] = []

    specs, outcomes = steps.publish_mail_records(
        client,  # type: ignore[arg-type]
        "account1",
        "getexample.com",
        dns_config,
        state,
        create_zone=True,
        dry_run=True,
        echo=lines.append,
    )

    assert client.writes == []
    assert outcomes == []
    assert len(specs) == 3
    assert any("would create the Cloudflare zone" in line for line in lines)


def test_pruning_stale_mx_deletes_nothing_in_a_dry_run(
    state: RunState, dns_config: DnsConfig
) -> None:
    """Pruning is the only destructive path in the tool; a preview must not delete."""
    client = RecordingCloudflareClient(zones=[{"id": "zone1", "name": "getexample.com"}])

    steps.publish_mail_records(
        client,  # type: ignore[arg-type]
        "account1",
        "getexample.com",
        dns_config,
        state,
        prune_stale_mx=True,
        dry_run=True,
    )

    assert not any(call[0] == "DELETE" for call in client.calls)


def test_publishing_dkim_makes_no_write_in_a_dry_run(
    state: RunState, dns_config: DnsConfig
) -> None:
    """The DKIM record is the one a human pasted, so a preview is worth having."""
    client = RecordingCloudflareClient(zones=[{"id": "zone1", "name": "getexample.com"}])

    spec, outcome = steps.publish_dkim_record(
        client,  # type: ignore[arg-type]
        "account1",
        "getexample.com",
        SAMPLE_KEY,
        dns_config,
        state,
        dry_run=True,
    )

    assert client.writes == []
    assert not state.is_done(STEP_DKIM)
    assert spec.name == "google._domainkey.getexample.com"
    assert outcome.action.startswith("would-")


def test_publishing_dkim_does_not_create_a_zone_in_a_dry_run(
    state: RunState, dns_config: DnsConfig
) -> None:
    """Third caller of require_zone_id, and the third chance to create a zone."""
    client = RecordingCloudflareClient(zones=[])

    steps.publish_dkim_record(
        client,  # type: ignore[arg-type]
        "account1",
        "getexample.com",
        SAMPLE_KEY,
        dns_config,
        state,
        create_zone=True,
        dry_run=True,
    )

    assert client.writes == []


def test_clay_import_writes_no_file_in_a_dry_run(
    state: RunState, tmp_path: Path
) -> None:
    """Writing a CSV changes the operator's filesystem, so a preview must not."""
    output_dir = tmp_path / "out"

    path = steps.prepare_clay_import(
        "getexample.com",
        "connect@getexample.com",
        MailboxConfig(),
        state,
        output_dir=output_dir,
        dry_run=True,
    )

    assert not path.exists()
    assert not output_dir.exists()
    assert not state.is_done(STEP_CLAY)


def test_clay_import_reports_the_path_it_would_write(state: RunState, tmp_path: Path) -> None:
    """The preview is only useful if it names the file."""
    lines: list[str] = []

    steps.prepare_clay_import(
        "getexample.com",
        "connect@getexample.com",
        MailboxConfig(),
        state,
        output_dir=tmp_path / "out",
        dry_run=True,
        echo=lines.append,
    )

    assert any("would write" in line and "getexample.com.clay.csv" in line for line in lines)


def test_verification_records_no_state_in_a_dry_run(
    state: RunState, dns_config: DnsConfig
) -> None:
    """Resolving is read-only, but recording the result is not."""

    class EmptyLookup:
        """Resolver stub for a domain with nothing published."""

        resolvers = ("192.0.2.1",)

        def txt(self, _name: str) -> list[str]:
            return []

        def mx(self, _name: str) -> list[str]:
            return []

    from google_workspace_clay_provisioner.backoff import BackoffPolicy

    report = steps.verify_records(
        "getexample.com",
        dns_config,
        state,
        lookup=EmptyLookup(),  # type: ignore[arg-type]
        policy=BackoffPolicy(attempts=1),
        dry_run=True,
    )

    assert not report.passed
    assert not state.is_done(STEP_VERIFY_RECORDS)
