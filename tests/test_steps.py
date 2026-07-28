"""Unit tests for the orchestration in ``steps.py``.

These are the guards that make the tool safe to re-run — the resume checks that
stop a second paid registration, the "password only on creation" rule, and the
honest recording of a failed verification. Each step takes injected clients and
an ``echo`` callable, so a fake stands in for the network.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from google_workspace_clay_provisioner import steps
from google_workspace_clay_provisioner.config import DnsConfig, MailboxConfig, RegistrantContact
from google_workspace_clay_provisioner.errors import PurchaseAborted
from google_workspace_clay_provisioner.state import (
    STEP_LICENSE,
    STEP_REGISTER,
    STEP_VERIFY_RECORDS,
    RunState,
)


class NotFound(Exception):
    """A stand-in for a googleapiclient 404, which callers treat as absence."""

    status_code = 404


class FakeRegistrarClient:
    """Serves the two reads/writes ``purchase_domain`` makes and records them."""

    def __init__(self, owned: dict[str, Any] | None = None) -> None:
        self.owned = owned
        self.register_calls = 0

    def get_optional(self, path: str, **_: Any) -> Any:
        return self.owned

    def request(self, method: str, path: str, **_: Any) -> tuple[Any, int]:
        self.register_calls += 1
        return {"id": "registration"}, 201


class ExplodingRegistrarClient:
    """Any registrar traffic at all fails the test."""

    def get_optional(self, path: str, **_: Any) -> Any:
        raise AssertionError("no ownership lookup should happen")

    def request(self, *_: Any, **__: Any) -> tuple[Any, int]:
        raise AssertionError("no registration should happen")


class FakeUsersDirectory:
    """Directory stub for user get/insert.

    ``exists`` decides whether the mailbox is already present; a fresh insert
    records the body so a test can confirm the create path ran.
    """

    def __init__(self, exists: bool = False) -> None:
        self.exists = exists
        self.inserted_body: dict[str, Any] | None = None
        self._op = ""

    def users(self) -> Any:
        return self

    def get(self, userKey: str | None = None) -> Any:  # noqa: N803 - Google's kwarg name
        self._op = "get"
        return self

    def insert(self, body: dict[str, Any] | None = None) -> Any:
        self._op = "insert"
        self.inserted_body = body
        return self

    def execute(self) -> dict[str, Any]:
        if self._op == "get":
            if self.exists:
                return {"primaryEmail": "connect@getexample.com"}
            raise NotFound("no such user")
        return {"primaryEmail": "connect@getexample.com"}


class FakeLicensingService:
    """Licensing stub recording the assignment it was asked to make."""

    def __init__(self) -> None:
        self.assigned: dict[str, Any] | None = None

    def licenseAssignments(self) -> Any:  # noqa: N802 - mirrors the Google client
        return self

    def insert(self, *, productId: str, skuId: str, body: dict[str, Any]) -> Any:  # noqa: N803
        self.assigned = {"productId": productId, "skuId": skuId, "body": body}
        return self

    def execute(self) -> dict[str, Any]:
        return {"skuId": (self.assigned or {}).get("skuId")}


@pytest.fixture
def state(tmp_path: Path) -> RunState:
    return RunState.load(tmp_path, "getexample.com")


def test_purchase_does_not_register_when_state_says_done(state: RunState) -> None:
    """A resumed run must never pay twice, so a recorded registration short-circuits."""
    state.mark_done(STEP_REGISTER, domain="getexample.com", outcome="registered")

    outcome = steps.purchase_domain(
        ExplodingRegistrarClient(),  # type: ignore[arg-type]
        "account1",
        "getexample.com",
        state,
        registrant=RegistrantContact(),
        confirmed=True,
    )

    assert outcome == "already-owned"


def test_purchase_does_not_register_when_domain_already_owned(state: RunState) -> None:
    """If Cloudflare already owns the domain, registering again would double-charge."""
    client = FakeRegistrarClient(owned={"name": "getexample.com"})

    outcome = steps.purchase_domain(
        client,  # type: ignore[arg-type]
        "account1",
        "getexample.com",
        state,
        registrant=RegistrantContact(),
        confirmed=True,
    )

    assert outcome == "already-owned"
    assert client.register_calls == 0
    assert state.is_done(STEP_REGISTER)


def test_purchase_refuses_without_confirmation(state: RunState) -> None:
    """Spending money requires an explicit confirmed flag outside a dry run."""
    client = FakeRegistrarClient(owned=None)

    with pytest.raises(PurchaseAborted):
        steps.purchase_domain(
            client,  # type: ignore[arg-type]
            "account1",
            "getexample.com",
            state,
            registrant=RegistrantContact(),
            confirmed=False,
        )

    assert client.register_calls == 0
    assert not state.is_done(STEP_REGISTER)


def test_purchase_dry_run_registers_nothing(state: RunState) -> None:
    """A preview must not touch the registrar or the state file."""
    client = FakeRegistrarClient(owned=None)

    outcome = steps.purchase_domain(
        client,  # type: ignore[arg-type]
        "account1",
        "getexample.com",
        state,
        registrant=RegistrantContact(),
        dry_run=True,
    )

    assert outcome == "would-register"
    assert client.register_calls == 0
    assert not state.is_done(STEP_REGISTER)


def test_create_mailbox_returns_password_only_on_creation(state: RunState) -> None:
    """A freshly created user yields a password to surface once."""
    email, password, action = steps.create_mailbox(
        FakeUsersDirectory(exists=False), "getexample.com", MailboxConfig(), state
    )

    assert action == "created"
    assert email == "connect@getexample.com"
    assert password is not None


def test_create_mailbox_returns_no_password_when_user_exists(state: RunState) -> None:
    """A resumed run must not hand back a password for a mailbox it did not create."""
    _, password, action = steps.create_mailbox(
        FakeUsersDirectory(exists=True), "getexample.com", MailboxConfig(), state
    )

    assert action == "exists"
    assert password is None


def test_create_mailbox_returns_no_password_when_step_already_done(state: RunState) -> None:
    """The state short-circuit also must not leak a password."""
    state.mark_done("create_mailbox", email="connect@getexample.com", outcome="created")

    _, password, action = steps.create_mailbox(
        FakeUsersDirectory(exists=False), "getexample.com", MailboxConfig(), state
    )

    assert action == "exists"
    assert password is None


class EmptyLookup:
    """Resolver stub for a domain with nothing published."""

    resolvers = ("192.0.2.1",)

    def txt(self, _name: str) -> list[str]:
        return []

    def mx(self, _name: str) -> list[str]:
        return []


def test_verify_records_marks_failed_not_done_on_failure(state: RunState) -> None:
    """A domain whose records do not resolve must not read as verified in status."""
    from google_workspace_clay_provisioner.backoff import BackoffPolicy

    report = steps.verify_records(
        "getexample.com",
        DnsConfig(),
        state,
        lookup=EmptyLookup(),  # type: ignore[arg-type]
        policy=BackoffPolicy(attempts=1),
    )

    assert not report.passed
    assert not state.is_done(STEP_VERIFY_RECORDS)
    assert state.detail(STEP_VERIFY_RECORDS)["status"] == "failed"


def test_verify_records_read_only_does_not_touch_state(state: RunState) -> None:
    """The checklist verifies read-only; it must not overwrite a recorded result."""
    from google_workspace_clay_provisioner.backoff import BackoffPolicy

    steps.verify_records(
        "getexample.com",
        DnsConfig(),
        state,
        lookup=EmptyLookup(),  # type: ignore[arg-type]
        policy=BackoffPolicy(attempts=1),
        record_state=False,
    )

    assert state.detail(STEP_VERIFY_RECORDS) == {}


def test_assign_mailbox_license_records_the_outcome(state: RunState) -> None:
    """Assigning a licence is recorded so a re-run can see it was done."""
    licensing = FakeLicensingService()

    action = steps.assign_mailbox_license(
        licensing,  # type: ignore[arg-type]
        "connect@getexample.com",
        state,
        product_id="Google-Apps",
        sku_id="1010020027",
    )

    assert action == "assigned"
    assert licensing.assigned is not None
    assert state.is_done(STEP_LICENSE)


def test_assign_mailbox_license_dry_run_makes_no_call(state: RunState) -> None:
    """A preview must not assign a licence or write state."""
    licensing = FakeLicensingService()

    action = steps.assign_mailbox_license(
        licensing,  # type: ignore[arg-type]
        "connect@getexample.com",
        state,
        product_id="Google-Apps",
        sku_id="1010020027",
        dry_run=True,
    )

    assert action == "would-assign"
    assert licensing.assigned is None
    assert not state.is_done(STEP_LICENSE)
