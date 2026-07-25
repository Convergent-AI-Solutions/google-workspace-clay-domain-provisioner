"""Publish DNS records in Cloudflare, idempotently.

Every write is an upsert keyed on the record's identity, not just its name:

* **MX** records match on name and target host, so the five-record legacy set
  coexists without overwriting itself.
* **TXT** records match on name and the spec's ``match_prefix``, so the SPF
  record and the Google site-verification token can share the zone apex
  without one replacing the other.

Re-running any step therefore converges rather than duplicating. Records are
only ever deleted when the caller explicitly asks to prune.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..dns_records import DnsRecordSpec, normalize_txt_value
from ..errors import CloudflareError
from .client import CloudflareClient

_PAGE_SIZE = 100


@dataclass(frozen=True)
class UpsertOutcome:
    """What happened to one record."""

    spec: DnsRecordSpec
    action: str
    record_id: str | None = None
    previous_content: str | None = None

    @property
    def changed(self) -> bool:
        """True when the zone was modified, or would be in a real run."""
        return self.action not in ("unchanged", "would-be-unchanged")


def get_zone_id(client: CloudflareClient, account_id: str, domain: str) -> str | None:
    """The zone id for ``domain``, or ``None`` when no zone exists yet."""
    result = client.get("/zones", params={"name": domain, "account.id": account_id})
    zones = result if isinstance(result, list) else []
    for zone in zones:
        if isinstance(zone, dict) and zone.get("name", "").lower() == domain.lower():
            zone_id = zone.get("id")
            if isinstance(zone_id, str):
                return zone_id
    return None


def create_zone(client: CloudflareClient, account_id: str, domain: str) -> str:
    """Create a full-setup zone for ``domain`` and return its id.

    Registering through Cloudflare Registrar normally creates the zone as part
    of registration, so this is the path for a domain registered elsewhere.
    """
    result = client.post(
        "/zones",
        json={"name": domain, "account": {"id": account_id}, "type": "full"},
    )
    zone_id = result.get("id") if isinstance(result, dict) else None
    if not isinstance(zone_id, str):
        raise CloudflareError(f"zone creation for {domain} returned no zone id")
    return zone_id


def require_zone_id(
    client: CloudflareClient,
    account_id: str,
    domain: str,
    *,
    create_if_missing: bool = False,
) -> str:
    """The zone id, creating the zone first when asked and it is absent."""
    zone_id = get_zone_id(client, account_id, domain)
    if zone_id:
        return zone_id
    if create_if_missing:
        return create_zone(client, account_id, domain)
    raise CloudflareError(
        f"no Cloudflare zone found for {domain}. If the domain is registered "
        f"elsewhere, add it to this account first, or re-run with the "
        f"create-zone option."
    )


def list_records(
    client: CloudflareClient,
    zone_id: str,
    *,
    record_type: str | None = None,
    name: str | None = None,
) -> list[dict[str, Any]]:
    """Every matching DNS record in the zone, following pagination."""
    records: list[dict[str, Any]] = []
    page = 1
    while True:
        params: dict[str, Any] = {"page": page, "per_page": _PAGE_SIZE}
        if record_type:
            params["type"] = record_type
        if name:
            params["name"] = name
        result = client.get(f"/zones/{zone_id}/dns_records", params=params)
        batch = result if isinstance(result, list) else []
        records.extend(item for item in batch if isinstance(item, dict))
        if len(batch) < _PAGE_SIZE:
            return records
        page += 1


def find_match(existing: list[dict[str, Any]], spec: DnsRecordSpec) -> dict[str, Any] | None:
    """The record ``spec`` should update, or ``None`` to create a new one.

    MX matches on target host so a multi-host set is preserved. TXT matches on
    ``match_prefix`` so the right one of several TXT records at a name is
    replaced.
    """
    for record in existing:
        if str(record.get("type", "")).upper() != spec.type.upper():
            continue
        if str(record.get("name", "")).lower() != spec.name.lower():
            continue

        content = str(record.get("content", ""))
        if spec.type.upper() == "MX":
            if content.rstrip(".").lower() == spec.content.rstrip(".").lower():
                return record
            continue
        if spec.match_prefix:
            if normalize_txt_value(content).lower().startswith(spec.match_prefix.lower()):
                return record
            continue
        if normalize_txt_value(content) == normalize_txt_value(spec.content):
            return record
    return None


def upsert_record(
    client: CloudflareClient,
    zone_id: str,
    spec: DnsRecordSpec,
    *,
    existing: list[dict[str, Any]] | None = None,
    dry_run: bool = False,
) -> UpsertOutcome:
    """Create or update one record so the zone matches ``spec``."""
    records = existing if existing is not None else list_records(client, zone_id)
    match = find_match(records, spec)
    body = _to_body(spec)

    if match is None:
        if dry_run:
            return UpsertOutcome(spec, "would-create")
        result = client.post(f"/zones/{zone_id}/dns_records", json=body)
        return UpsertOutcome(spec, "created", record_id=_id_of(result))

    if _matches_desired(match, spec):
        return UpsertOutcome(spec, "unchanged", record_id=str(match.get("id")))

    previous = str(match.get("content", ""))
    if dry_run:
        return UpsertOutcome(
            spec, "would-update", record_id=str(match.get("id")), previous_content=previous
        )

    result = client.put(f"/zones/{zone_id}/dns_records/{match.get('id')}", json=body)
    return UpsertOutcome(spec, "updated", record_id=_id_of(result), previous_content=previous)


def apply_specs(
    client: CloudflareClient,
    zone_id: str,
    specs: list[DnsRecordSpec],
    *,
    dry_run: bool = False,
) -> list[UpsertOutcome]:
    """Apply every spec, reading the zone once rather than per record."""
    existing = list_records(client, zone_id)
    outcomes = []
    for spec in specs:
        outcome = upsert_record(client, zone_id, spec, existing=existing, dry_run=dry_run)
        outcomes.append(outcome)
        # Keep the local view current so two specs sharing a name behave
        # correctly within one call.
        if outcome.action == "created" and outcome.record_id:
            existing.append(_to_body(spec) | {"id": outcome.record_id})
    return outcomes


def prune_unexpected_mx(
    client: CloudflareClient,
    zone_id: str,
    domain: str,
    expected_hosts: list[str],
    *,
    dry_run: bool = False,
) -> list[UpsertOutcome]:
    """Delete MX records at ``domain`` that are not in ``expected_hosts``.

    Destructive, so callers must opt in. Needed when switching between the
    single-host and legacy MX layouts, which would otherwise leave stale
    records routing mail to the wrong place.
    """
    wanted = {host.rstrip(".").lower() for host in expected_hosts}
    outcomes: list[UpsertOutcome] = []
    for record in list_records(client, zone_id, record_type="MX", name=domain):
        content = str(record.get("content", "")).rstrip(".").lower()
        if content in wanted:
            continue
        spec = DnsRecordSpec(
            type="MX",
            name=domain,
            content=content,
            priority=int(record.get("priority", 0) or 0),
            label=f"stale MX {content}",
        )
        if dry_run:
            outcomes.append(UpsertOutcome(spec, "would-delete", record_id=str(record.get("id"))))
            continue
        client.delete(f"/zones/{zone_id}/dns_records/{record.get('id')}")
        outcomes.append(UpsertOutcome(spec, "deleted", record_id=str(record.get("id"))))
    return outcomes


def _to_body(spec: DnsRecordSpec) -> dict[str, Any]:
    body: dict[str, Any] = {
        "type": spec.type,
        "name": spec.name,
        "content": spec.content,
        "ttl": spec.ttl,
    }
    if spec.priority is not None:
        body["priority"] = spec.priority
    return body


def _matches_desired(record: dict[str, Any], spec: DnsRecordSpec) -> bool:
    """True when the live record already says exactly what the spec wants."""
    if normalize_txt_value(str(record.get("content", ""))) != normalize_txt_value(spec.content):
        return False
    if spec.priority is not None and int(record.get("priority", -1) or -1) != spec.priority:
        return False
    return int(record.get("ttl", -1) or -1) == spec.ttl


def _id_of(result: Any) -> str | None:
    if isinstance(result, dict):
        value = result.get("id")
        return value if isinstance(value, str) else None
    return None
