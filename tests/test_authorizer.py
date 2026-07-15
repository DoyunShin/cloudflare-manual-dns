"""Tests for the DNS-record request authorization decision layer."""

from types import SimpleNamespace
from typing import Any

import pytest

from cfproxy.authz.authorizer import AuthDecision, authorize_dns_request
from cfproxy.core.cf_errors import FORBIDDEN, RECORD_NOT_FOUND

pytestmark = pytest.mark.asyncio


def make_rule(
    zone_id: str = "zone1",
    name_pattern: str | None = None,
    name_match: str = "exact",
    record_types: list | None = None,
    record_ids: list | None = None,
    allow_read: bool = False,
    allow_create: bool = False,
    allow_write: bool = False,
    allow_delete: bool = False,
) -> SimpleNamespace:
    """Build a `ScopeRule`-shaped `SimpleNamespace` for test fixtures.

    Return:
        rule(SimpleNamespace): An object exposing the same attributes as
            `cfproxy.db.models.ScopeRule`.
    """
    return SimpleNamespace(
        zone_id=zone_id,
        name_pattern=name_pattern,
        name_match=name_match,
        record_types=record_types if record_types is not None else ["A"],
        record_ids=record_ids,
        allow_read=allow_read,
        allow_create=allow_create,
        allow_write=allow_write,
        allow_delete=allow_delete,
    )


def make_fetch_record(record: dict | None) -> Any:
    """Build a fake `fetch_record` coroutine that always returns `record`.

    Return:
        fetch_record(Callable): Async callable ignoring its arguments and
            returning the fixed `record`.
    """

    async def _fetch(zone_id: str, record_id: str | None) -> dict | None:
        return record

    return _fetch


# ---------------------------------------------------------------------------
# POST (create)
# ---------------------------------------------------------------------------


async def test_create_allowed_by_body() -> None:
    """A create request authorized from the body's name/type is allowed."""
    rules = [
        make_rule(
            name_pattern="www.example.com", record_types=["A"], allow_create=True
        )
    ]
    decision = await authorize_dns_request(
        rules=rules,
        method="POST",
        zone_id="zone1",
        record_id=None,
        body={"name": "www.example.com", "type": "A", "content": "1.2.3.4"},
        fetch_record=make_fetch_record(None),
    )
    assert decision == AuthDecision(allowed=True)


async def test_create_denied_by_body() -> None:
    """A create request not covered by any rule is denied with 403 9109."""
    rules = [
        make_rule(
            name_pattern="www.example.com", record_types=["A"], allow_create=True
        )
    ]
    decision = await authorize_dns_request(
        rules=rules,
        method="POST",
        zone_id="zone1",
        record_id=None,
        body={"name": "other.example.com", "type": "A"},
        fetch_record=make_fetch_record(None),
    )
    assert decision.allowed is False
    assert decision.error == (403, FORBIDDEN, decision.error[2])
    assert decision.error[1] == FORBIDDEN


# ---------------------------------------------------------------------------
# GET (read) by-id
# ---------------------------------------------------------------------------


async def test_get_allowed_in_scope() -> None:
    """A GET for an in-scope record is allowed and carries the pre-image."""
    rules = [
        make_rule(
            name_pattern="www.example.com", record_types=["A"], allow_read=True
        )
    ]
    record = {"zone_id": "zone1", "name": "www.example.com", "type": "A"}
    decision = await authorize_dns_request(
        rules=rules,
        method="GET",
        zone_id="zone1",
        record_id="rec1",
        body=None,
        fetch_record=make_fetch_record(record),
    )
    assert decision.allowed is True
    assert decision.needs_lock is False
    assert decision.pre_image == record


async def test_get_out_of_scope_returns_404_not_403() -> None:
    """A GET for a record outside the rules is denied as 404 (no leak), not 403."""
    rules = [
        make_rule(
            name_pattern="www.example.com", record_types=["A"], allow_read=True
        )
    ]
    record = {"zone_id": "zone1", "name": "other.example.com", "type": "A"}
    decision = await authorize_dns_request(
        rules=rules,
        method="GET",
        zone_id="zone1",
        record_id="rec1",
        body=None,
        fetch_record=make_fetch_record(record),
    )
    assert decision.allowed is False
    assert decision.error == (404, RECORD_NOT_FOUND, decision.error[2])


async def test_get_missing_record_returns_404() -> None:
    """A GET for a record that does not exist upstream is 404."""
    rules = [make_rule(allow_read=True)]
    decision = await authorize_dns_request(
        rules=rules,
        method="GET",
        zone_id="zone1",
        record_id="rec1",
        body=None,
        fetch_record=make_fetch_record(None),
    )
    assert decision.allowed is False
    assert decision.error == (404, RECORD_NOT_FOUND, decision.error[2])


async def test_get_cross_zone_returns_404() -> None:
    """A GET where the fetched record belongs to a different zone is 404."""
    rules = [
        make_rule(
            name_pattern="www.example.com", record_types=["A"], allow_read=True
        )
    ]
    record = {"zone_id": "zone2", "name": "www.example.com", "type": "A"}
    decision = await authorize_dns_request(
        rules=rules,
        method="GET",
        zone_id="zone1",
        record_id="rec1",
        body=None,
        fetch_record=make_fetch_record(record),
    )
    assert decision.allowed is False
    assert decision.error == (404, RECORD_NOT_FOUND, decision.error[2])


# ---------------------------------------------------------------------------
# DELETE by-id
# ---------------------------------------------------------------------------


async def test_delete_allowed_in_scope() -> None:
    """A DELETE for an in-scope record is allowed."""
    rules = [
        make_rule(
            name_pattern="www.example.com", record_types=["A"], allow_delete=True
        )
    ]
    record = {"zone_id": "zone1", "name": "www.example.com", "type": "A"}
    decision = await authorize_dns_request(
        rules=rules,
        method="DELETE",
        zone_id="zone1",
        record_id="rec1",
        body=None,
        fetch_record=make_fetch_record(record),
    )
    assert decision.allowed is True


async def test_delete_denied_out_of_scope() -> None:
    """A DELETE for a record the rules do not grant delete on is 404."""
    rules = [
        make_rule(
            name_pattern="www.example.com", record_types=["A"], allow_read=True
        )
    ]
    record = {"zone_id": "zone1", "name": "www.example.com", "type": "A"}
    decision = await authorize_dns_request(
        rules=rules,
        method="DELETE",
        zone_id="zone1",
        record_id="rec1",
        body=None,
        fetch_record=make_fetch_record(record),
    )
    assert decision.allowed is False
    assert decision.error == (404, RECORD_NOT_FOUND, decision.error[2])


# ---------------------------------------------------------------------------
# PUT / PATCH rename-escape
# ---------------------------------------------------------------------------


async def test_put_rename_escape_denied() -> None:
    """PUT changing 'www A' to '@ A' (zone apex) is denied with 403 (rename escape)."""
    rules = [
        make_rule(
            name_pattern="www.example.com",
            name_match="exact",
            record_types=["A"],
            allow_write=True,
        )
    ]
    record = {"zone_id": "zone1", "name": "www.example.com", "type": "A"}
    decision = await authorize_dns_request(
        rules=rules,
        method="PUT",
        zone_id="zone1",
        record_id="rec1",
        body={"name": "example.com", "type": "A", "content": "1.2.3.4"},
        fetch_record=make_fetch_record(record),
    )
    assert decision.allowed is False
    assert decision.error == (403, FORBIDDEN, decision.error[2])


async def test_patch_type_change_escape_denied() -> None:
    """PATCH changing the record's type out of the rule's scope is denied with 403."""
    rules = [
        make_rule(
            name_pattern="www.example.com",
            name_match="exact",
            record_types=["A"],
            allow_write=True,
        )
    ]
    record = {"zone_id": "zone1", "name": "www.example.com", "type": "A"}
    decision = await authorize_dns_request(
        rules=rules,
        method="PATCH",
        zone_id="zone1",
        record_id="rec1",
        body={"type": "TXT"},
        fetch_record=make_fetch_record(record),
    )
    assert decision.allowed is False
    assert decision.error == (403, FORBIDDEN, decision.error[2])


async def test_patch_unchanged_name_type_allowed() -> None:
    """PATCH not changing name/type only needs the old-image authorization."""
    rules = [
        make_rule(
            name_pattern="www.example.com",
            name_match="exact",
            record_types=["A"],
            allow_write=True,
        )
    ]
    record = {"zone_id": "zone1", "name": "www.example.com", "type": "A"}
    decision = await authorize_dns_request(
        rules=rules,
        method="PATCH",
        zone_id="zone1",
        record_id="rec1",
        body={"content": "5.6.7.8"},
        fetch_record=make_fetch_record(record),
    )
    assert decision.allowed is True


async def test_put_rename_within_scope_allowed() -> None:
    """PUT renaming to another name still covered by the rule (wildcard) is allowed."""
    rules = [
        make_rule(
            name_pattern="*.example.com",
            name_match="wildcard",
            record_types=["A"],
            allow_write=True,
        )
    ]
    record = {"zone_id": "zone1", "name": "www.example.com", "type": "A"}
    decision = await authorize_dns_request(
        rules=rules,
        method="PUT",
        zone_id="zone1",
        record_id="rec1",
        body={"name": "api.example.com", "type": "A", "content": "1.2.3.4"},
        fetch_record=make_fetch_record(record),
    )
    assert decision.allowed is True


# ---------------------------------------------------------------------------
# Cross-zone by-id for mutation methods
# ---------------------------------------------------------------------------


async def test_delete_cross_zone_returns_404() -> None:
    """A DELETE where the fetched record belongs to another zone is 404."""
    rules = [make_rule(record_types=["*"], allow_delete=True)]
    record = {"zone_id": "zoneX", "name": "www.example.com", "type": "A"}
    decision = await authorize_dns_request(
        rules=rules,
        method="DELETE",
        zone_id="zone1",
        record_id="rec1",
        body=None,
        fetch_record=make_fetch_record(record),
    )
    assert decision.allowed is False
    assert decision.error == (404, RECORD_NOT_FOUND, decision.error[2])


# ---------------------------------------------------------------------------
# needs_lock
# ---------------------------------------------------------------------------


async def test_needs_lock_true_when_not_lock_exempt() -> None:
    """A name/type-authorized (non-id-pinned) PATCH requires the mutation lock."""
    rules = [
        make_rule(
            name_pattern="www.example.com",
            name_match="exact",
            record_types=["A"],
            allow_write=True,
        )
    ]
    record = {"zone_id": "zone1", "name": "www.example.com", "type": "A"}
    decision = await authorize_dns_request(
        rules=rules,
        method="PATCH",
        zone_id="zone1",
        record_id="rec1",
        body={"content": "5.6.7.8"},
        fetch_record=make_fetch_record(record),
    )
    assert decision.needs_lock is True


async def test_needs_lock_false_when_lock_exempt() -> None:
    """A pure record_ids + ['*'] + no-name rule is lock-exempt for PATCH."""
    rules = [
        make_rule(
            name_pattern=None,
            record_types=["*"],
            record_ids=["rec1"],
            allow_write=True,
        )
    ]
    record = {"zone_id": "zone1", "name": "www.example.com", "type": "A"}
    decision = await authorize_dns_request(
        rules=rules,
        method="PATCH",
        zone_id="zone1",
        record_id="rec1",
        body={"content": "5.6.7.8"},
        fetch_record=make_fetch_record(record),
    )
    assert decision.needs_lock is False
    assert decision.allowed is True


async def test_needs_lock_false_for_get() -> None:
    """GET (read-only) never requires the mutation lock."""
    rules = [
        make_rule(
            name_pattern="www.example.com", record_types=["A"], allow_read=True
        )
    ]
    record = {"zone_id": "zone1", "name": "www.example.com", "type": "A"}
    decision = await authorize_dns_request(
        rules=rules,
        method="GET",
        zone_id="zone1",
        record_id="rec1",
        body=None,
        fetch_record=make_fetch_record(record),
    )
    assert decision.needs_lock is False


async def test_needs_lock_computed_before_fetch_even_when_denied() -> None:
    """needs_lock is computed from record_id+rules regardless of the fetch outcome."""
    rules = [
        make_rule(
            name_pattern=None,
            record_types=["*"],
            record_ids=["rec1"],
            allow_delete=True,
        )
    ]
    decision = await authorize_dns_request(
        rules=rules,
        method="DELETE",
        zone_id="zone1",
        record_id="rec1",
        body=None,
        fetch_record=make_fetch_record(None),
    )
    assert decision.allowed is False
    assert decision.needs_lock is False
    assert decision.error == (404, RECORD_NOT_FOUND, decision.error[2])
