"""Tests for client-facing DNS-record list filtering and re-pagination."""

from types import SimpleNamespace

from cfproxy.filtering.list_filter import filter_records, paginate_and_result_info


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
        record_types=record_types if record_types is not None else ["*"],
        record_ids=record_ids,
        allow_read=allow_read,
        allow_create=allow_create,
        allow_write=allow_write,
        allow_delete=allow_delete,
    )


# ---------------------------------------------------------------------------
# filter_records
# ---------------------------------------------------------------------------


def test_filter_records_keeps_only_read_authorized() -> None:
    """Only records matched by a read-granting rule survive filtering."""
    rules = [make_rule(name_pattern="home.example.com", allow_read=True)]
    records = [
        {"id": "rec1", "name": "home.example.com", "type": "A"},
        {"id": "rec2", "name": "other.example.com", "type": "A"},
    ]
    assert filter_records(records, rules, "zone1") == [
        {"id": "rec1", "name": "home.example.com", "type": "A"}
    ]


def test_filter_records_wrong_zone_excluded() -> None:
    """A rule bound to a different zone_id never authorizes any record."""
    rules = [make_rule(zone_id="zone2", allow_read=True)]
    records = [{"id": "rec1", "name": "home.example.com", "type": "A"}]
    assert filter_records(records, rules, "zone1") == []


def test_filter_records_no_rules_returns_empty() -> None:
    """An empty rule set authorizes nothing."""
    records = [{"id": "rec1", "name": "home.example.com", "type": "A"}]
    assert filter_records(records, [], "zone1") == []


def test_filter_records_write_only_rule_excludes_from_read() -> None:
    """A rule that only grants write (not read) does not authorize a read filter."""
    rules = [make_rule(allow_write=True)]
    records = [{"id": "rec1", "name": "home.example.com", "type": "A"}]
    assert filter_records(records, rules, "zone1") == []


def test_filter_records_type_restricted_rule_excludes_other_types() -> None:
    """A type-restricted rule filters out records of a different type."""
    rules = [make_rule(record_types=["A"], allow_read=True)]
    records = [
        {"id": "rec1", "name": "home.example.com", "type": "A"},
        {"id": "rec2", "name": "home.example.com", "type": "TXT"},
    ]
    assert filter_records(records, rules, "zone1") == [
        {"id": "rec1", "name": "home.example.com", "type": "A"}
    ]


def test_filter_records_preserves_order() -> None:
    """Filtering preserves the original ordering of authorized records."""
    rules = [make_rule(allow_read=True)]
    records = [
        {"id": "rec3", "name": "c.example.com", "type": "A"},
        {"id": "rec1", "name": "a.example.com", "type": "A"},
        {"id": "rec2", "name": "b.example.com", "type": "A"},
    ]
    assert [r["id"] for r in filter_records(records, rules, "zone1")] == [
        "rec3",
        "rec1",
        "rec2",
    ]


# ---------------------------------------------------------------------------
# paginate_and_result_info
# ---------------------------------------------------------------------------


def test_paginate_full_first_page() -> None:
    """The first full page returns the correct slice and result_info."""
    records = [{"id": f"rec{i}"} for i in range(5)]
    page_records, result_info = paginate_and_result_info(records, page=1, per_page=2)
    assert page_records == records[0:2]
    assert result_info == {
        "page": 1,
        "per_page": 2,
        "count": 2,
        "total_count": 5,
        "total_pages": 3,
    }


def test_paginate_middle_page() -> None:
    """A middle page returns the correct slice and result_info."""
    records = [{"id": f"rec{i}"} for i in range(5)]
    page_records, result_info = paginate_and_result_info(records, page=2, per_page=2)
    assert page_records == records[2:4]
    assert result_info == {
        "page": 2,
        "per_page": 2,
        "count": 2,
        "total_count": 5,
        "total_pages": 3,
    }


def test_paginate_last_partial_page() -> None:
    """The final, partially-filled page returns only its remaining records."""
    records = [{"id": f"rec{i}"} for i in range(5)]
    page_records, result_info = paginate_and_result_info(records, page=3, per_page=2)
    assert page_records == records[4:5]
    assert result_info == {
        "page": 3,
        "per_page": 2,
        "count": 1,
        "total_count": 5,
        "total_pages": 3,
    }


def test_paginate_page_beyond_range_returns_empty() -> None:
    """A page number past the end of the data returns an empty slice."""
    records = [{"id": f"rec{i}"} for i in range(5)]
    page_records, result_info = paginate_and_result_info(records, page=4, per_page=2)
    assert page_records == []
    assert result_info == {
        "page": 4,
        "per_page": 2,
        "count": 0,
        "total_count": 5,
        "total_pages": 3,
    }


def test_paginate_empty_records() -> None:
    """An empty record list yields a zeroed result_info."""
    page_records, result_info = paginate_and_result_info([], page=1, per_page=20)
    assert page_records == []
    assert result_info == {
        "page": 1,
        "per_page": 20,
        "count": 0,
        "total_count": 0,
        "total_pages": 0,
    }


def test_paginate_exact_multiple_of_per_page() -> None:
    """When total_count is an exact multiple of per_page, total_pages divides evenly."""
    records = [{"id": f"rec{i}"} for i in range(6)]
    _, result_info = paginate_and_result_info(records, page=3, per_page=2)
    assert result_info["total_pages"] == 3
    assert result_info["total_count"] == 6
