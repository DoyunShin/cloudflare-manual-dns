"""Heavy unit matrix for the pure DNS-record scope matching logic."""

from types import SimpleNamespace

import pytest

from cfproxy.authz.scope import (
    is_lock_exempt,
    match_rules,
    merge_patch_image,
    name_matches,
    normalize_fqdn,
    validate_name_pattern,
)


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


# ---------------------------------------------------------------------------
# normalize_fqdn
# ---------------------------------------------------------------------------


def test_normalize_fqdn_lowercases() -> None:
    """Uppercase labels are lowercased."""
    assert normalize_fqdn("WWW.Example.COM") == "www.example.com"


def test_normalize_fqdn_strips_trailing_dot() -> None:
    """A trailing dot is stripped."""
    assert normalize_fqdn("example.com.") == "example.com"


def test_normalize_fqdn_strips_whitespace() -> None:
    """Surrounding whitespace is stripped."""
    assert normalize_fqdn("  example.com  ") == "example.com"


def test_normalize_fqdn_idna_encodes_unicode_labels() -> None:
    """Unicode labels are punycode-encoded."""
    assert normalize_fqdn("café.example.com") == "xn--caf-dma.example.com"


def test_normalize_fqdn_preserves_ascii_wildcard_label() -> None:
    """A literal '*' label passes through unchanged."""
    assert normalize_fqdn("*.example.com") == "*.example.com"


def test_normalize_fqdn_idempotent_on_already_ascii() -> None:
    """Already-punycode names are unaffected."""
    assert normalize_fqdn("xn--caf-dma.example.com") == "xn--caf-dma.example.com"


def test_normalize_fqdn_empty_string() -> None:
    """An empty string normalizes to an empty string."""
    assert normalize_fqdn("") == ""


# ---------------------------------------------------------------------------
# validate_name_pattern -- exact
# ---------------------------------------------------------------------------


def test_validate_name_pattern_exact_apex_zone_name() -> None:
    """Exact pattern equal to the zone name (apex) is valid."""
    validate_name_pattern("example.com", "exact", "example.com")


def test_validate_name_pattern_exact_apex_at_symbol() -> None:
    """Exact pattern '@' (apex marker) is valid."""
    validate_name_pattern("@", "exact", "example.com")


def test_validate_name_pattern_exact_subdomain() -> None:
    """Exact pattern for a subdomain of the zone is valid."""
    validate_name_pattern("www.example.com", "exact", "example.com")


def test_validate_name_pattern_exact_case_insensitive() -> None:
    """Exact pattern validation is case-insensitive."""
    validate_name_pattern("WWW.EXAMPLE.COM", "exact", "example.com")


def test_validate_name_pattern_exact_wrong_zone_rejected() -> None:
    """Exact pattern outside the zone is rejected."""
    with pytest.raises(ValueError):
        validate_name_pattern("www.other.com", "exact", "example.com")


def test_validate_name_pattern_exact_suffix_without_dot_rejected() -> None:
    """A same-suffix-but-no-dot-boundary name is rejected (not a real subdomain)."""
    with pytest.raises(ValueError):
        validate_name_pattern("notexample.com", "exact", "example.com")


def test_validate_name_pattern_exact_rejects_wildcard_char() -> None:
    """Exact patterns must not contain '*'."""
    with pytest.raises(ValueError):
        validate_name_pattern("*.example.com", "exact", "example.com")


# ---------------------------------------------------------------------------
# validate_name_pattern -- wildcard
# ---------------------------------------------------------------------------


def test_validate_name_pattern_wildcard_leftmost_label() -> None:
    """Wildcard occupying the leftmost label of the zone is valid."""
    validate_name_pattern("*.example.com", "wildcard", "example.com")


def test_validate_name_pattern_wildcard_deeper_label() -> None:
    """Wildcard occupying a fixed deeper label is valid."""
    validate_name_pattern("*.sub.example.com", "wildcard", "example.com")


def test_validate_name_pattern_wildcard_bare_star_rejected() -> None:
    """A bare '*' with no zone suffix is rejected."""
    with pytest.raises(ValueError):
        validate_name_pattern("*", "wildcard", "example.com")


def test_validate_name_pattern_wildcard_multiple_stars_rejected() -> None:
    """More than one '*' is rejected."""
    with pytest.raises(ValueError):
        validate_name_pattern("*.*.example.com", "wildcard", "example.com")


def test_validate_name_pattern_wildcard_mid_label_rejected() -> None:
    """A '*' that does not occupy a whole label is rejected."""
    with pytest.raises(ValueError):
        validate_name_pattern("ab*.example.com", "wildcard", "example.com")


def test_validate_name_pattern_wildcard_prefix_mid_label_rejected() -> None:
    """A '*' at the end of a mixed label is rejected."""
    with pytest.raises(ValueError):
        validate_name_pattern("*ab.example.com", "wildcard", "example.com")


def test_validate_name_pattern_wildcard_wrong_zone_suffix_rejected() -> None:
    """A wildcard pattern whose fixed suffix is not the rule's zone is rejected."""
    with pytest.raises(ValueError):
        validate_name_pattern("*.other.com", "wildcard", "example.com")


def test_validate_name_pattern_unknown_name_match_rejected() -> None:
    """An unrecognized name_match value is rejected."""
    with pytest.raises(ValueError):
        validate_name_pattern("example.com", "regex", "example.com")


# ---------------------------------------------------------------------------
# name_matches -- exact
# ---------------------------------------------------------------------------


def test_name_matches_exact_equal() -> None:
    """Exact match succeeds on equal canonical names."""
    assert name_matches("home.example.com", "exact", "home.example.com") is True


def test_name_matches_exact_case_and_dot_insensitive() -> None:
    """Exact match ignores case and a trailing dot."""
    assert name_matches("Home.Example.com", "exact", "home.example.com.") is True


def test_name_matches_exact_different_name_rejected() -> None:
    """Exact match fails on a different name."""
    assert name_matches("home.example.com", "exact", "work.example.com") is False


def test_name_matches_exact_apex() -> None:
    """Exact match on the zone apex itself succeeds."""
    assert name_matches("example.com", "exact", "example.com") is True


def test_name_matches_exact_underscore_label() -> None:
    """Exact match works for underscore-prefixed labels (e.g. ACME challenge)."""
    assert (
        name_matches(
            "_acme-challenge.example.com", "exact", "_acme-challenge.example.com"
        )
        is True
    )


# ---------------------------------------------------------------------------
# name_matches -- wildcard (DNS-label-aware, heavy matrix)
# ---------------------------------------------------------------------------


def test_name_matches_wildcard_one_label_matches() -> None:
    """'*.example.com' matches a single-label subdomain."""
    assert name_matches("*.example.com", "wildcard", "a.example.com") is True


def test_name_matches_wildcard_does_not_cross_dot() -> None:
    """'*.example.com' does NOT match a two-label subdomain (no dot-crossing)."""
    assert name_matches("*.example.com", "wildcard", "a.b.example.com") is False


def test_name_matches_wildcard_excludes_apex() -> None:
    """'*.example.com' does NOT match the zone apex."""
    assert name_matches("*.example.com", "wildcard", "example.com") is False


def test_name_matches_wildcard_deeper_fixed_position() -> None:
    """'*.sub.example.com' matches exactly one label at that fixed position."""
    assert name_matches("*.sub.example.com", "wildcard", "a.sub.example.com") is True


def test_name_matches_wildcard_deeper_position_rejects_extra_label() -> None:
    """'*.sub.example.com' does not match with an extra label inserted."""
    assert (
        name_matches("*.sub.example.com", "wildcard", "a.b.sub.example.com") is False
    )


def test_name_matches_wildcard_deeper_position_rejects_missing_label() -> None:
    """'*.sub.example.com' does not match with the wildcard label missing."""
    assert name_matches("*.sub.example.com", "wildcard", "sub.example.com") is False


def test_name_matches_wildcard_rejects_wrong_fixed_suffix() -> None:
    """'*.example.com' does not match a name in a different zone."""
    assert name_matches("*.example.com", "wildcard", "a.other.com") is False


def test_name_matches_wildcard_case_and_dot_insensitive() -> None:
    """Wildcard match ignores case and a trailing dot on the target."""
    assert name_matches("*.Example.com", "wildcard", "A.example.com.") is True


# ---------------------------------------------------------------------------
# match_rules
# ---------------------------------------------------------------------------


def test_match_rules_exact_read_allowed() -> None:
    """A matching exact rule with allow_read grants a read."""
    rules = [
        make_rule(
            name_pattern="home.example.com",
            name_match="exact",
            record_types=["A"],
            allow_read=True,
        )
    ]
    assert (
        match_rules(rules, "zone1", "home.example.com", "A", "rec1", "read") is True
    )


def test_match_rules_wildcard_read_allowed() -> None:
    """A matching wildcard rule with allow_read grants a read."""
    rules = [
        make_rule(
            name_pattern="*.example.com",
            name_match="wildcard",
            record_types=["A"],
            allow_read=True,
        )
    ]
    assert match_rules(rules, "zone1", "a.example.com", "A", "rec1", "read") is True


def test_match_rules_wildcard_does_not_cross_label_boundary() -> None:
    """A wildcard rule denies a multi-label subdomain."""
    rules = [
        make_rule(
            name_pattern="*.example.com",
            name_match="wildcard",
            record_types=["A"],
            allow_read=True,
        )
    ]
    assert (
        match_rules(rules, "zone1", "a.b.example.com", "A", "rec1", "read") is False
    )


def test_match_rules_wrong_zone_denied() -> None:
    """A rule for a different zone_id never matches."""
    rules = [
        make_rule(
            zone_id="zone2",
            name_pattern="home.example.com",
            allow_read=True,
        )
    ]
    assert (
        match_rules(rules, "zone1", "home.example.com", "A", "rec1", "read") is False
    )


def test_match_rules_type_wildcard_allows_any_type() -> None:
    """record_types == ['*'] allows any DNS record type."""
    rules = [
        make_rule(
            name_pattern="home.example.com",
            record_types=["*"],
            allow_read=True,
        )
    ]
    assert (
        match_rules(rules, "zone1", "home.example.com", "TXT", "rec1", "read")
        is True
    )


def test_match_rules_type_mismatch_denied() -> None:
    """A rule restricted to one type does not match a different type."""
    rules = [
        make_rule(
            name_pattern="home.example.com",
            record_types=["A"],
            allow_read=True,
        )
    ]
    assert (
        match_rules(rules, "zone1", "home.example.com", "TXT", "rec1", "read")
        is False
    )


def test_match_rules_record_ids_pin_matches() -> None:
    """A record_ids-pinned rule matches when the id is in the pin list."""
    rules = [make_rule(record_ids=["rec1", "rec2"], allow_read=True)]
    assert match_rules(rules, "zone1", None, "A", "rec1", "read") is True


def test_match_rules_record_ids_pin_rejects_other_id() -> None:
    """A record_ids-pinned rule denies an id not in the pin list."""
    rules = [make_rule(record_ids=["rec1", "rec2"], allow_read=True)]
    assert match_rules(rules, "zone1", None, "A", "rec3", "read") is False


def test_match_rules_record_ids_pin_denies_create_without_id() -> None:
    """An id-pinned rule never grants create (create has no record_id yet)."""
    rules = [make_rule(record_ids=["rec1"], allow_create=True)]
    assert match_rules(rules, "zone1", "home.example.com", "A", None, "create") is False


def test_match_rules_create_uses_name_and_type_from_body() -> None:
    """A create is authorized from name+type when record_id is None."""
    rules = [
        make_rule(
            name_pattern="home.example.com",
            record_types=["A"],
            allow_create=True,
        )
    ]
    assert (
        match_rules(rules, "zone1", "home.example.com", "A", None, "create") is True
    )


@pytest.mark.parametrize(
    "op,flag_kwarg",
    [
        ("read", "allow_read"),
        ("create", "allow_create"),
        ("write", "allow_write"),
        ("delete", "allow_delete"),
    ],
)
def test_match_rules_per_op_flags(op: str, flag_kwarg: str) -> None:
    """Each operation is gated independently by its own allow_* flag."""
    granted = [
        make_rule(
            name_pattern="home.example.com",
            record_types=["*"],
            **{flag_kwarg: True},
        )
    ]
    assert match_rules(granted, "zone1", "home.example.com", "A", "rec1", op) is True

    denied = [make_rule(name_pattern="home.example.com", record_types=["*"])]
    assert match_rules(denied, "zone1", "home.example.com", "A", "rec1", op) is False


def test_match_rules_no_rules_denies() -> None:
    """An empty rule set never authorizes anything."""
    assert match_rules([], "zone1", "home.example.com", "A", "rec1", "read") is False


def test_match_rules_no_name_pattern_matches_any_name() -> None:
    """A rule with name_pattern=None matches any name (e.g. an id-only rule)."""
    rules = [make_rule(name_pattern=None, record_ids=["rec1"], allow_read=True)]
    assert match_rules(rules, "zone1", "anything.example.com", "A", "rec1", "read") is True


def test_match_rules_second_rule_can_grant_after_first_fails() -> None:
    """If one rule doesn't match, later rules are still evaluated."""
    rules = [
        make_rule(name_pattern="other.example.com", allow_read=True),
        make_rule(name_pattern="home.example.com", allow_read=True),
    ]
    assert (
        match_rules(rules, "zone1", "home.example.com", "A", "rec1", "read") is True
    )


# ---------------------------------------------------------------------------
# is_lock_exempt
# ---------------------------------------------------------------------------


def test_is_lock_exempt_true_for_pure_record_id_rule() -> None:
    """A pure record_ids + ['*'] + no-name rule is lock-exempt."""
    rules = [
        make_rule(
            name_pattern=None,
            record_types=["*"],
            record_ids=["rec1"],
            allow_write=True,
        )
    ]
    assert is_lock_exempt(rules, "zone1", "rec1", "write") is True


def test_is_lock_exempt_false_when_name_pattern_present() -> None:
    """A rule with a name_pattern is never lock-exempt, even if id-pinned."""
    rules = [
        make_rule(
            name_pattern="home.example.com",
            record_types=["*"],
            record_ids=["rec1"],
            allow_write=True,
        )
    ]
    assert is_lock_exempt(rules, "zone1", "rec1", "write") is False


def test_is_lock_exempt_false_when_record_types_restricted() -> None:
    """A rule restricted to specific record types is never lock-exempt."""
    rules = [
        make_rule(
            name_pattern=None,
            record_types=["A"],
            record_ids=["rec1"],
            allow_write=True,
        )
    ]
    assert is_lock_exempt(rules, "zone1", "rec1", "write") is False


def test_is_lock_exempt_false_when_id_not_pinned() -> None:
    """A rule without record_ids (or a different id) is never lock-exempt."""
    rules = [make_rule(name_pattern=None, record_types=["*"], allow_write=True)]
    assert is_lock_exempt(rules, "zone1", "rec1", "write") is False


def test_is_lock_exempt_false_when_id_not_in_pin_list() -> None:
    """A rule pinning a different record id is not exempt for this id."""
    rules = [
        make_rule(
            name_pattern=None,
            record_types=["*"],
            record_ids=["rec2"],
            allow_write=True,
        )
    ]
    assert is_lock_exempt(rules, "zone1", "rec1", "write") is False


def test_is_lock_exempt_false_when_op_not_granted() -> None:
    """A qualifying rule that does not grant the requested op is not exempt."""
    rules = [
        make_rule(
            name_pattern=None,
            record_types=["*"],
            record_ids=["rec1"],
            allow_read=True,
        )
    ]
    assert is_lock_exempt(rules, "zone1", "rec1", "write") is False


def test_is_lock_exempt_false_for_wrong_zone() -> None:
    """A qualifying rule for a different zone is not exempt for this zone."""
    rules = [
        make_rule(
            zone_id="zone2",
            name_pattern=None,
            record_types=["*"],
            record_ids=["rec1"],
            allow_write=True,
        )
    ]
    assert is_lock_exempt(rules, "zone1", "rec1", "write") is False


# ---------------------------------------------------------------------------
# merge_patch_image
# ---------------------------------------------------------------------------


def test_merge_patch_image_both_fields_present() -> None:
    """Both name and type come from the body when present."""
    pre = {"name": "old.example.com", "type": "A"}
    body = {"name": "new.example.com", "type": "CNAME"}
    assert merge_patch_image(pre, body) == ("new.example.com", "CNAME")


def test_merge_patch_image_name_absent_unchanged() -> None:
    """An absent name in the body falls back to the pre-image."""
    pre = {"name": "old.example.com", "type": "A"}
    body = {"type": "CNAME"}
    assert merge_patch_image(pre, body) == ("old.example.com", "CNAME")


def test_merge_patch_image_type_absent_unchanged() -> None:
    """An absent type in the body falls back to the pre-image."""
    pre = {"name": "old.example.com", "type": "A"}
    body = {"name": "new.example.com"}
    assert merge_patch_image(pre, body) == ("new.example.com", "A")


def test_merge_patch_image_empty_body_fully_unchanged() -> None:
    """An empty body leaves both name and type unchanged."""
    pre = {"name": "old.example.com", "type": "A"}
    assert merge_patch_image(pre, {}) == ("old.example.com", "A")
