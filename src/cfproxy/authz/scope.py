"""Pure DNS-record scope matching logic (no I/O).

Implements FQDN normalization, DNS-label-aware wildcard matching, and the
shared authorization predicate used by the proxy layer to decide whether a
scoped token's rules grant a given DNS-record operation.

`rules` parameters accept any iterable of objects exposing the same
attributes as `cfproxy.db.models.ScopeRule` (`zone_id`, `name_pattern`,
`name_match`, `record_types`, `record_ids`, `allow_read`, `allow_create`,
`allow_write`, `allow_delete`) -- a `ScopeRule` instance or a
`types.SimpleNamespace` with matching attributes both work.
"""

from typing import Any, Iterable, Literal

Need = Literal["read", "create", "write", "delete"]


def normalize_fqdn(name: str) -> str:
    """Canonicalize a DNS name for comparison.

    Lowercases the name, strips a trailing dot, and IDNA (punycode)
    encodes it so unicode and ASCII forms of the same name compare equal.

    Args:
        name(str): Raw DNS name (FQDN, possibly with a wildcard label).

    Return:
        canonical(str): Lowercased, dot-stripped, IDNA-encoded name.
    """
    stripped = name.strip().rstrip(".").lower()
    if not stripped:
        return stripped
    return stripped.encode("idna").decode("ascii")


def validate_name_pattern(pattern: str, name_match: str, zone_name: str) -> None:
    """Validate a `ScopeRule.name_pattern` at rule-creation time.

    `exact` patterns must be the zone apex (written as the zone name or
    `@`) or any FQDN ending in the zone. `wildcard` patterns must contain
    exactly one `*` occupying an entire leftmost-or-deeper label, with the
    remaining (non-wildcard) labels ending in the zone.

    Args:
        pattern(str): The name pattern to validate.
        name_match(str): Either "exact" or "wildcard".
        zone_name(str): The FQDN of the zone the rule belongs to.

    Return:
        None: Returns nothing; raises on an invalid pattern.
    """
    if name_match not in ("exact", "wildcard"):
        raise ValueError(f"unknown name_match: {name_match!r}")

    zone = normalize_fqdn(zone_name)

    if name_match == "exact":
        if "*" in pattern:
            raise ValueError("exact name_pattern must not contain '*'")
        candidate = zone if pattern == "@" else normalize_fqdn(pattern)
        if candidate != zone and not candidate.endswith("." + zone):
            raise ValueError(
                f"name_pattern {pattern!r} does not end in zone {zone_name!r}"
            )
        return

    # name_match == "wildcard"
    if pattern.count("*") != 1:
        raise ValueError("wildcard name_pattern must contain exactly one '*'")

    labels = pattern.split(".")
    star_index = next(i for i, label in enumerate(labels) if "*" in label)
    if labels[star_index] != "*":
        raise ValueError(
            f"'*' must occupy a whole label, got {labels[star_index]!r}"
        )

    remainder_labels = labels[:star_index] + labels[star_index + 1 :]
    remainder = ".".join(remainder_labels)
    remainder_norm = normalize_fqdn(remainder) if remainder else ""
    if remainder_norm != zone and not remainder_norm.endswith("." + zone):
        raise ValueError(
            f"wildcard name_pattern {pattern!r} does not end in zone {zone_name!r}"
        )


def name_matches(pattern: str, name_match: str, target: str) -> bool:
    """Check whether a target DNS name matches a rule's name pattern.

    Both `pattern` and `target` are canonicalized via `normalize_fqdn`
    before comparison. `exact` requires full-string equality. `wildcard`
    requires the `*` to match exactly one whole label -- it never crosses
    a `.` boundary, so it cannot match the zone apex (one label short) or
    names with extra labels (one label too many).

    Args:
        pattern(str): The rule's `name_pattern`.
        name_match(str): Either "exact" or "wildcard".
        target(str): The DNS name being checked.

    Return:
        matches(bool): True if `target` satisfies `pattern` under
            `name_match` semantics.
    """
    canonical_pattern = normalize_fqdn(pattern)
    canonical_target = normalize_fqdn(target)

    if name_match == "exact":
        return canonical_pattern == canonical_target

    if name_match == "wildcard":
        pattern_labels = canonical_pattern.split(".")
        target_labels = canonical_target.split(".")
        star_index = next(
            (i for i, label in enumerate(pattern_labels) if label == "*"), None
        )
        if star_index is None:
            return False
        if len(pattern_labels) != len(target_labels):
            return False
        for i, (pattern_label, target_label) in enumerate(
            zip(pattern_labels, target_labels)
        ):
            if i == star_index:
                continue
            if pattern_label != target_label:
                return False
        return True

    return False


def match_rules(
    rules: Iterable[Any],
    zone_id: str,
    name: str | None,
    rtype: str,
    record_id: str | None,
    need: Need,
) -> bool:
    """Decide whether a set of scope rules grants a DNS-record operation.

    Args:
        rules(Iterable[Any]): The token's scope rules (`ScopeRule`-like
            objects: `zone_id`, `name_pattern`, `name_match`,
            `record_types`, `record_ids`, `allow_read`, `allow_create`,
            `allow_write`, `allow_delete`).
        zone_id(str): The Cloudflare zone id of the target record.
        name(str | None): The record's DNS name (None only permitted when
            no name is applicable, e.g. an id-less create is never
            called with name=None -- callers pass the record's name).
        rtype(str): The record's DNS type (e.g. "A", "TXT").
        record_id(str | None): The Cloudflare record id, or None for a
            create request that has not yet been assigned one.
        need(str): One of "read", "create", "write", "delete".

    Return:
        allowed(bool): True if any rule grants `need` for this record.
    """
    normalized_name = normalize_fqdn(name) if name else None

    for rule in rules:
        if rule.zone_id != zone_id:
            continue
        if not ("*" in rule.record_types or rtype in rule.record_types):
            continue
        if rule.record_ids:
            if record_id is None or record_id not in rule.record_ids:
                continue
        if rule.name_pattern is not None:
            if normalized_name is None or not name_matches(
                rule.name_pattern, rule.name_match, normalized_name
            ):
                continue

        if need == "read" and rule.allow_read:
            return True
        if need == "create" and rule.allow_create:
            return True
        if need == "write" and rule.allow_write:
            return True
        if need == "delete" and rule.allow_delete:
            return True

    return False


def is_lock_exempt(
    rules: Iterable[Any], zone_id: str, path_record_id: str, op: Need
) -> bool:
    """Decide whether a by-id mutation is exempt from the mutation lock.

    A mutation is exempt only when some rule granting `op` pins this exact
    `path_record_id`, allows any record type (`record_types == ["*"]`),
    and has no `name_pattern` -- such a rule is escape-proof (the id is
    stable and type/name are unconstrained), so the record can be mutated
    without first acquiring the per-record advisory lock.

    Args:
        rules(Iterable[Any]): The token's scope rules.
        zone_id(str): The Cloudflare zone id of the target record.
        path_record_id(str): The record id from the request path.
        op(str): One of "read", "create", "write", "delete".

    Return:
        exempt(bool): True if the mutation may proceed without a lock.
    """
    for rule in rules:
        if rule.zone_id != zone_id:
            continue
        if rule.name_pattern is not None:
            continue
        if rule.record_types != ["*"]:
            continue
        if not rule.record_ids or path_record_id not in rule.record_ids:
            continue

        if op == "read" and rule.allow_read:
            return True
        if op == "create" and rule.allow_create:
            return True
        if op == "write" and rule.allow_write:
            return True
        if op == "delete" and rule.allow_delete:
            return True

    return False


def merge_patch_image(pre: dict, body: dict) -> tuple[str, str]:
    """Compute the post-mutation (name, type) for a PATCH/PUT request.

    Fields absent from `body` are treated as unchanged (kept from `pre`).

    Args:
        pre(dict): The pre-mutation Cloudflare record image.
        body(dict): The client's request body.

    Return:
        post(tuple[str, str]): `(post_name, post_type)` reflecting the
            record's name/type after the mutation is applied.
    """
    post_name = body.get("name", pre.get("name"))
    post_type = body.get("type", pre.get("type"))
    return post_name, post_type
