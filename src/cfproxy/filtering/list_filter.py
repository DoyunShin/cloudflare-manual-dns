"""Client-facing filtering and re-pagination of Cloudflare DNS-record lists.

The proxy fetches every upstream page of a list request, keeps only the
records the caller's scoped token is authorized to read, then re-paginates
and recomputes `result_info` locally -- so the authorized subset is what the
client actually paginates over, rather than the raw upstream page boundaries
(which would otherwise leak gaps or loops once records are filtered out).
"""

from typing import Any, Iterable

from cfproxy.authz.scope import match_rules


def filter_records(records: list[dict], rules: Iterable[Any], zone_id: str) -> list[dict]:
    """Keep only the records the given rules authorize for reading.

    Args:
        records(list[dict]): Cloudflare DNS record payloads (each with at
            least `id`, `name`, `type`).
        rules(Iterable[Any]): The scoped token's scope rules.
        zone_id(str): The Cloudflare zone id the records belong to.

    Return:
        authorized(list[dict]): The subset of `records` for which
            `match_rules(..., "read")` grants access.
    """
    return [
        record
        for record in records
        if match_rules(
            rules, zone_id, record.get("name"), record.get("type"), record.get("id"), "read"
        )
    ]


def paginate_and_result_info(
    records: list[dict], page: int, per_page: int
) -> tuple[list[dict], dict]:
    """Locally slice a record list and compute Cloudflare-style pagination metadata.

    Args:
        records(list[dict]): The full (already-authorized) record list.
        page(int): 1-indexed page number requested by the client.
        per_page(int): Number of records per page requested by the client.

    Return:
        paginated(tuple[list[dict], dict]): `(page_records, result_info)`
            where `result_info` has keys `page`, `per_page`, `count`,
            `total_count`, `total_pages`.
    """
    total_count = len(records)
    total_pages = -(-total_count // per_page) if per_page > 0 else 0
    start = (page - 1) * per_page
    end = start + per_page
    page_records = records[start:end]
    result_info = {
        "page": page,
        "per_page": per_page,
        "count": len(page_records),
        "total_count": total_count,
        "total_pages": total_pages,
    }
    return page_records, result_info
