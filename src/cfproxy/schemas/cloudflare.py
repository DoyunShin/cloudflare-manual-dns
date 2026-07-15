"""Pydantic models mirroring Cloudflare API shapes.

These describe the shape of data exchanged with the real Cloudflare API and
returned verbatim (or filtered/repaginated) through the `/client/v4` proxy
surface. Fields are permissive (`extra="allow"`) since Cloudflare's payloads
carry more fields than the proxy needs to reason about.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict


class CloudflareDNSRecord(BaseModel):
    """A Cloudflare DNS record as returned by the `/zones/{id}/dns_records` API.

    Args:
        id(str): Cloudflare record id.
        zone_id(str): Cloudflare zone id the record belongs to.
        zone_name(str, optional): Name of the zone the record belongs to.
        type(str): DNS record type (e.g. "A", "CNAME", "TXT").
        name(str): Fully-qualified DNS record name.
        content(str): DNS record content/value.
        ttl(int, optional): Time-to-live in seconds.
        proxied(bool, optional): Whether the record is proxied through Cloudflare.
        created_on(str, optional): ISO-8601 creation timestamp.
        modified_on(str, optional): ISO-8601 last-modified timestamp.
    """

    model_config = ConfigDict(extra="allow")

    id: str
    zone_id: str
    zone_name: str | None = None
    type: str
    name: str
    content: str
    ttl: int | None = None
    proxied: bool | None = None
    created_on: str | None = None
    modified_on: str | None = None


class CloudflareResultInfo(BaseModel):
    """Cloudflare-style pagination metadata attached to list responses.

    Args:
        page(int): Current page number (1-indexed).
        per_page(int): Number of results per page.
        count(int): Number of results in this page.
        total_count(int): Total number of results across all pages.
        total_pages(int): Total number of pages.
    """

    page: int
    per_page: int
    count: int
    total_count: int
    total_pages: int


class CloudflareMessage(BaseModel):
    """A single Cloudflare-style informational message.

    Args:
        code(int): Cloudflare message code.
        message(str): Human-readable message text.
    """

    model_config = ConfigDict(extra="allow")

    code: int
    message: str


class CloudflareError(BaseModel):
    """A single Cloudflare-style error entry.

    Args:
        code(int): Cloudflare error code.
        message(str): Human-readable error message.
    """

    model_config = ConfigDict(extra="allow")

    code: int
    message: str


class CloudflareEnvelope(BaseModel):
    """The generic Cloudflare API response envelope shape.

    Args:
        success(bool): Whether the request succeeded.
        errors(list[CloudflareError]): Error entries, empty on success.
        messages(list[CloudflareMessage]): Informational messages.
        result(Any): The result payload, or None on error.
        result_info(CloudflareResultInfo, optional): Pagination metadata.
    """

    model_config = ConfigDict(extra="allow")

    success: bool
    errors: list[CloudflareError] = []
    messages: list[CloudflareMessage] = []
    result: Any = None
    result_info: CloudflareResultInfo | None = None
