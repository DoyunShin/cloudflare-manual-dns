"""Management API router: querying proxy-request audit log entries."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from cfproxy.core.envelopes import make_response
from cfproxy.core.security import get_current_user
from cfproxy.db.models import User
from cfproxy.db.session import get_session
from cfproxy.schemas.management import AuditLogResponse
from cfproxy.services.audit_service import list_audit_logs

router = APIRouter(prefix="/api/v1/audit-logs", tags=["Audit Logs"])


@router.get(
    "",
    responses={
        200: {
            "description": "Audit logs listed",
            "content": {
                "application/json": {
                    "examples": {
                        "success": {
                            "summary": "One allowed request",
                            "value": {
                                "status": 200,
                                "message": "Audit logs listed",
                                "data": {
                                    "items": [
                                        {
                                            "id": "3c4d5e6f-7081-4a5b-8c6d-7e8f9a0b1c2d",
                                            "ts": "2026-07-15T10:05:00+00:00",
                                            "scoped_token_id": "1a2b3c4d-5e6f-4a5b-8c6d-7e8f9a0b1c2d",
                                            "token_prefix": "cfsx_AbCdEf",
                                            "method": "PATCH",
                                            "path": "/client/v4/zones/023e105f4ecef8ad9ca31a8372d0c353"
                                            "/dns_records/rec1",
                                            "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
                                            "record_id": "rec1",
                                            "record_name": "app.staging.example.com",
                                            "record_type": "A",
                                            "decision": "allow",
                                            "deny_reason": None,
                                            "upstream_status": 200,
                                            "client_ip": "203.0.113.7",
                                            "latency_ms": 42,
                                        },
                                    ],
                                    "result_info": {
                                        "page": 1,
                                        "per_page": 50,
                                        "count": 1,
                                        "total_count": 1,
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
    },
)
async def get_audit_logs(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    token_id: Annotated[str | None, Query()] = None,
    zone_id: Annotated[str | None, Query()] = None,
    since: Annotated[datetime | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[int, Query(ge=1, le=200)] = 50,
) -> JSONResponse:
    """List audit log entries owned by the authenticated user, most recent first.

    Args:
        current_user(User): The authenticated owning user.
        session(AsyncSession): Database session.
        token_id(str, optional): Filter to a single scoped token id.
        zone_id(str, optional): Filter to a single Cloudflare zone id.
        since(datetime, optional): Only include entries at or after this timestamp.
        page(int, optional): 1-indexed page number.
        per_page(int, optional): Number of entries per page.

    Return:
        response(JSONResponse): The standard envelope wrapping `{"items", "result_info"}`.
    """
    entries, result_info = await list_audit_logs(
        session,
        current_user.id,
        token_id=token_id,
        zone_id=zone_id,
        since=since,
        page=page,
        per_page=per_page,
    )
    items = [AuditLogResponse.model_validate(entry).model_dump(mode="json") for entry in entries]
    return make_response(200, "Audit logs listed", {"items": items, "result_info": result_info})
