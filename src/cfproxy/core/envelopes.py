"""Response envelope builders for the management and proxy APIs."""

from typing import Any

from fastapi.responses import JSONResponse


def make_response(status: int, message: str, data: Any = None) -> JSONResponse:
    """Build the standard management API response envelope.

    Args:
        status(int): HTTP status code.
        message(str): Human-readable message.
        data(Any, optional): Response payload.

    Return:
        response(JSONResponse): FastAPI response with the {status, message, data} envelope.
    """
    return JSONResponse(
        status_code=status,
        content={"status": status, "message": message, "data": data},
    )


def make_cf_response(
    result: Any,
    *,
    status: int = 200,
    messages: list[dict] | None = None,
    result_info: dict | None = None,
) -> JSONResponse:
    """Build a Cloudflare-compatible success response envelope.

    Args:
        result(Any): The result payload to return.
        status(int, optional): HTTP status code.
        messages(list[dict], optional): Cloudflare-style message list.
        result_info(dict, optional): Pagination metadata; included only when provided.

    Return:
        response(JSONResponse): FastAPI response matching the Cloudflare API envelope.
    """
    content: dict[str, Any] = {
        "success": True,
        "errors": [],
        "messages": messages or [],
        "result": result,
    }
    if result_info is not None:
        content["result_info"] = result_info
    return JSONResponse(status_code=status, content=content)


def make_cf_error(status: int, code: int, message: str) -> JSONResponse:
    """Build a Cloudflare-compatible error response envelope.

    Args:
        status(int): HTTP status code.
        code(int): Cloudflare error code.
        message(str): Human-readable error message.

    Return:
        response(JSONResponse): FastAPI response matching the Cloudflare error envelope.
    """
    return JSONResponse(
        status_code=status,
        content={
            "success": False,
            "errors": [{"code": code, "message": message}],
            "messages": [],
            "result": None,
        },
    )
