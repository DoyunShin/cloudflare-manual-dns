"""Smoke tests for the cfproxy foundation contract layer."""

import json

from sqlalchemy import select

import cfproxy
from cfproxy.core.crypto import (
    decrypt_secret,
    encrypt_secret,
    generate_scoped_token,
    hash_token,
    parse_scoped_token,
    verify_token,
)
from cfproxy.core.envelopes import make_cf_error, make_cf_response, make_response
from cfproxy.db.models import User


def test_import_cfproxy() -> None:
    """The top-level package imports cleanly."""
    assert cfproxy is not None


def test_encrypt_decrypt_secret_roundtrip() -> None:
    """A plaintext secret survives an encrypt/decrypt roundtrip unchanged."""
    plaintext = "cf-super-secret-token-value"
    ciphertext = encrypt_secret(plaintext)
    assert ciphertext != plaintext
    assert decrypt_secret(ciphertext) == plaintext


def test_generate_parse_verify_scoped_token() -> None:
    """Scoped token generation, parsing, and hash verification are consistent."""
    token = generate_scoped_token()

    assert set(token.keys()) == {"lookup_id", "secret", "full", "token_hash", "token_prefix"}
    assert len(token["lookup_id"]) == 16
    assert len(token["secret"]) == 40
    assert token["full"] == f"cfsx_{token['lookup_id']}_{token['secret']}"
    assert token["token_hash"] == hash_token(token["full"])
    assert token["token_prefix"] == f"cfsx_{token['lookup_id'][:6]}"

    parsed = parse_scoped_token(token["full"])
    assert parsed == (token["lookup_id"], token["secret"])

    assert verify_token(token["full"], token["token_hash"]) is True
    assert verify_token("garbage_value_here", token["token_hash"]) is False


def test_parse_scoped_token_rejects_malformed() -> None:
    """Malformed token strings are rejected instead of raising."""
    assert parse_scoped_token("not-a-valid-token") is None
    assert parse_scoped_token("cfsx_onlyonepart") is None
    assert parse_scoped_token("cfsx_" + "a" * 16 + "_" + "b" * 39) is None


def test_make_response_shape() -> None:
    """make_response builds the {status, message, data} management envelope."""
    response = make_response(200, "OK", {"id": "abc"})
    body = json.loads(response.body)
    assert response.status_code == 200
    assert body == {"status": 200, "message": "OK", "data": {"id": "abc"}}


def test_make_cf_response_shape() -> None:
    """make_cf_response builds the Cloudflare success envelope, with optional result_info."""
    response = make_cf_response({"id": "rec1"}, status=200)
    body = json.loads(response.body)
    assert response.status_code == 200
    assert body == {"success": True, "errors": [], "messages": [], "result": {"id": "rec1"}}
    assert "result_info" not in body

    paginated = make_cf_response(
        [{"id": "rec1"}],
        result_info={"page": 1, "per_page": 20, "count": 1, "total_count": 1, "total_pages": 1},
    )
    paginated_body = json.loads(paginated.body)
    assert paginated_body["result_info"] == {
        "page": 1,
        "per_page": 20,
        "count": 1,
        "total_count": 1,
        "total_pages": 1,
    }


def test_make_cf_error_shape() -> None:
    """make_cf_error builds the Cloudflare error envelope."""
    response = make_cf_error(404, 81044, "Record not found")
    body = json.loads(response.body)
    assert response.status_code == 404
    assert body == {
        "success": False,
        "errors": [{"code": 81044, "message": "Record not found"}],
        "messages": [],
        "result": None,
    }


async def test_create_and_query_user(db_session) -> None:
    """A User row can be created and queried back through the async session."""
    user = User(email="smoke@example.com", auth_provider="local", is_active=True)
    db_session.add(user)
    await db_session.commit()

    result = await db_session.execute(select(User).where(User.email == "smoke@example.com"))
    fetched = result.scalar_one()

    assert fetched.id == user.id
    assert fetched.email == "smoke@example.com"
    assert fetched.is_active is True
