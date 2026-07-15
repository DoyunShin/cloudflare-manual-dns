"""prompt_toolkit-based operational console for cfproxy.

Subcommands: `init-db`, `bootstrap-admin`, `discover-scope`, `tail-audit`,
`health`. Runnable as `python -m cfproxy.cli <command>`.
"""

import argparse
import asyncio
import sys
from collections.abc import Sequence

from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import FormattedText
from sqlalchemy import select

from cfproxy.auth.oauth_cf import discover_dns_scope
from cfproxy.core.security import hash_password
from cfproxy.db.models import AuditLog, User
from cfproxy.db.session import Sessionmaker, init_db
from cfproxy.main import check_database, check_redis


def _emit(message: str, style: str = "") -> None:
    """Print one line of CLI output via prompt_toolkit.

    Applies the given style only when standard output is an interactive
    terminal that can render it; otherwise falls back to plain, unstyled
    text so the message stays readable on terminals (or piped output) that
    do not support escape sequences.

    Args:
        message(str): The text to print.
        style(str, optional): A prompt_toolkit style string.

    Return:
        None
    """
    if style and sys.stdout.isatty():
        print_formatted_text(FormattedText([(style, message)]))
    else:
        print_formatted_text(message)


async def init_db_command() -> None:
    """Create all database tables and record the current schema version.

    Return:
        None
    """
    await init_db()
    _emit("[OK] database initialized", "fg:green bold")


async def bootstrap_admin_command(email: str, password: str) -> None:
    """Create an initial local admin user with a password credential.

    Args:
        email(str): The admin's login email.
        password(str): The admin's plaintext password (hashed before storage).

    Return:
        None
    """
    async with Sessionmaker() as session:
        existing = await session.execute(select(User).where(User.email == email))
        if existing.scalar_one_or_none() is not None:
            _emit(f"[ERROR] a user with email '{email}' already exists", "fg:red bold")
            return
        user = User(email=email, password_hash=hash_password(password), auth_provider="local")
        session.add(user)
        await session.commit()
        await session.refresh(user)
    _emit(f"[OK] created admin user id={user.id} email={email}", "fg:green bold")


async def discover_scope_command() -> None:
    """Print the Cloudflare OAuth DNS scope literals discovered from the upstream API.

    Return:
        None
    """
    scopes = await discover_dns_scope()
    if not scopes:
        _emit("[INFO] no scopes returned", "fg:yellow")
        return
    for scope in scopes:
        _emit(scope)


async def tail_audit_command(limit: int) -> None:
    """Print the most recent audit log entries, oldest of the batch first.

    Args:
        limit(int): Maximum number of entries to print.

    Return:
        None
    """
    async with Sessionmaker() as session:
        result = await session.execute(
            select(AuditLog).order_by(AuditLog.ts.desc()).limit(limit)
        )
        entries = list(result.scalars().all())

    if not entries:
        _emit("[INFO] no audit log entries found", "fg:yellow")
        return

    for entry in reversed(entries):
        _emit(
            f"[{entry.ts.isoformat()}] {entry.decision.upper()} {entry.method} {entry.path} "
            f"zone={entry.zone_id} record={entry.record_id} reason={entry.deny_reason}"
        )


async def health_command() -> None:
    """Check database and Redis connectivity and print the results.

    Return:
        None
    """
    db_ok = await check_database()
    _emit(
        f"[{'OK' if db_ok else 'FAIL'}] database",
        "fg:green bold" if db_ok else "fg:red bold",
    )

    redis_ok = await check_redis()
    _emit(
        f"[{'OK' if redis_ok else 'DEGRADED'}] redis",
        "fg:green bold" if redis_ok else "fg:yellow bold",
    )


def build_console_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the cfproxy operational console.

    Return:
        parser(argparse.ArgumentParser): The configured top-level parser.
    """
    parser = argparse.ArgumentParser(
        prog="python -m cfproxy.cli", description="cfproxy operational console"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init-db", help="Create database tables and record the schema version")

    bootstrap_parser = subparsers.add_parser(
        "bootstrap-admin", help="Create an initial local admin user"
    )
    bootstrap_parser.add_argument("--email", required=True, help="Admin login email")
    bootstrap_parser.add_argument("--password", required=True, help="Admin login password")

    subparsers.add_parser(
        "discover-scope", help="List Cloudflare OAuth DNS scopes available upstream"
    )

    tail_parser = subparsers.add_parser("tail-audit", help="Print the most recent audit log entries")
    tail_parser.add_argument("--limit", type=int, default=20, help="Maximum entries to print")

    subparsers.add_parser("health", help="Check database and redis connectivity")

    return parser


def main(argv: Sequence[str] | None = None) -> None:
    """CLI entrypoint: parse arguments and dispatch to the matching async command.

    Args:
        argv(Sequence[str] | None, optional): Argument list to parse; defaults
            to `sys.argv[1:]` when omitted.

    Return:
        None
    """
    parser = build_console_parser()
    args = parser.parse_args(argv)

    if args.command == "init-db":
        asyncio.run(init_db_command())
    elif args.command == "bootstrap-admin":
        asyncio.run(bootstrap_admin_command(args.email, args.password))
    elif args.command == "discover-scope":
        asyncio.run(discover_scope_command())
    elif args.command == "tail-audit":
        asyncio.run(tail_audit_command(args.limit))
    elif args.command == "health":
        asyncio.run(health_command())


if __name__ == "__main__":
    main()
