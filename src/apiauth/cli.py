"""APIAuth CLI — API key and JWT lifecycle management."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .keystore import Keystore
from .keygen import create_api_key_entry, create_jwt_entry, rotate_key, rotate_jwt
from .verify import verify_api_key, check_expiry

console = Console()
err_console = Console(stderr=True)


@click.group()
@click.option("--key-dir", "-d", default=None, help="Custom keystore directory")
@click.version_option(__version__, prog_name="apiauth")
@click.pass_context
def cli(ctx: click.Context, key_dir: str | None) -> None:
    """APIAuth — API key and JWT lifecycle management.

    Generate, rotate, and manage API keys and JWTs with an
    AES-256-GCM encrypted local keystore.
    """
    ctx.ensure_object(dict)
    ctx.obj["keystore"] = Keystore(key_dir)


# ── generate ──────────────────────────────────────────────────────────


@cli.group()
def generate() -> None:
    """Generate a new API key or JWT."""


@generate.command("api-key")
@click.option("--name", "-n", required=True, help="A name for this key")
@click.option("--service", "-s", required=True, help="Associated service name")
@click.option("--expiry-days", "-e", type=int, default=None, help="Expiry in days")
@click.option("--rate-limit", "-r", type=int, default=None, help="Rate limit (req/s)")
@click.option("--prefix", "-p", default="ak", help="Key prefix (default: ak)")
@click.pass_context
def generate_api_key_cmd(
    ctx: click.Context,
    name: str,
    service: str,
    expiry_days: int | None,
    rate_limit: int | None,
    prefix: str,
) -> None:
    """Generate a new API key."""
    ks: Keystore = ctx.obj["keystore"]
    result = create_api_key_entry(ks, name, service, expiry_days, rate_limit, prefix)
    console.print(f"[green]✓[/green] API key [bold]{result['id']}[/bold] created")
    console.print(f"  Key: [bold yellow]{result['api_key']}[/bold yellow]")
    console.print(f"  Name: {result['name']}")
    console.print(f"  Service: {result['service']}")
    if result.get("expires_at"):
        console.print(f"  Expires: {result['expires_at']}")
    if result.get("rate_limit"):
        console.print(f"  Rate limit: {result['rate_limit']} req/s")
    console.print(f"  [dim]Save this key — it won't be shown again.[/dim]")


@generate.command("jwt")
@click.option("--name", "-n", required=True, help="A name for this JWT")
@click.option("--service", "-s", required=True, help="Associated service name")
@click.option("--expiry-days", "-e", type=int, default=30, help="Expiry in days")
@click.option("--claim", "-c", multiple=True, help="Custom claim key=value (repeatable)")
@click.pass_context
def generate_jwt_cmd(
    ctx: click.Context,
    name: str,
    service: str,
    expiry_days: int,
    claim: tuple[str, ...],
) -> None:
    """Generate a new JWT."""
    ks: Keystore = ctx.obj["keystore"]
    claims: dict[str, Any] = {}
    for c in claim:
        if "=" in c:
            k, v = c.split("=", 1)
            claims[k] = v
        else:
            claims[c] = True

    result = create_jwt_entry(ks, name, service, expiry_days, claims or None)
    console.print(f"[green]✓[/green] JWT [bold]{result['id']}[/bold] created")
    console.print(f"  Token: [bold yellow]{result['token']}[/bold yellow]")
    console.print(f"  Name: {result['name']}")
    console.print(f"  Service: {result['service']}")
    if result.get("expires_at"):
        console.print(f"  Expires: {result['expires_at']}")
    console.print(f"  [dim]Save this token — it won't be shown again.[/dim]")


# ── list ──────────────────────────────────────────────────────────────


@cli.command()
@click.option("--service", "-s", default=None, help="Filter by service")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
@click.option("--show-expired", is_flag=True, help="Include expired keys")
@click.pass_context
def list(ctx: click.Context, service: str | None, json_output: bool, show_expired: bool) -> None:
    """List stored keys and JWTs."""
    ks: Keystore = ctx.obj["keystore"]
    keys = ks.list_keys(service)

    if not keys:
        console.print("[yellow]No keys found.[/yellow]")
        return

    # Add expiry status to each key
    for k in keys:
        entry = ks.get(k["id"])
        if entry:
            k["expiry_status"] = check_expiry(entry)

    if not show_expired:
        keys = [k for k in keys if k.get("expiry_status") != "expired"]

    if json_output:
        console.print(json.dumps(keys, indent=2, default=str))
        return

    table = Table(title=f"Keys{' for service: ' + service if service else ''}")
    table.add_column("ID", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Name", style="green")
    table.add_column("Service")
    table.add_column("Created")
    table.add_column("Expires")
    table.add_column("Status")
    table.add_column("Revoked")

    for k in keys:
        exp_status = k.get("expiry_status")
        if exp_status == "expired":
            status_str = "[red]EXPIRED[/red]"
        elif exp_status == "expiring":
            status_str = "[yellow]EXPIRING[/yellow]"
        else:
            status_str = ""

        table.add_row(
            k["id"],
            k.get("type", "?"),
            k.get("name", ""),
            k.get("service", ""),
            _short_ts(k.get("created_at", "")),
            _short_ts(k.get("expires_at", "")) if k.get("expires_at") else "-",
            status_str,
            "✓" if k.get("revoked") else "",
        )

    console.print(table)


# ── show ──────────────────────────────────────────────────────────────


@cli.command()
@click.argument("key_id")
@click.pass_context
def show(ctx: click.Context, key_id: str) -> None:
    """Show details for a specific key or JWT."""
    ks: Keystore = ctx.obj["keystore"]
    entry = ks.get(key_id)
    if not entry:
        err_console.print(f"[red]Key '{key_id}' not found.[/red]")
        sys.exit(1)

    # Add expiry status
    exp_status = check_expiry(entry)
    output = {"id": key_id, **entry}
    if exp_status:
        output["expiry_status"] = exp_status

    console.print(json.dumps(output, indent=2, default=str))


# ── rotate ────────────────────────────────────────────────────────────


@cli.command()
@click.argument("key_id")
@click.option("--expiry-days", "-e", type=int, default=None, help="New expiry in days")
@click.pass_context
def rotate(ctx: click.Context, key_id: str, expiry_days: int | None) -> None:
    """Rotate an existing API key or JWT."""
    ks: Keystore = ctx.obj["keystore"]
    entry = ks.get(key_id)
    if not entry:
        err_console.print(f"[red]Key '{key_id}' not found.[/red]")
        sys.exit(1)

    key_type = entry.get("type", "api_key")

    if key_type == "jwt":
        result = rotate_jwt(ks, key_id, expiry_days or 30)
    else:
        result = rotate_key(ks, key_id, expiry_days)

    if not result:
        err_console.print(f"[red]Failed to rotate '{key_id}'.[/red]")
        sys.exit(1)

    console.print(f"[green]✓[/green] Rotated [bold]{key_id}[/bold] (v{result.get('version', '?')})")
    if key_type == "jwt":
        console.print(f"  New token: [bold yellow]{result['token']}[/bold yellow]")
    else:
        console.print(f"  New key: [bold yellow]{result['api_key']}[/bold yellow]")
    console.print(f"  [dim]Previous value has been hashed out. Save the new value.[/dim]")


# ── revoke ────────────────────────────────────────────────────────────


@cli.command()
@click.argument("key_id")
@click.pass_context
def revoke(ctx: click.Context, key_id: str) -> None:
    """Revoke an API key or JWT."""
    ks: Keystore = ctx.obj["keystore"]
    entry = ks.get(key_id)
    if not entry:
        err_console.print(f"[red]Key '{key_id}' not found.[/red]")
        sys.exit(1)

    entry["revoked"] = True
    ks.put(key_id, entry)
    console.print(f"[red]✗[/red] Revoked [bold]{key_id}[/bold]")


# ── verify ────────────────────────────────────────────────────────────


@cli.command()
@click.argument("api_key")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
@click.pass_context
def verify(ctx: click.Context, api_key: str, json_output: bool) -> None:
    """Verify an API key against the keystore.

    Checks if the key exists, is not revoked, and is not expired.
    """
    ks: Keystore = ctx.obj["keystore"]
    result = verify_api_key(ks, api_key)

    if json_output:
        console.print(json.dumps(result, indent=2, default=str))
        return

    if result["valid"]:
        console.print(f"[green]✓[/green] Key [bold]{result['key_id']}[/bold] is [green]VALID[/green]")
        console.print(f"  Name: {result.get('name', '')}")
        console.print(f"  Service: {result.get('service', '')}")
        console.print(f"  Version: {result.get('version', '?')}")
        if result.get("rate_limit"):
            console.print(f"  Rate limit: {result['rate_limit']} req/s")
    else:
        console.print(f"[red]✗[/red] Key is [red]INVALID[/red]")
        if result.get("key_id"):
            reasons = []
            if result.get("revoked"):
                reasons.append("revoked")
            if result.get("expired"):
                reasons.append("expired")
            console.print(f"  Key ID: {result['key_id']}")
            console.print(f"  Reason: {', '.join(reasons) if reasons else 'key hash mismatch'}")
        else:
            console.print("  Key not found in keystore")


# ── import ────────────────────────────────────────────────────────────


@cli.command("import")
@click.argument("api_key")
@click.option("--name", "-n", required=True, help="A name for this key")
@click.option("--service", "-s", required=True, help="Associated service name")
@click.option("--expiry-days", "-e", type=int, default=None, help="Expiry in days")
@click.option("--rate-limit", "-r", type=int, default=None, help="Rate limit (req/s)")
@click.pass_context
def import_key(
    ctx: click.Context,
    api_key: str,
    name: str,
    service: str,
    expiry_days: int | None,
    rate_limit: int | None,
) -> None:
    """Import an existing API key into the keystore.

    The key value is hashed for storage; the plaintext is not retained.
    Use 'verify' to check if an incoming key matches a stored entry.
    """
    import datetime as dt
    import hashlib

    ks: Keystore = ctx.obj["keystore"]
    from .keygen import _generate_key_id, _timestamp

    key_id = _generate_key_id()
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    prefix = api_key[:20] if len(api_key) >= 20 else api_key

    now = _timestamp()
    expiry = None
    if expiry_days:
        expiry = (
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=expiry_days)
        ).isoformat()[:23] + "Z"

    entry = {
        "type": "api_key",
        "name": name,
        "service": service,
        "key_hash": key_hash,
        "prefix": prefix,
        "created_at": now,
        "imported_at": now,
        "last_used": None,
        "expires_at": expiry,
        "rate_limit": rate_limit,
        "revoked": False,
        "version": 1,
    }

    ks.put(key_id, entry)
    console.print(f"[green]✓[/green] Imported key [bold]{key_id}[/bold]")
    console.print(f"  Name: {name}")
    console.print(f"  Service: {service}")
    console.print(f"  [dim]Key has been hashed. Use 'verify' to check keys.[/dim]")


# ── export ────────────────────────────────────────────────────────────


@cli.command()
@click.option("--format", "-f", "fmt", type=click.Choice(["env", "json", "dotenv", "github-actions"]), default="env")
@click.option("--service", "-s", default=None, help="Filter by service")
@click.pass_context
def export(ctx: click.Context, fmt: str, service: str | None) -> None:
    """Export keys as environment variables or JSON.

    Formats:
      env            — KEY=value shell exports (default)
      dotenv         — .env file format (no export prefix)
      json           — JSON array
      github-actions — GitHub Actions set-output format
    """
    ks: Keystore = ctx.obj["keystore"]
    keys = ks.list_keys(service)

    # Only include non-revoked, non-expired keys
    active = []
    for k in keys:
        if k.get("revoked"):
            continue
        entry = ks.get(k["id"])
        if entry and check_expiry(entry) == "expired":
            continue
        active.append(k)

    if fmt == "json":
        console.print(json.dumps(active, indent=2, default=str))
    elif fmt == "dotenv":
        _export_dotenv(active)
    elif fmt == "github-actions":
        _export_github_actions(active)
    else:
        _export_env(active)


def _make_env_prefix(k: dict) -> str:
    kid = k["id"].replace("-", "_")
    name = k.get("name", "").upper().replace(" ", "_").replace("-", "_")
    return f"APIAUTH_{name}" if name else f"APIAUTH_{kid}"


def _export_env(active: list[dict]) -> None:
    for k in active:
        prefix = _make_env_prefix(k)
        console.print(f"export {prefix}_ID={k['id']}")
        console.print(f"export {prefix}_SERVICE={k.get('service', '')}")
        console.print(f"export {prefix}_CREATED={k.get('created_at', '')}")
        if k.get("expires_at"):
            console.print(f"export {prefix}_EXPIRES={k['expires_at']}")
        console.print()


def _export_dotenv(active: list[dict]) -> None:
    for k in active:
        prefix = _make_env_prefix(k)
        console.print(f"{prefix}_ID={k['id']}")
        console.print(f"{prefix}_SERVICE={k.get('service', '')}")
        console.print(f"{prefix}_CREATED={k.get('created_at', '')}")
        if k.get("expires_at"):
            console.print(f"{prefix}_EXPIRES={k['expires_at']}")
        console.print()


def _export_github_actions(active: list[dict]) -> None:
    console.print("# GitHub Actions: Add these as repository secrets or use with actions/env")
    for k in active:
        prefix = _make_env_prefix(k)
        console.print(f"echo \"{prefix}_ID={k['id']}\" >> $GITHUB_ENV")
        console.print(f"echo \"{prefix}_SERVICE={k.get('service', '')}\" >> $GITHUB_ENV")
        console.print(f"echo \"{prefix}_CREATED={k.get('created_at', '')}\" >> $GITHUB_ENV")
        if k.get("expires_at"):
            console.print(f"echo \"{prefix}_EXPIRES={k['expires_at']}\" >> $GITHUB_ENV")
    console.print()
    console.print("# Or add to .github/workflows/*.yml env: block:")
    console.print("env:")
    for k in active:
        prefix = _make_env_prefix(k)
        console.print(f"  {prefix}_ID: \"{k['id']}\"")
        console.print(f"  {prefix}_SERVICE: \"{k.get('service', '')}\"")


# ── audit ─────────────────────────────────────────────────────────────


@cli.command()
@click.pass_context
def audit(ctx: click.Context) -> None:
    """Audit keystore: find expired, expiring, and revoked keys."""
    ks: Keystore = ctx.obj["keystore"]
    keys = ks.list_keys()

    expired = []
    expiring = []
    revoked = []
    healthy = []

    for k in keys:
        entry = ks.get(k["id"])
        if not entry:
            continue
        if k.get("revoked"):
            revoked.append(k)
            continue
        exp_status = check_expiry(entry)
        if exp_status == "expired":
            expired.append(k)
        elif exp_status == "expiring":
            expiring.append(k)
        else:
            healthy.append(k)

    if not expired and not expiring and not revoked:
        console.print(f"[green]✓[/green] All {len(healthy)} keys are healthy")
        return

    if expired:
        console.print(f"[red]✗ {len(expired)} EXPIRED key(s):[/red]")
        for k in expired:
            console.print(f"  [red]{k['id']}[/red] {k.get('name', '')} — expired {_short_ts(k.get('expires_at', ''))}")
        console.print()

    if expiring:
        console.print(f"[yellow]⚠ {len(expiring)} EXPIRING key(s) (within 7 days):[/yellow]")
        for k in expiring:
            console.print(f"  [yellow]{k['id']}[/yellow] {k.get('name', '')} — expires {_short_ts(k.get('expires_at', ''))}")
        console.print()

    if revoked:
        console.print(f"[dim]⊘ {len(revoked)} REVOKED key(s):[/dim]")
        for k in revoked:
            console.print(f"  [dim]{k['id']} {k.get('name', '')}[/dim]")
        console.print()

    console.print(f"[green]✓ {len(healthy)} key(s) healthy[/green]")


# ── stats ─────────────────────────────────────────────────────────────


@cli.command()
@click.pass_context
def stats(ctx: click.Context) -> None:
    """Show keystore statistics."""
    ks: Keystore = ctx.obj["keystore"]
    stats_data = ks.get_stats()
    console.print(f"Total keys: [bold]{stats_data['total_keys']}[/bold]")
    console.print("By service:")
    for svc, count in stats_data["by_service"].items():
        console.print(f"  {svc}: {count}")
    console.print(f"Store: {stats_data['store_path']}")
    console.print(f"Master key: {stats_data['key_path']}")


# ── helpers ───────────────────────────────────────────────────────────


def _short_ts(ts: str) -> str:
    """Shorten an ISO timestamp to date."""
    if not ts:
        return ""
    return ts[:10] if "T" in ts else ts[:16]


if __name__ == "__main__":
    cli()
