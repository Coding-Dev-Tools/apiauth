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
@click.pass_context
def list(ctx: click.Context, service: str | None, json_output: bool) -> None:
    """List stored keys and JWTs."""
    ks: Keystore = ctx.obj["keystore"]
    keys = ks.list_keys(service)

    if not keys:
        console.print("[yellow]No keys found.[/yellow]")
        return

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
    table.add_column("Revoked")

    for k in keys:
        table.add_row(
            k["id"],
            k.get("type", "?"),
            k.get("name", ""),
            k.get("service", ""),
            _short_ts(k.get("created_at", "")),
            _short_ts(k.get("expires_at", "")) if k.get("expires_at") else "-",
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

    console.print(json.dumps({"id": key_id, **entry}, indent=2, default=str))


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


# ── export ────────────────────────────────────────────────────────────


@cli.command()
@click.option("--format", "-f", "fmt", type=click.Choice(["env", "json"]), default="env")
@click.option("--service", "-s", default=None, help="Filter by service")
@click.pass_context
def export(ctx: click.Context, fmt: str, service: str | None) -> None:
    """Export keys as environment variables or JSON."""
    ks: Keystore = ctx.obj["keystore"]
    keys = ks.list_keys(service)

    # Only include non-revoked keys
    active = [k for k in keys if not k.get("revoked")]

    if fmt == "json":
        console.print(json.dumps(active, indent=2, default=str))
    else:
        for k in active:
            kid = k["id"].replace("-", "_")
            name = k.get("name", "").upper().replace(" ", "_").replace("-", "_")
            prefix = f"APIAUTH_{name}" if name else "APIAUTH"
            entry = ks.get(k["id"])
            if entry and entry.get("type") == "jwt":
                # For JWTs we can't export the token itself since we only store metadata
                console.print(f"# {k['id']} ({k.get('name', '')}) — JWT (token not stored)")
            else:
                console.print(f"# {k['id']} ({k.get('name', '')})")
                console.print(f"{prefix}_ID={k['id']}")
                console.print(f"{prefix}_SERVICE={k.get('service', '')}")
                console.print(f"{prefix}_CREATED={k.get('created_at', '')}")
                if k.get("expires_at"):
                    console.print(f"{prefix}_EXPIRES={k['expires_at']}")
                console.print()


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
