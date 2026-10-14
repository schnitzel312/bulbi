"""Click CLI entry point for Bulbi."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from bulbi.constants import SPEC_FILENAME
from bulbi.spec import BulbiSpec, load_spec, SpecError

console = Console()


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(package_name="bulbi")
def main() -> None:
    """Bulbi -- run coding agents in isolated, spec-defined sandbox environments."""


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

@main.command()
@click.option("--force", is_flag=True, help="Overwrite an existing bulbi.toml.")
def init(force: bool) -> None:
    """Generate a starter bulbi.toml for this project."""
    from bulbi.init import generate_starter_spec

    project_root = Path.cwd()
    spec_path = project_root / SPEC_FILENAME

    if spec_path.exists() and not force:
        raise click.ClickException(
            f"{SPEC_FILENAME} already exists. Use --force to overwrite."
        )

    content = generate_starter_spec(project_root)
    spec_path.write_text(content)
    console.print(f"[green]Wrote {SPEC_FILENAME}[/green]")


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

@main.command()
def check() -> None:
    """Validate the spec and show what the box can/cannot do."""
    project_root = Path.cwd()

    try:
        spec = load_spec(project_root)
    except SpecError as exc:
        raise click.ClickException(str(exc))

    console.print(f"\n[bold]Box:[/bold] {spec.box.name}  (agent: {spec.box.agent})\n")

    # Tools ----------------------------------------------------------------
    tools_table = Table(title="Tools")
    tools_table.add_column("Tool", style="cyan")
    for tool in spec.tools.allow:
        tools_table.add_row(tool)
    if not spec.tools.allow:
        tools_table.add_row("[dim]none[/dim]")
    console.print(tools_table)

    # Mounts ---------------------------------------------------------------
    mounts_table = Table(title="Mounts")
    mounts_table.add_column("Path", style="cyan")
    mounts_table.add_column("Mode")
    mounts_table.add_column("Excludes", style="dim")
    for m in spec.mounts:
        mode_style = "green" if m.mode == "read-write" else "yellow"
        excludes = ", ".join(m.exclude) if m.exclude else ""
        mounts_table.add_row(m.path, f"[{mode_style}]{m.mode}[/{mode_style}]", excludes)
    if not spec.mounts:
        mounts_table.add_row("[dim]none[/dim]", "", "")
    console.print(mounts_table)

    # Network --------------------------------------------------------------
    net_table = Table(title="Network")
    net_table.add_column("Setting", style="bold")
    net_table.add_column("Value")
    net_table.add_row("Default policy", spec.network.default)
    for domain in spec.network.allow:
        net_table.add_row("Allow", f"[green]{domain}[/green]")
    console.print(net_table)

    # Profiles -------------------------------------------------------------
    if spec.profiles:
        prof_table = Table(title="Profiles")
        prof_table.add_column("Name", style="cyan")
        prof_table.add_column("Tools override")
        prof_table.add_column("Network override")
        for pname, profile in spec.profiles.items():
            t_info = ", ".join(profile.tools.allow) if profile.tools else "-"
            n_info = (
                f"allow {len(profile.network.allow)} domains"
                if profile.network
                else "-"
            )
            prof_table.add_row(pname, t_info, n_info)
        console.print(prof_table)

    # Limits ---------------------------------------------------------------
    limits_table = Table(title="Limits")
    limits_table.add_column("Resource", style="bold")
    limits_table.add_column("Value")
    limits_table.add_row("CPU", str(spec.limits.cpu))
    limits_table.add_row("Memory", spec.limits.memory)
    console.print(limits_table)

    # Validation -----------------------------------------------------------
    from bulbi.validate import validate_spec

    result = validate_spec(spec)

    if result.errors:
        console.print("\n[bold red]Errors:[/bold red]")
        for e in result.errors:
            console.print(f"  [red]✗ {e}[/red]")

    if result.warnings:
        console.print("\n[bold yellow]Warnings:[/bold yellow]")
        for w in result.warnings:
            console.print(f"  [yellow]! {w}[/yellow]")

    if not result.errors and not result.warnings:
        console.print("\n[green]Spec is valid with no warnings.[/green]")

    console.print()


# ---------------------------------------------------------------------------
# Shared sandbox lifecycle
# ---------------------------------------------------------------------------

def _run_in_sandbox(
    spec: BulbiSpec,
    project_root: Path,
    cmd: list[str],
    *,
    status_msg: str = "Running",
) -> int:
    """Build image, start proxy + container, run a command, then clean up."""
    from bulbi.agents import get_agent_config
    from bulbi.container import run_in_box, start_box, stop_box
    from bulbi.image import build_image
    from bulbi.log import ensure_log_dir, get_log_path
    from bulbi.proxy import AllowlistProxy

    ensure_log_dir(project_root)
    log_path = get_log_path(project_root)

    console.print(f"[bold]Building image for [cyan]{spec.box.name}[/cyan]...[/bold]")
    build_image(spec, project_root)

    proxy = AllowlistProxy(
        allowed_domains=spec.network.allow,
        secrets=spec.secrets,
        log_path=log_path,
    )
    container_id: str | None = None

    try:
        proxy_port = proxy.start()
        console.print("[bold]Starting container...[/bold]")
        container_id = start_box(spec, project_root, profile=None, proxy_port=proxy_port)
        console.print(f"[bold]{status_msg}:[/bold] {' '.join(cmd)}")
        exit_code = run_in_box(container_id, cmd)
    finally:
        if container_id:
            stop_box(container_id)
        proxy.stop()

    return exit_code


def _load_and_resolve(profile: str | None) -> tuple[BulbiSpec, Path]:
    """Load the spec from cwd and optionally apply a profile."""
    project_root = Path.cwd()
    try:
        spec = load_spec(project_root)
    except SpecError as exc:
        raise click.ClickException(str(exc))

    if profile:
        try:
            spec = spec.resolve_profile(profile)
        except SpecError as exc:
            raise click.ClickException(str(exc))

    return spec, project_root


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

@main.command()
@click.option(
    "-p", "--profile",
    default=None,
    help="Apply a named profile from the spec.",
)
@click.argument("command", nargs=-1)
def run(profile: str | None, command: tuple[str, ...]) -> None:
    """Build the sandbox and run a command (default: the configured agent)."""
    from bulbi.agents import get_agent_config

    spec, project_root = _load_and_resolve(profile)

    if command:
        cmd = list(command)
    else:
        agent_config = get_agent_config(spec.box.agent)
        if agent_config:
            cmd = list(agent_config.command)
        else:
            cmd = [spec.box.agent]

    exit_code = _run_in_sandbox(spec, project_root, cmd, status_msg="Running")
    raise SystemExit(exit_code)


# ---------------------------------------------------------------------------
# shell
# ---------------------------------------------------------------------------

@main.command()
@click.option(
    "-p", "--profile",
    default=None,
    help="Apply a named profile from the spec.",
)
def shell(profile: str | None) -> None:
    """Open an interactive bash shell inside the sandbox."""
    spec, project_root = _load_and_resolve(profile)
    exit_code = _run_in_sandbox(spec, project_root, ["bash"], status_msg="Opening shell")
    raise SystemExit(exit_code)


# ---------------------------------------------------------------------------
# log
# ---------------------------------------------------------------------------

@main.command("log")
@click.option("--denied", is_flag=True, help="Show only denied requests.")
def log_cmd(denied: bool) -> None:
    """Show proxy log entries (allowed/denied network requests)."""
    from bulbi.log import get_log_path, format_log_table

    project_root = Path.cwd()
    log_path = get_log_path(project_root)

    if not log_path.exists():
        raise click.ClickException(
            f"No log file found at {log_path}. Run a command first."
        )

    try:
        entries = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
    except (json.JSONDecodeError, ValueError) as exc:
        raise click.ClickException(f"Failed to parse log file: {exc}")

    table = format_log_table(entries, denied_only=denied)
    console.print(table)

    total = len(entries)
    denied_count = sum(1 for e in entries if e.get("action") == "deny")
    console.print(
        f"\n[dim]{total} total entries, {denied_count} denied[/dim]\n"
    )


# ---------------------------------------------------------------------------
# ls
# ---------------------------------------------------------------------------

@main.command("ls")
def ls_cmd() -> None:
    """List all running bulbi containers."""
    from bulbi.container import list_boxes

    boxes = list_boxes()

    if not boxes:
        console.print("[dim]No running bulbi containers.[/dim]")
        return

    table = Table(title="Bulbi Containers")
    table.add_column("ID", style="dim")
    table.add_column("Container", style="cyan")
    table.add_column("Box", style="bold")
    table.add_column("Status")

    for box in boxes:
        status_style = "green" if box.get("status") == "running" else "yellow"
        table.add_row(
            box.get("id", "?"),
            box.get("name", "?"),
            box.get("box", "?"),
            f"[{status_style}]{box.get('status', '?')}[/{status_style}]",
        )

    console.print(table)


# ---------------------------------------------------------------------------
# rm
# ---------------------------------------------------------------------------

@main.command()
@click.argument("container")
def rm(container: str) -> None:
    """Remove a bulbi container by name or ID."""
    from bulbi.container import remove_box

    try:
        remove_box(container)
    except Exception as exc:
        raise click.ClickException(str(exc))

    console.print(f"[green]Removed container: {container}[/green]")


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------

@main.command()
@click.confirmation_option(prompt="This will remove ALL bulbi containers and images. Continue?")
def reset() -> None:
    """Remove all bulbi containers and images."""
    from bulbi.container import reset_boxes

    try:
        reset_boxes()
    except Exception as exc:
        raise click.ClickException(str(exc))

    console.print("[green]All bulbi containers and images removed.[/green]")
