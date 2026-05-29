import logging
import sys
from typing import Annotated

import typer

from network.recon.config import DEFAULT_TIMEOUT
from network.recon.orchestrator import recon_async

app = typer.Typer(add_completion=False, help="Passive reconnaissance tool.")


@app.command()
def main(
    target: Annotated[
        str | None,
        typer.Argument(help="Domain or URL to probe."),
    ] = None,
    probes: Annotated[
        str | None,
        typer.Option("--probes", help="Comma-separated probe names (default: all)."),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", help="Output format: rich | json | html | pandas."),
    ] = "rich",
    no_cache: Annotated[
        bool,
        typer.Option("--no-cache", help="Bypass reading the local cache (still writes)."),
    ] = False,
    clear_cache: Annotated[
        bool,
        typer.Option("--clear-cache", help="Clear the cache and exit."),
    ] = False,
    ssl_labs: Annotated[
        bool,
        typer.Option("--ssl-labs", help="Include slow SSL Labs grade probe."),
    ] = False,
    verbose: Annotated[
        int,
        typer.Option("-v", "--verbose", count=True, help="Increase verbosity (-v INFO, -vv DEBUG)."),
    ] = 0,
) -> None:
    level = logging.WARNING
    if verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")

    if clear_cache:
        from network.recon import cache
        cache.clear()
        typer.echo("Cache cleared.")
        raise typer.Exit()

    if target is None:
        typer.echo("Error: Missing argument 'TARGET'.", err=True)
        raise typer.Exit(code=1)

    import asyncio

    probe_list = [p.strip() for p in probes.split(",")] if probes else None

    result = asyncio.run(
        recon_async(
            target,
            probes=probe_list,
            timeout=DEFAULT_TIMEOUT,
            use_cache=not no_cache,
            ssl_labs=ssl_labs,
        )
    )

    if fmt == "rich":
        from network.recon.renderers.rich_renderer import render
        render(result)
    elif fmt == "json":
        from network.recon.renderers.json_renderer import render
        typer.echo(render(result))
    elif fmt == "html":
        from network.recon.renderers.html_renderer import render
        typer.echo(render(result))
    elif fmt == "pandas":
        from network.recon.renderers.pandas_renderer import render
        frames = render(result)
        for name, df in frames.items():
            typer.echo(f"\n=== {name} ===")
            typer.echo(df.to_string(index=False))
    else:
        typer.echo(str(result))
