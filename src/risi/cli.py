"""Command-line interface for the RISI scaffold."""

import typer

from risi import __version__

app = typer.Typer(
    help="Reference tooling for Retrieval-Induced State Interference research.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Print the installed RISI package version."""
    typer.echo(__version__)


@app.command()
def smoke() -> None:
    """Run a deterministic package smoke check."""
    typer.echo("risi smoke: ok")
