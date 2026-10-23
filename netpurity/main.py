"""Command-line interface for NetPurity."""

import logging
from pathlib import Path
from typing import Annotated, Optional, Set

import typer

from netpurity.analyzer import DomainAnalyzer, Finding
from netpurity.notifier import DiscordNotifier
from netpurity.sniffer import DnsSniffer, SnifferError
from netpurity.utils import clean_text, format_timestamp, normalize_domain

logger = logging.getLogger(__name__)

app = typer.Typer(no_args_is_help=True, add_completion=False)


@app.callback()
def _root() -> None:
    """NetPurity: monitor DNS traffic for anomalous domains and alert a Discord webhook."""


def load_blacklist(path: Path) -> Set[str]:
    """Read one domain per line from ``path`` and skip blank lines and # comments."""
    domains: Set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = normalize_domain(line.split("#", 1)[0])
        if entry:
            domains.add(entry)
    return domains


def format_finding(finding: Finding) -> str:
    """Render ``finding`` as one console line with sanitized network data."""
    return (
        f"[{format_timestamp(finding.timestamp)}] {finding.reason.value:<14} "
        f"src={clean_text(finding.src_ip, 64)} "
        f"domain={clean_text(finding.domain, 253)} "
        f"entropy={finding.entropy:.2f} | {clean_text(finding.detail, 300)}"
    )


@app.command()
def start(
    interface: Annotated[
        str,
        typer.Option(help="Network interface to sniff, such as eth0 or en0."),
    ],
    webhook: Annotated[
        str,
        typer.Option(
            envvar="NETPURITY_WEBHOOK_URL",
            show_default=False,
            help=(
                "Discord webhook URL. Set NETPURITY_WEBHOOK_URL instead of passing "
                "this flag: other local users can read command-line arguments."
            ),
        ),
    ],
    entropy_threshold: Annotated[
        float,
        typer.Option(min=0.0, help="Minimum label entropy (bits per character) that flags a domain."),
    ] = 3.8,
    port: Annotated[
        int,
        typer.Option(min=1, max=65535, help="UDP port to sniff for DNS traffic."),
    ] = 53,
    blacklist_file: Annotated[
        Optional[Path],
        typer.Option(
            exists=True,
            dir_okay=False,
            readable=True,
            help="Text file with one blacklisted domain per line. A # starts a comment.",
        ),
    ] = None,
    beacon_threshold: Annotated[
        int,
        typer.Option(
            min=2,
            help="Queries from one source to one domain per window that count as beaconing.",
        ),
    ] = 20,
    beacon_window: Annotated[
        int,
        typer.Option(min=1, help="Beaconing window length in seconds."),
    ] = 60,
    cooldown: Annotated[
        int,
        typer.Option(min=0, help="Minimum seconds between two reports of the same finding."),
    ] = 300,
) -> None:
    """Sniff DNS queries on INTERFACE and alert on anomalous domains. Requires root or Administrator."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    blacklist: Set[str] = set()
    if blacklist_file is not None:
        try:
            blacklist = load_blacklist(blacklist_file)
        except (OSError, UnicodeDecodeError) as exc:
            raise typer.BadParameter(
                f"Cannot read blacklist file: {exc}", param_hint="--blacklist-file"
            ) from exc
        logger.info("Loaded %d blacklisted domains from %s", len(blacklist), blacklist_file)

    try:
        notifier = DiscordNotifier(webhook)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--webhook") from exc

    analyzer = DomainAnalyzer(
        entropy_threshold=entropy_threshold,
        blacklist=blacklist,
        beacon_window_seconds=beacon_window,
        beacon_threshold=beacon_threshold,
        cooldown_seconds=cooldown,
    )

    def handle_query(src_ip: str, domain: str, timestamp: float) -> None:
        """Analyze one query; print and send each finding."""
        for finding in analyzer.analyze(src_ip, domain, timestamp):
            typer.echo(format_finding(finding))
            notifier.send(finding)

    sniffer = DnsSniffer(interface, handle_query, port=port)
    try:
        sniffer.start()
    except SnifferError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    except KeyboardInterrupt:
        logger.info("Stopped by user")
    finally:
        notifier.close()


if __name__ == "__main__":
    app()
