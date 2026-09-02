"""
Rich terminal dashboard for the SIEM alert output.
Renders a ranked alert table followed by per-alert detail panels.
"""
from datetime import datetime
from typing import Dict, List

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from models import Alert

console = Console(highlight=False)

_SEVERITY_STYLE: Dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold cyan",
    "LOW":      "bold green",
    "INFO":     "dim",
}
_SEVERITY_ICON: Dict[str, str] = {
    "CRITICAL": "[red][CRIT][/red]",
    "HIGH":     "[yellow][HIGH][/yellow]",
    "MEDIUM":   "[cyan][MED][/cyan]",
    "LOW":      "[green][LOW][/green]",
}
_TYPE_LABEL: Dict[str, str] = {
    "BRUTE_FORCE":          "Brute Force",
    "LATERAL_MOVEMENT":     "Lateral Movement",
    "PRIVILEGE_ESCALATION": "Privilege Escalation",
    "IMPOSSIBLE_TRAVEL":    "Impossible Travel",
    "OFF_HOURS_LOGIN":      "Off-Hours Login",
    "CREDENTIAL_STUFFING":  "Credential Stuffing",
    "DATA_EXFILTRATION":    "Data Exfiltration",
    "WEB_ATTACK":           "Web Attack",
}


def render_dashboard(alerts: List[Alert], log_stats: Dict[str, int]) -> None:
    console.print()
    console.rule(
        "[bold blue]SIEM LOG ANALYZER  |  Alert Dashboard[/bold blue]",
        style="bold blue",
    )
    console.print(
        f"  [dim]Run at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
    )
    console.print()

    _render_summary(alerts, log_stats)
    console.print()

    if not alerts:
        console.print("[bold green]  No threats detected in the provided logs.[/bold green]")
        return

    _render_alert_table(alerts)
    console.print()
    console.rule("[bold]Alert Details[/bold]")
    console.print()

    for rank, alert in enumerate(alerts, 1):
        _render_detail_panel(rank, alert)
        console.print()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _render_summary(alerts: List[Alert], log_stats: Dict[str, int]) -> None:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        counts[a.severity] = counts.get(a.severity, 0) + 1

    total_events = sum(log_stats.values())

    t = Table(box=box.ROUNDED, show_header=False, padding=(0, 2), expand=False)
    t.add_column("k", style="bold dim")
    t.add_column("v")

    t.add_row("Alerts found", str(len(alerts)))
    t.add_row(
        "Breakdown",
        "  ".join(
            f"[{_SEVERITY_STYLE[s]}]{s}: {c}[/{_SEVERITY_STYLE[s]}]"
            for s, c in counts.items()
            if c > 0
        ) or "[dim]none[/dim]",
    )
    t.add_row(
        "Events parsed",
        "  ".join(f"{src.upper()}: {n:,}" for src, n in log_stats.items())
        + f"  (total {total_events:,})",
    )

    console.print(Panel(t, title="[bold]Summary[/bold]", border_style="blue", expand=False))


def _render_alert_table(alerts: List[Alert]) -> None:
    t = Table(
        title="Ranked Alerts",
        title_style="bold white on blue",
        box=box.DOUBLE_EDGE,
        show_lines=True,
        expand=False,
    )
    t.add_column("#",         width=3,  justify="right", style="dim")
    t.add_column("Severity",  width=12)
    t.add_column("Type",      width=24)
    t.add_column("Score",     width=6,  justify="center")
    t.add_column("Source IPs",width=20)
    t.add_column("Users",     width=18)
    t.add_column("Events",    width=7,  justify="right")
    t.add_column("Title",     min_width=28)

    for i, a in enumerate(alerts, 1):
        sty  = _SEVERITY_STYLE.get(a.severity, "white")
        icon = _SEVERITY_ICON.get(a.severity, "")
        label = _TYPE_LABEL.get(a.alert_type, a.alert_type)

        ips = ", ".join(a.involved_ips[:2])
        if len(a.involved_ips) > 2:
            ips += f" (+{len(a.involved_ips) - 2})"

        users = ", ".join(a.involved_users[:2])
        if len(a.involved_users) > 2:
            users += f" (+{len(a.involved_users) - 2})"

        t.add_row(
            str(i),
            f"{icon} [{sty}]{a.severity}[/{sty}]",
            label,
            f"[{sty}]{a.score}[/{sty}]",
            ips   or "[dim]-[/dim]",
            users or "[dim]-[/dim]",
            str(a.event_count),
            a.title,
        )

    console.print(t)


def _render_detail_panel(rank: int, alert: Alert) -> None:
    sty  = _SEVERITY_STYLE.get(alert.severity, "white")
    icon = _SEVERITY_ICON.get(alert.severity, "")
    border = sty.replace("bold ", "")

    lines: List[str] = [alert.description, ""]

    for k, v in alert.details.items():
        label = k.replace("_", " ").title()
        if isinstance(v, list):
            val = ", ".join(str(x) for x in v[:8])
            if len(v) > 8:
                val += f" … (+{len(v) - 8} more)"
        elif isinstance(v, bool):
            val = "[green]Yes[/green]" if v else "[dim]No[/dim]"
        else:
            val = str(v)
        lines.append(f"  [dim]{label}:[/dim] {val}")

    lines.append(
        f"  [dim]Time Range:[/dim] "
        f"{alert.first_seen.strftime('%H:%M:%S')} to "
        f"{alert.last_seen.strftime('%H:%M:%S')} "
        f"({alert.first_seen.strftime('%Y-%m-%d')})"
    )

    if alert.mitre_technique:
        lines.append(f"  [dim]MITRE ATT&CK:[/dim] [italic]{alert.mitre_technique}[/italic]")

    console.print(Panel(
        "\n".join(lines),
        title=f"{icon} [{sty}][{rank}] {alert.title}[/{sty}]",
        title_align="left",
        subtitle=f"[dim]Score: {alert.score}/100[/dim]",
        subtitle_align="right",
        border_style=border,
    ))
