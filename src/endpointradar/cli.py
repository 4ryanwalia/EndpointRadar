"""EndpointRadar command line interface.

Every subcommand is a thin shell over the same engine the GUI uses, so a
terminal run, a CI job and the desktop dashboard all produce identical
records and identical risk scores.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_THRESHOLD = 2

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# --------------------------------------------------------------------------
# Terminal rendering
# --------------------------------------------------------------------------

class Style:
    """ANSI helpers that quietly turn themselves off when output is piped."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)

    def severity(self, level: str, text: str | None = None) -> str:
        label = text if text is not None else level
        level = (level or "").upper()
        if level in {"CRITICAL", "HIGH"}:
            return self.red(label)
        if level == "MEDIUM":
            return self.yellow(label)
        if level == "LOW":
            return self.green(label)
        return self.dim(label)


def _color_enabled(no_color: bool) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        # Enable VT sequences on older Windows consoles; harmless if unsupported.
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            return False
    return True


def _emit(message: str, quiet: bool = False) -> None:
    if not quiet:
        print(message)


def _configure_stdout() -> None:
    """Keep box-drawing and emoji from crashing legacy Windows codepages."""
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass



def _table(rows: Sequence[Sequence[str]], headers: Sequence[str]) -> str:
    """Render a plain, dependency-free aligned table."""
    cols = len(headers)
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for i in range(cols):
            widths[i] = max(widths[i], len(str(row[i])))
    out = [" ".join(str(headers[i]).ljust(widths[i]) for i in range(cols)).rstrip()]
    out.append(" ".join("-" * widths[i] for i in range(cols)))
    for row in rows:
        out.append(" ".join(str(row[i]).ljust(widths[i]) for i in range(cols)).rstrip())
    return "\n".join(out)


def _progress_printer(style: Style, quiet: bool):
    """Build a progress callback for the long-running scanner operations."""
    state: dict[str, Any] = {"last": ""}

    def callback(message: str, percent: float, eta_seconds: int | None) -> None:
        if quiet:
            return
        eta = f" ~{eta_seconds}s left" if eta_seconds else ""
        line = f"  [{percent:5.1f}%] {message}{eta}"
        if line == state["last"]:
            return
        state["last"] = line
        print(style.dim(line), flush=True)

    return callback


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------

def _write_json(payload: Any, output: Path | None, style: Style, quiet: bool) -> None:
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if output is None:
        print(text)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text + "\n", encoding="utf-8")
    _emit(style.green(f"Saved {output}"), quiet)


def _render_scan_summary(scan: dict[str, Any], style: Style, limit: int = 12) -> str:
    from . import risk

    lines: list[str] = []
    level = str(scan.get("risk_level") or "UNKNOWN").upper()
    score = scan.get("risk_score", 0)
    host = scan.get("hostname") or "Unknown"
    ip = scan.get("target_ip") or scan.get("device_id") or "n/a"

    lines.append("")
    lines.append(style.bold(f"  {host}  ({ip})"))
    lines.append(f"  Risk score {style.bold(str(score))}   Level {style.severity(level, level)}")

    reason = risk.summarize_risk_reason(scan)
    if reason:
        lines.append(f"  {style.dim(reason)}")

    drivers = [d for d in risk.top_risk_drivers(scan, limit=3) if d[1] > 0]
    if drivers:
        lines.append("")
        lines.append(style.bold("  Top risk drivers"))
        for name, points, percent in drivers:
            bar = "#" * max(1, int(percent / 5))
            lines.append(f"    {name:<22} {points:>3} pts  {percent:5.1f}%  {style.dim(bar)}")

    vulns = scan.get("vulnerabilities") or []
    if vulns:
        ordered = sorted(
            vulns,
            key=lambda v: SEVERITY_ORDER.get(str(v.get("severity") or "").upper(), 0),
            reverse=True,
        )
        lines.append("")
        lines.append(style.bold(f"  Findings ({len(vulns)})"))
        for v in ordered[:limit]:
            sev = str(v.get("severity") or "INFO").upper()
            lines.append(f"    {style.severity(sev, sev.ljust(8))} {v.get('title')}")
        if len(ordered) > limit:
            lines.append(style.dim(f"    ... {len(ordered) - limit} more (use --format json for all)"))
    else:
        lines.append("")
        lines.append(style.green("  No findings raised by these checks."))

    lines.append("")
    return "\n".join(lines)


def _threshold_exit(scan: dict[str, Any], fail_on: str, style: Style, quiet: bool) -> int:
    if fail_on == "never":
        return EXIT_OK
    threshold = SEVERITY_ORDER.get(fail_on.upper(), 99)
    level = SEVERITY_ORDER.get(str(scan.get("risk_level") or "LOW").upper(), 0)
    if level >= threshold:
        _emit(
            style.red(
                f"FAIL: risk level {scan.get('risk_level')} meets or exceeds --fail-on {fail_on}."
            ),
            quiet,
        )
        return EXIT_THRESHOLD
    return EXIT_OK


def _load_scan(args: argparse.Namespace) -> dict[str, Any]:
    """Resolve a single scan record from --input / --device, or the newest saved one."""
    from . import scanner

    if getattr(args, "input", None):
        path = Path(args.input)
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            if not data:
                raise SystemExit(f"{path} contains no scan records.")
            records = data
        else:
            records = [data]
    else:
        records = scanner.load_scan_results()
        if not records:
            raise SystemExit(
                "No saved scans found. Run 'endpointradar scan' first, or pass --input <file>."
            )

    device = getattr(args, "device", None)
    if device:
        for record in records:
            if device in {record.get("device_id"), record.get("hostname"), record.get("target_ip")}:
                return record
        known = ", ".join(str(r.get("hostname")) for r in records)
        raise SystemExit(f"No scan matching '{device}'. Available: {known}")

    return sorted(records, key=lambda r: str(r.get("last_scan_at") or ""), reverse=True)[0]


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace, style: Style) -> int:
    from . import os_check, scanner

    if args.format == "text":
        _emit(style.dim("Running local posture checks..."), args.quiet)
        report = os_check.build_text_report()
        if args.output:
            Path(args.output).write_text(report, encoding="utf-8")
            _emit(style.green(f"Saved {args.output}"), args.quiet)
        else:
            print(report)
        return EXIT_OK

    _emit(style.dim("Running local posture checks..."), args.quiet)
    scan = scanner.run_single_scan()

    if not args.no_save:
        results = scanner.upsert_scan_result(scanner.load_scan_results(), scan)
        scanner.save_scan_results(results)
        _emit(style.dim(f"Saved to {scanner.SCAN_RESULTS_FILE}"), args.quiet)

    if args.format == "json":
        _write_json(scan, Path(args.output) if args.output else None, style, args.quiet)
    else:
        print(_render_scan_summary(scan, style))
        if args.output:
            _write_json(scan, Path(args.output), style, args.quiet)

    return _threshold_exit(scan, args.fail_on, style, args.quiet)


def cmd_discover(args: argparse.Namespace, style: Style) -> int:
    from . import scanner

    subnet = args.subnet or scanner.guess_default_subnet()
    _emit(style.dim(f"Discovering devices on {subnet} ..."), args.quiet)
    probed = scanner.discover_devices(subnet, timeout_ms=args.timeout, max_workers=args.workers)

    # discover_devices probes every address in the subnet and flags which answered.
    devices = probed if args.include_offline else [d for d in probed if d.get("online")]
    devices.sort(key=lambda d: [int(part) for part in str(d.get("ip") or "0.0.0.0").split(".") if part.isdigit()])

    if args.format == "json":
        _write_json(devices, Path(args.output) if args.output else None, style, args.quiet)
        return EXIT_OK

    if not devices:
        _emit(style.yellow(f"No devices responded on {subnet}."), args.quiet)
        return EXIT_OK

    rows = [
        [
            str(d.get("ip") or "-"),
            str(d.get("hostname") or "-"),
            str(d.get("mac_address") or "-"),
            str(d.get("mac_vendor") or "-"),
            str(d.get("device_type_label") or "-"),
            str(d.get("status") or "-"),
        ]
        for d in devices
    ]
    print("")
    print(style.bold(f"  {len(devices)} device(s) responding on {subnet}"))
    print(style.dim(f"  {len(probed)} addresses probed."))
    print("")
    print(_table(rows, ["IP", "HOSTNAME", "MAC", "VENDOR", "TYPE", "STATUS"]))
    print("")
    if args.output:
        _write_json(devices, Path(args.output), style, args.quiet)
    return EXIT_OK


def cmd_sweep(args: argparse.Namespace, style: Style) -> int:
    from . import scanner

    subnet = args.subnet or scanner.guess_default_subnet()
    _emit(style.dim(f"Unauthenticated exposure sweep of {subnet} ..."), args.quiet)
    callback = _progress_printer(style, args.quiet)

    if args.no_save:
        results = scanner.run_unauthenticated_scan(subnet, progress_callback=callback)
    else:
        results = scanner.add_unauthenticated_scan_to_results(subnet, progress_callback=callback)
        _emit(style.dim(f"Saved to {scanner.UNAUTH_SCAN_RESULTS_FILE}"), args.quiet)

    if args.format == "json":
        _write_json(results, Path(args.output) if args.output else None, style, args.quiet)
        return EXIT_OK

    if not results:
        _emit(style.yellow(f"No reachable devices found on {subnet}."), args.quiet)
        return EXIT_OK

    rows = []
    for record in results:
        ports = (record.get("open_ports") or {}).get("risky_open") or []
        port_text = ", ".join(str(p.get("port")) for p in ports) or "-"
        rows.append(
            [
                str(record.get("target_ip") or ""),
                str(record.get("hostname") or "-"),
                str(record.get("risk_level") or "-"),
                str(record.get("risk_score") or 0),
                port_text,
            ]
        )
    print("")
    print(style.bold(f"  {len(results)} device(s) scanned on {subnet}"))
    print(style.dim("  Unauthenticated view: open ports only, no host internals."))
    print("")
    print(_table(rows, ["IP", "HOSTNAME", "RISK", "SCORE", "OPEN PORTS"]))
    print("")
    if args.output:
        _write_json(results, Path(args.output), style, args.quiet)
    return EXIT_OK


def cmd_remote(args: argparse.Namespace, style: Style) -> int:
    from . import scanner

    password = os.environ.get(args.password_env or "")
    if not password:
        if not sys.stdin.isatty():
            raise SystemExit(
                f"No password available. Set ${args.password_env} or run in an interactive terminal."
            )
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")
    if not password:
        raise SystemExit("A password is required for WinRM authentication.")

    _emit(style.dim(f"Connecting to {args.host} over WinRM as {args.username} ..."), args.quiet)
    try:
        scan = scanner.run_remote_scan(
            args.host,
            args.username,
            password,
            timeout_s=args.timeout,
            progress_callback=_progress_printer(style, args.quiet),
        )
    except scanner.RemoteScanError as exc:
        print(style.red(f"Remote scan failed ({exc.code}): {exc}"), file=sys.stderr)
        return EXIT_ERROR

    if not args.no_save:
        results = scanner.upsert_scan_result(scanner.load_scan_results(), scan)
        scanner.save_scan_results(results)
        _emit(style.dim(f"Saved to {scanner.SCAN_RESULTS_FILE}"), args.quiet)

    if args.format == "json":
        _write_json(scan, Path(args.output) if args.output else None, style, args.quiet)
    else:
        print(_render_scan_summary(scan, style))
        if args.output:
            _write_json(scan, Path(args.output), style, args.quiet)

    return _threshold_exit(scan, args.fail_on, style, args.quiet)


def cmd_threats(args: argparse.Namespace, style: Style) -> int:
    from . import threats as threat_analysis

    scan = _load_scan(args)
    generated = threat_analysis.generate_threats(scan, max_threats=args.max)

    if args.format == "json":
        _write_json(generated, Path(args.output) if args.output else None, style, args.quiet)
        return EXIT_OK

    if not generated:
        _emit(style.green("No threats derived from this scan."), args.quiet)
        return EXIT_OK

    rows = [
        [
            str(t.get("risk_level") or ""),
            str(t.get("score") or ""),
            str(t.get("nist_function") or ""),
            str(t.get("category") or ""),
            str(t.get("threat_title") or ""),
        ]
        for t in generated
    ]
    print("")
    print(style.bold(f"  Threat analysis - {scan.get('hostname')} ({len(generated)} threats)"))
    print(style.dim("  Scored likelihood x impact, mapped to NIST CSF 2.0 functions."))
    print("")
    print(_table(rows, ["RISK", "SCORE", "CSF", "CATEGORY", "THREAT"]))
    print("")

    if args.verbose:
        for t in generated:
            print(style.bold(f"  {t.get('threat_title')}"))
            print(f"    {t.get('description')}")
            print(style.cyan(f"    Fix: {t.get('recommendation')}"))
            print("")

    if args.output:
        _write_json(generated, Path(args.output), style, args.quiet)
    return EXIT_OK


def cmd_report(args: argparse.Namespace, style: Style) -> int:
    from . import reporting, scanner

    if args.kind == "threat":
        scan = _load_scan(args)
        default_name = f"threat_report_{scan.get('hostname') or 'device'}.docx"
        output = Path(args.output or default_name)
        path = reporting.build_threat_word_report(scan, output_path=output)
    else:
        if getattr(args, "input", None):
            records = json.loads(Path(args.input).read_text(encoding="utf-8"))
            if isinstance(records, dict):
                records = [records]
        else:
            records = scanner.load_scan_results()
        if not records:
            raise SystemExit("No scans to report on. Run 'endpointradar scan' first.")
        output = Path(args.output or "endpointradar_report.docx")
        path = reporting.build_word_report(records, output_path=output)

    _emit(style.green(f"Report written to {path}"), args.quiet)
    return EXIT_OK


def cmd_show(args: argparse.Namespace, style: Style) -> int:
    from . import risk, scanner

    if args.all:
        records = scanner.load_scan_results()
        if not records:
            raise SystemExit("No saved scans found. Run 'endpointradar scan' first.")
        if args.format == "json":
            _write_json(records, Path(args.output) if args.output else None, style, args.quiet)
            return EXIT_OK
        counts, names = risk.risk_distribution(records)
        rows = [
            [
                str(r.get("hostname") or "-"),
                str(r.get("target_ip") or "-"),
                str(r.get("risk_level") or "-"),
                str(r.get("risk_score") or 0),
                str(len(r.get("vulnerabilities") or [])),
                str(r.get("last_scan_at") or "-")[:19].replace("T", " "),
            ]
            for r in records
        ]
        print("")
        print(style.bold(f"  {len(records)} saved scan(s)"))
        summary = "  ".join(
            f"{style.severity(level, level)} {counts[level]}" for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        )
        print(f"  {summary}")
        print("")
        print(_table(rows, ["HOSTNAME", "IP", "RISK", "SCORE", "FINDINGS", "LAST SCAN"]))
        print("")
        return EXIT_OK

    scan = _load_scan(args)
    if args.format == "json":
        _write_json(scan, Path(args.output) if args.output else None, style, args.quiet)
        return EXIT_OK
    print(_render_scan_summary(scan, style, limit=args.limit))
    if args.verbose:
        for v in scan.get("vulnerabilities") or []:
            print(style.bold(f"  {v.get('title')}"))
            print(f"    {v.get('description')}")
            print(style.cyan(f"    Fix: {v.get('fix')}"))
            print("")
    return _threshold_exit(scan, args.fail_on, style, args.quiet)


def cmd_dashboard(args: argparse.Namespace, style: Style) -> int:
    try:
        from .gui import EndpointDashboard
    except ImportError as exc:  # pragma: no cover - depends on optional extras
        print(
            style.red(f"The desktop dashboard needs the 'gui' extra: pip install 'endpointradar[gui]'\n  ({exc})"),
            file=sys.stderr,
        )
        return EXIT_ERROR
    EndpointDashboard().mainloop()
    return EXIT_OK


def cmd_serve(args: argparse.Namespace, style: Style) -> int:
    try:
        from .server import app
    except ImportError as exc:  # pragma: no cover - depends on optional extras
        print(
            style.red(f"The web API needs the 'web' extra: pip install 'endpointradar[web]'\n  ({exc})"),
            file=sys.stderr,
        )
        return EXIT_ERROR
    _emit(style.green(f"EndpointRadar web dashboard on http://{args.host}:{args.port}"), args.quiet)
    app.run(host=args.host, port=args.port, debug=args.debug)
    return EXIT_OK


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="endpointradar",
        description="Agentless Windows endpoint security posture scanner.",
        epilog="Docs: https://4ryanwalia.github.io/EndpointRadar/",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"EndpointRadar {__version__}")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress progress and status lines")

    # Repeated on every subcommand so both orderings work: `endpointradar -q scan`
    # and `endpointradar scan -q`. SUPPRESS keeps the subcommand copy from
    # resetting a flag that was already given before the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--no-color", action="store_true", default=argparse.SUPPRESS, help="disable coloured output"
    )
    common.add_argument(
        "-q", "--quiet", action="store_true", default=argparse.SUPPRESS,
        help="suppress progress and status lines",
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    def add_common(p: argparse.ArgumentParser, formats: Sequence[str] = ("summary", "json")) -> None:
        p.add_argument("-f", "--format", choices=list(formats), default=formats[0], help="output format")
        p.add_argument("-o", "--output", help="write the result to this file instead of stdout")

    # scan
    p_scan = sub.add_parser("scan", help="run a full posture scan on this machine", parents=[common])
    add_common(p_scan, ("summary", "json", "text"))
    p_scan.add_argument("--no-save", action="store_true", help="do not append to scan_results.json")
    p_scan.add_argument(
        "--fail-on",
        choices=["never", "low", "medium", "high", "critical"],
        default="never",
        help="exit with code 2 when the risk level reaches this threshold (for CI)",
    )
    p_scan.set_defaults(func=cmd_scan)

    # discover
    p_disc = sub.add_parser("discover", help="find live devices on a subnet (no credentials)", parents=[common])
    p_disc.add_argument("subnet", nargs="?", help="CIDR subnet, e.g. 192.168.1.0/24 (default: auto-detect)")
    p_disc.add_argument("--timeout", type=int, default=400, help="per-host ping timeout in ms (default: 400)")
    p_disc.add_argument("--workers", type=int, default=32, help="parallel probes (default: 32)")
    p_disc.add_argument(
        "--include-offline", action="store_true", help="also list addresses that did not respond"
    )
    add_common(p_disc, ("table", "json"))
    p_disc.set_defaults(func=cmd_discover)

    # sweep
    p_sweep = sub.add_parser("sweep", help="unauthenticated port and exposure sweep of a subnet", parents=[common])
    p_sweep.add_argument("subnet", nargs="?", help="CIDR subnet, e.g. 192.168.1.0/24 (default: auto-detect)")
    p_sweep.add_argument("--no-save", action="store_true", help="do not append to unauth_scan_results.json")
    add_common(p_sweep, ("table", "json"))
    p_sweep.set_defaults(func=cmd_sweep)

    # remote
    p_remote = sub.add_parser("remote", help="agentless scan of a remote Windows host over WinRM", parents=[common])
    p_remote.add_argument("host", help="target IP address or hostname")
    p_remote.add_argument("-u", "--username", required=True, help="WinRM username (DOMAIN\\user or .\\user)")
    p_remote.add_argument(
        "--password-env",
        default="ENDPOINTRADAR_PASSWORD",
        metavar="VAR",
        help="environment variable holding the password (default: ENDPOINTRADAR_PASSWORD); "
        "prompts interactively when unset",
    )
    p_remote.add_argument("--timeout", type=int, default=90, help="WinRM operation timeout in seconds")
    p_remote.add_argument("--no-save", action="store_true", help="do not append to scan_results.json")
    p_remote.add_argument(
        "--fail-on",
        choices=["never", "low", "medium", "high", "critical"],
        default="never",
        help="exit with code 2 when the risk level reaches this threshold (for CI)",
    )
    add_common(p_remote, ("summary", "json"))
    p_remote.set_defaults(func=cmd_remote)

    # threats
    p_threats = sub.add_parser("threats", help="derive the NIST CSF threat analysis for a scan", parents=[common])
    p_threats.add_argument("-i", "--input", help="scan JSON file (default: the newest saved scan)")
    p_threats.add_argument("-d", "--device", help="hostname or IP to select from saved scans")
    p_threats.add_argument("--max", type=int, default=10, help="maximum threats to generate (default: 10)")
    p_threats.add_argument("-v", "--verbose", action="store_true", help="include descriptions and fixes")
    add_common(p_threats, ("table", "json"))
    p_threats.set_defaults(func=cmd_threats)

    # report
    p_report = sub.add_parser("report", help="build a Word report from saved scans", parents=[common])
    p_report.add_argument(
        "kind",
        nargs="?",
        choices=["fleet", "threat"],
        default="fleet",
        help="fleet: every saved scan; threat: the NIST analysis for one device",
    )
    p_report.add_argument("-i", "--input", help="scan JSON file (default: saved scans)")
    p_report.add_argument("-d", "--device", help="hostname or IP, for the threat report")
    p_report.add_argument("-o", "--output", help="output .docx path")
    p_report.set_defaults(func=cmd_report)

    # show
    p_show = sub.add_parser("show", help="print a saved scan without rescanning", parents=[common])
    p_show.add_argument("-i", "--input", help="scan JSON file (default: saved scans)")
    p_show.add_argument("-d", "--device", help="hostname or IP to select")
    p_show.add_argument("-a", "--all", action="store_true", help="list every saved scan instead of one")
    p_show.add_argument("--limit", type=int, default=12, help="findings to list (default: 12)")
    p_show.add_argument("-v", "--verbose", action="store_true", help="include descriptions and fixes")
    p_show.add_argument(
        "--fail-on",
        choices=["never", "low", "medium", "high", "critical"],
        default="never",
        help="exit with code 2 when the risk level reaches this threshold (for CI)",
    )
    add_common(p_show, ("summary", "json"))
    p_show.set_defaults(func=cmd_show)

    # dashboard
    p_dash = sub.add_parser("dashboard", help="launch the desktop dashboard (needs the gui extra)", parents=[common])
    p_dash.set_defaults(func=cmd_dashboard)

    # serve
    p_serve = sub.add_parser("serve", help="run the read-only web dashboard (needs the web extra)", parents=[common])
    p_serve.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=5000, help="port (default: 5000)")
    p_serve.add_argument("--debug", action="store_true", help="run Flask in debug mode")
    p_serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    _configure_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_OK

    style = Style(_color_enabled(args.no_color))
    try:
        return int(args.func(args, style))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except SystemExit:
        raise
    except FileNotFoundError as exc:
        print(style.red(f"File not found: {exc.filename}"), file=sys.stderr)
        return EXIT_ERROR
    except json.JSONDecodeError as exc:
        print(style.red(f"Invalid JSON: {exc}"), file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # pragma: no cover - top-level safety net
        print(style.red(f"Error: {exc}"), file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
