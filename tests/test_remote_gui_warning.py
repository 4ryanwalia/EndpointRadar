"""Exercise the actual GUI scan-start method without creating a Tk window."""

import ast
from pathlib import Path
from types import SimpleNamespace

from endpointradar import scanner


def _scan_start_method(messagebox, thread_factory):
    source = (Path(__file__).resolve().parents[1] / "src/endpointradar/gui.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    dashboard = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "EndpointDashboard")
    method = next(node for node in dashboard.body if isinstance(node, ast.FunctionDef) and node.name == "_start_remote_scan")
    module = ast.Module(body=[method], type_ignores=[])
    namespace = {"messagebox": messagebox, "threading": SimpleNamespace(Thread=thread_factory)}
    exec(compile(ast.fix_missing_locations(module), "gui.py", "exec"), namespace)
    return namespace["_start_remote_scan"]


def test_warning_is_shown_before_initial_and_cached_scan_start():
    for reuse_cached_session in (False, True):
        events = []

        def warn(title, text, parent):
            events.append(("warning", text, parent))

        def make_thread(**kwargs):
            return SimpleNamespace(start=lambda: events.append(("start", kwargs)))

        fake = SimpleNamespace(
            selected_device=None,
            remote_scan_in_progress=False,
            _update_remote_scan_progress_ui=lambda *args: None,
            _update_connection_status_ui=lambda: None,
            _remote_scan_worker=lambda *args: None,
        )
        start = _scan_start_method(SimpleNamespace(showwarning=warn), make_thread)
        start(fake, "192.0.2.1", reuse_cached_session=reuse_cached_session)
        assert [event[0] for event in events] == ["warning", "start"]
        assert "sensitive scan results remain" in events[0][1]
        assert "write access" in events[0][1]
        assert events[0][2] is fake
        assert fake.remote_scan_in_progress


def test_multiple_open_ports_describe_scanner_reachability():
    ports = [{"port": port} for port in (22, 80, 443)]
    _, _, reasons = scanner._calculate_unauthenticated_risk(ports)
    assert any("reachable from this scanner" in reason for reason in reasons)
    assert not any("externally reachable" in reason for reason in reasons)
