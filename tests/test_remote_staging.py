"""Guard the architectural constraint behind agentless WinRM scanning.

The modules in ``REMOTE_SCAN_FILES`` get copied onto a remote Windows host that
has no packages installed. If one of them ever grows a third-party import, the
remote scan breaks at run time on someone else's machine — so it is checked here
instead. These tests are pure static analysis and run on every platform.
"""

from __future__ import annotations

import ast
import sys

import pytest

from endpointradar import scanner

# Imports the remote host is allowed to resolve: the standard library, the
# package itself, and the two optional dependencies that are already guarded by
# try/except at their call sites.
GUARDED_OPTIONAL = {"psutil", "winrm"}


def _top_level_imports(path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import, i.e. inside this package
                continue
            if node.module:
                found.add(node.module.split(".")[0])
    return found


@pytest.mark.parametrize("filename", scanner.REMOTE_SCAN_FILES)
def test_staged_file_exists(filename: str) -> None:
    assert (scanner.PACKAGE_DIR / filename).is_file(), f"{filename} is staged but missing"


@pytest.mark.parametrize("filename", scanner.REMOTE_SCAN_FILES)
def test_staged_file_imports_only_the_standard_library(filename: str) -> None:
    imports = _top_level_imports(scanner.PACKAGE_DIR / filename)
    offenders = {
        name
        for name in imports
        if name not in sys.stdlib_module_names
        and name not in GUARDED_OPTIONAL
        and name != "endpointradar"
    }
    assert not offenders, (
        f"{filename} is staged onto bare remote hosts but imports {sorted(offenders)}. "
        "Move that code into gui.py, server.py or reporting.py."
    )


def test_stage_payloads_resolve_against_the_package_not_the_cwd(tmp_path, monkeypatch) -> None:
    """Regression: payloads were once read from Path(filename), i.e. the CWD."""
    monkeypatch.chdir(tmp_path)
    payloads = scanner._build_remote_stage_payloads()
    assert payloads, "no payloads were built"
    for item in payloads:
        assert item["data"], f"{item['label']} staged as empty"


def test_every_staged_module_lands_inside_the_package_directory() -> None:
    payloads = scanner._build_remote_stage_payloads()
    module_payloads = [p for p in payloads if p["remote_path"].endswith(".py")]
    package_files = [p for p in module_payloads if scanner.PACKAGE_NAME + "\\" in p["remote_path"]]
    assert len(package_files) == len(scanner.REMOTE_SCAN_FILES)


def test_runner_is_staged_outside_the_package() -> None:
    payloads = scanner._build_remote_stage_payloads()
    runner = [p for p in payloads if p["remote_path"] == scanner.REMOTE_SCAN_RUNNER_FILE]
    assert len(runner) == 1, "expected exactly one runner payload"
    # It must sit beside the package so `from endpointradar import scanner` resolves.
    assert scanner.PACKAGE_NAME + "\\" not in runner[0]["remote_path"]


def test_runner_script_is_valid_python_and_imports_the_package() -> None:
    source = scanner._build_remote_runner_text()
    ast.parse(source)  # raises SyntaxError if the generated script is malformed
    assert f"from {scanner.PACKAGE_NAME} import scanner" in source
    assert "sys.path.insert" in source, "runner must put its own directory on sys.path"
    assert scanner.REMOTE_SCAN_SENTINEL in source, "runner must print the completion sentinel"


def test_init_is_staged_so_the_package_is_importable() -> None:
    assert "__init__.py" in scanner.REMOTE_SCAN_FILES
