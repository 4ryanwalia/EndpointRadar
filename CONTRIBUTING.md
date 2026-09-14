# Contributing to EndpointRadar

Thanks for taking a look. Bug reports, new checks and better remediation text are all welcome.

## Getting set up

```powershell
git clone https://github.com/4ryanwalia/EndpointRadar
cd EndpointRadar
py -m venv .venv
.venv\Scripts\activate
pip install -e ".[all,dev]"

pytest -q
ruff check src tests
```

The test suite runs off `examples/sample-scan.json` rather than the host, so it passes on Linux and
macOS too. You only need Windows to exercise the collectors themselves.

## The one structural rule

`os_check.py`, `installed_apps.py`, `risk.py` and `scanner.py` are staged onto remote hosts during a
WinRM scan, where nothing is installed. **Those four modules must import only the standard library**
(plus the optional, guarded `psutil` and `winrm` imports that already exist).

Anything needing Flask, matplotlib, python-docx or openpyxl belongs in `gui.py`, `server.py` or
`reporting.py`, and must be imported lazily inside a function if the CLI touches it.

## Good first contributions

| Where | What |
| --- | --- |
| `scanner.py` → `UNAUTHENTICATED_PORT_MAP` | Add a port with its service, severity, weight, reason and fix |
| `scanner.py` → `KNOWN_OUI_VENDORS` | Add a MAC OUI prefix so more devices get attributed |
| `os_check.py` → `check_running_services` | Add a risky-service signature |
| `risk.py` → `analyze_software_risk` | Improve the version heuristics for a common application |
| `threats.py` | Improve a recommendation so it reads like advice, not a label |

## Adding a check

1. Collect in `os_check.py` and return a plain dict — never raise on a missing data source, report
   `UNKNOWN` instead.
2. Add it to the scan record in `scanner.run_single_scan`.
3. Score it in `risk.compute_component_scores`.
4. Give it a threat and a fix in `threats.generate_threats`.
5. Add a test that exercises it from a scan fixture.

Write findings for the person who has to fix them. Every finding should say what was found, why it
matters, and the concrete step to resolve it.

## Pull requests

- Keep `ruff check src tests` and `pytest -q` green.
- Never commit scan output. `scan_results.json`, `*.docx` and friends are gitignored because they
  contain real hostnames, IPs and software inventories.
- If you change the scan record shape, update `examples/sample-scan.json` and the README section
  that documents it.
