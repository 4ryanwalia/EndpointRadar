<div align="center">

<img src="docs/logo.svg" width="88" alt="EndpointRadar">

# EndpointRadar

**Agentless Windows endpoint security posture scanner.**

Find out how exposed a Windows machine is — antivirus, firewall, patching, open ports,
running services and installed software — scored, explained in plain English, and mapped to NIST CSF 2.0.

[![CI](https://github.com/4ryanwalia/EndpointRadar/actions/workflows/ci.yml/badge.svg)](https://github.com/4ryanwalia/EndpointRadar/actions/workflows/ci.yml)
[![Deploy site](https://github.com/4ryanwalia/EndpointRadar/actions/workflows/pages.yml/badge.svg)](https://github.com/4ryanwalia/EndpointRadar/actions/workflows/pages.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-5DA9E9.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-5DA9E9.svg)](https://www.python.org/downloads/)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078D6.svg)](#requirements)

### [**→ Live demo and docs**](https://4ryanwalia.github.io/EndpointRadar/)

</div>

---

```
PS C:\> endpointradar scan

  WIN-DEMO-01  (10.0.0.51)
  Risk score 9   Level MEDIUM
  Risk level is MEDIUM mainly due to: Risky port listening: 445,
  Potentially risky service running: LanmanServer, LanmanWorkstation.

  Top risk drivers
    SMB / Open Ports         3 pts   30.0%  ######
    Services                 3 pts   30.0%  ######
    Patching                 2 pts   20.0%  ####

  Findings (4)
    HIGH     Risky port listening: 445
    HIGH     Potentially risky service running: LanmanServer
    MEDIUM   Potentially risky service running: LanmanWorkstation
    MEDIUM   Unusually low patch count
```

---

## Table of contents

- [Why this exists](#why-this-exists)
- [What it is — and what it is not](#what-it-is--and-what-it-is-not)
- [Quick start](#quick-start)
- [Installation](#installation)
- [The four scan modes](#the-four-scan-modes)
- [CLI reference](#cli-reference)
- [Using it in CI](#using-it-in-ci)
- [How risk is scored](#how-risk-is-scored)
- [Threat analysis and NIST CSF 2.0](#threat-analysis-and-nist-csf-20)
- [Scan record format](#scan-record-format)
- [Desktop dashboard](#desktop-dashboard)
- [Web dashboard and JSON API](#web-dashboard-and-json-api)
- [Word and Excel reports](#word-and-excel-reports)
- [Remote scanning over WinRM](#remote-scanning-over-winrm)
- [Requirements](#requirements)
- [Project structure](#project-structure)
- [Development](#development)
- [Security, privacy and legal](#security-privacy-and-legal)
- [Contributing](#contributing)
- [License](#license)

---

## Why this exists

Commercial EDR tells you **when you are being attacked**. Almost nothing tells a small team
**how easy they would be to attack in the first place.**

Basic endpoint hygiene questions are surprisingly hard to answer across even a handful of machines:

- Is Defender actually running, with real-time protection on — or just installed?
- Is the firewall off on *one* profile, which is all an attacker needs?
- Is SMB (445) listening on a machine that has no business sharing files?
- When was this box genuinely last patched?
- Which of the installed applications are old enough to be a liability?

EndpointRadar answers those questions with **one command**, produces a **number you can track over
time**, and explains every finding in language you can paste into a ticket.

## What it is — and what it is not

| It is | It is not |
| --- | --- |
| A **posture and exposure scanner** | An EDR, an AV, or a real-time monitor |
| **Point-in-time**: you run it, it reports | Always-on. Nothing is installed or left running |
| **Read-only**: it collects and scores | A remediation tool. It never changes settings for you |
| **Transparent**: scoring is plain Python you can read | A model, a heuristic black box, or a cloud service |
| **Offline**: no telemetry, no account, no network calls out | A SaaS product. Nothing leaves your machine |

> The repository was previously named `KINDA-EDR`, which was honest about the gap but said nothing
> about what the tool does. It has never been an EDR, and the current name reflects what it actually is.

## Quick start

```powershell
git clone https://github.com/4ryanwalia/EndpointRadar
cd EndpointRadar
py -m venv .venv
.venv\Scripts\activate
pip install -e .

endpointradar scan
```

That is the whole first run. The scan writes `scan_results.json` into the current directory and
prints the summary above.

Try the rest without touching a network:

```powershell
endpointradar show    -i examples\sample-scan.json      # render the shipped sample
endpointradar threats -i examples\sample-scan.json -v   # NIST CSF analysis with fixes
```

## Installation

The core install has **one dependency** (`psutil`). Everything heavier is an optional extra.

```powershell
pip install -e .                # core: scan, discover, sweep, threats, show
pip install -e ".[remote]"      # + WinRM remote scanning        (pywinrm)
pip install -e ".[report]"      # + Word and Excel reports       (python-docx, openpyxl)
pip install -e ".[gui]"         # + desktop dashboard            (matplotlib, tkinter)
pip install -e ".[web]"         # + web dashboard and JSON API   (Flask)
pip install -e ".[all]"         # everything
pip install -e ".[dev]"         # pytest + ruff, for contributors
```

You can also run it without installing:

```powershell
py -m endpointradar scan
```

## The four scan modes

All four produce the **same record shape** and run through the **same scoring code**, so their
results are directly comparable.

### 1. Local — the deep, authenticated view

Runs every check against the machine you are on. The richest view available: antivirus state,
firewall profiles, hotfix history, listening ports, running services, and the full installed-software
inventory read from the registry.

```powershell
endpointradar scan
endpointradar scan -f json -o box.json
endpointradar scan -f text                # the long, human-readable report
endpointradar scan --fail-on high         # exit code 2 if the host is HIGH or worse
```

Run an elevated terminal for complete service and port visibility. Without elevation the scan still
works, but some checks report `UNKNOWN` rather than guessing.

### 2. Remote — agentless, over WinRM

Stages the **stdlib-only subset** of the scanner onto the target over WinRM, runs it with the
target's own Python, reads the JSON back, and leaves no service or agent behind. The remote host
needs **no pip packages** and no permanent installation.

```powershell
$env:ENDPOINTRADAR_PASSWORD = 'your-password'
endpointradar remote 10.0.0.51 -u Administrator

# or omit the variable and be prompted
endpointradar remote 10.0.0.51 -u ".\Admin"
```

Passwords are read from an environment variable or prompted for interactively — **never** accepted
as a command-line argument, where they would land in shell history and the process table.

See [Remote scanning over WinRM](#remote-scanning-over-winrm) for target setup.

### 3. Discovery — who is on this network?

Sweeps a subnet in parallel, resolves DNS and NetBIOS names, reads the ARP table for MAC addresses,
and classifies each device as a Windows PC, a mobile device, or unknown, using OS hints, hostname
patterns and MAC vendor prefixes. **No credentials at all.**

```powershell
endpointradar discover                      # auto-detects your subnet
endpointradar discover 192.168.1.0/24
endpointradar discover --workers 64 --timeout 300
endpointradar discover --include-offline     # list non-responding addresses too
```

```
  5 device(s) responding on 192.168.1.0/24
  254 addresses probed.

IP            HOSTNAME MAC               VENDOR  TYPE           STATUS
------------- -------- ----------------- ------- -------------- ------
192.168.1.1   -        2C:97:B1:4E:4B:DF -       Unknown Device Online
192.168.1.83  -        80:64:7C:6B:56:EF Samsung Mobile Device  Online
192.168.1.156 WIN-BOX  -                 -       Windows PC     Online
```

### 4. Exposure sweep — the attacker's view

Port-scans every responding device and scores what an **unauthenticated** attacker on the same
network could see. Results are explicitly tagged *limited visibility* so they are never confused
with a full authenticated scan.

```powershell
endpointradar sweep
endpointradar sweep 192.168.1.0/24 -f json -o exposure.json
```

Ports checked and their exposure weight:

| Port | Service | Severity | Weight | Why it matters |
| ---: | --- | --- | ---: | --- |
| 445 | SMB | HIGH | 8 | Wormable-exploit history and a classic lateral-movement path |
| 3389 | RDP | MEDIUM | 5 | Attracts brute-force attempts and remote-access abuse |
| 22 | SSH | MEDIUM | 3 | Exposes a remote administration surface |
| 80 | HTTP | LOW | 2 | May reveal a management page, app, or banner |
| 443 | HTTPS | LOW | 2 | May expose a reachable application or management interface |

## CLI reference

Nine subcommands. Every one that produces data accepts `-f json` and `-o FILE`.
`-q/--quiet` and `--no-color` work on **either side** of the subcommand.

```
endpointradar [-q] [--no-color] [-V] <command> [options]
```

| Command | What it does |
| --- | --- |
| `scan` | Full posture scan of this machine |
| `discover` | Find live devices on a subnet, no credentials |
| `sweep` | Unauthenticated port and exposure scan of a subnet |
| `remote` | Agentless scan of a remote Windows host over WinRM |
| `threats` | NIST CSF 2.0 threat analysis derived from a scan |
| `report` | Word report — fleet summary or per-device threats |
| `show` | Re-read a saved scan without rescanning |
| `dashboard` | Launch the Tkinter desktop dashboard |
| `serve` | Run the read-only web dashboard and JSON API |

<details>
<summary><b>Full options for every command</b></summary>

#### `endpointradar scan`
| Option | Default | Description |
| --- | --- | --- |
| `-f, --format {summary,json,text}` | `summary` | `text` prints the long classic report |
| `-o, --output FILE` | — | Write the result to a file |
| `--no-save` | off | Do not append to `scan_results.json` |
| `--fail-on {never,low,medium,high,critical}` | `never` | Exit `2` when the risk level reaches this threshold |

#### `endpointradar discover [SUBNET]`
| Option | Default | Description |
| --- | --- | --- |
| `SUBNET` | auto-detect | CIDR, e.g. `192.168.1.0/24` |
| `--timeout MS` | `400` | Per-host ping timeout |
| `--workers N` | `32` | Parallel probes |
| `--include-offline` | off | Also list addresses that did not respond |
| `-f, --format {table,json}` | `table` | Output format |

#### `endpointradar sweep [SUBNET]`
| Option | Default | Description |
| --- | --- | --- |
| `SUBNET` | auto-detect | CIDR, e.g. `192.168.1.0/24` |
| `--no-save` | off | Do not append to `unauth_scan_results.json` |
| `-f, --format {table,json}` | `table` | Output format |

#### `endpointradar remote HOST -u USER`
| Option | Default | Description |
| --- | --- | --- |
| `-u, --username` | required | `DOMAIN\user` or `.\localuser` |
| `--password-env VAR` | `ENDPOINTRADAR_PASSWORD` | Env var holding the password; prompts if unset |
| `--timeout S` | `90` | WinRM operation timeout |
| `--no-save` | off | Do not append to `scan_results.json` |
| `--fail-on LEVEL` | `never` | Exit `2` at or above this risk level |

#### `endpointradar threats`
| Option | Default | Description |
| --- | --- | --- |
| `-i, --input FILE` | newest saved scan | Scan JSON to analyse |
| `-d, --device NAME` | — | Pick a host by hostname or IP |
| `--max N` | `10` | Maximum threats to generate |
| `-v, --verbose` | off | Include descriptions and recommended fixes |

#### `endpointradar report [fleet|threat]`
| Option | Default | Description |
| --- | --- | --- |
| `kind` | `fleet` | `fleet` = every saved scan; `threat` = NIST analysis for one device |
| `-i, --input FILE` | saved scans | Source data |
| `-d, --device NAME` | — | Device for the threat report |
| `-o, --output FILE` | auto | Output `.docx` path |

#### `endpointradar show`
| Option | Default | Description |
| --- | --- | --- |
| `-i, --input FILE` | saved scans | Scan JSON to render |
| `-d, --device NAME` | newest | Pick a host by hostname or IP |
| `-a, --all` | off | List every saved scan as a table |
| `--limit N` | `12` | Findings to list |
| `-v, --verbose` | off | Include descriptions and fixes |
| `--fail-on LEVEL` | `never` | Exit `2` at or above this risk level |

#### `endpointradar serve`
| Option | Default | Description |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Bind address |
| `--port` | `5000` | Port |
| `--debug` | off | Flask debug mode |

</details>

### Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Success |
| `1` | Error — bad input, unreachable host, missing file, failed remote scan |
| `2` | The `--fail-on` risk threshold was met or exceeded |
| `130` | Interrupted with Ctrl-C |

### Where files are written

Results land in the directory you run the command from. Override that with an environment variable:

```powershell
$env:ENDPOINTRADAR_DATA_DIR = "C:\scans"
```

| File | Written by |
| --- | --- |
| `scan_results.json` | `scan`, `remote` |
| `unauth_scan_results.json` | `sweep` |
| `report.txt` | `scan -f text` (when run through `os_check` directly) |
| `*.docx` | `report` |

All of these are in `.gitignore` — **they contain real hostnames, IP addresses and software
inventories, and should never be committed.**

## Using it in CI

`--fail-on` turns the scanner into a policy gate. It exits `2` once the risk level reaches your
threshold, so a Windows runner can fail the build when a machine drifts out of policy.

```yaml
- name: Endpoint posture gate
  run: |
    pip install -e .
    endpointradar scan --fail-on high --no-color
  shell: pwsh
```

Machine-readable output for your own tooling:

```powershell
endpointradar scan -f json -o posture.json
endpointradar threats -i posture.json -f json -o threats.json
```

This repository's own [CI workflow](.github/workflows/ci.yml) runs the test suite on Linux and
Windows across Python 3.10–3.13, then performs a real self-scan of the Windows runner and uploads
the result as an artifact.

## How risk is scored

Scoring is deterministic and readable — no model, no cloud call, no hidden weighting. The whole
thing lives in [`risk.py`](src/endpointradar/risk.py) and
[`os_check.py`](src/endpointradar/os_check.py).

**Overall risk level** comes from the total score:

| Score | Level |
| ---: | --- |
| `0–4` | LOW |
| `5–9` | MEDIUM |
| `10–15` | HIGH |
| `16+` | CRITICAL |

**Component scores** break that total down across six areas, each clamped to 0–100, then converted
into percentage contributions so you can see *what is actually driving* the number:

| Component | Points added for |
| --- | --- |
| **Antivirus** | No AV found `+5` · AV disabled `+4` · real-time protection off `+3` |
| **Firewall** | Each profile (Domain / Private / Public) that is OFF `+5` |
| **Patching** | Last patch > 30 days `+4` · > 14 days `+2` · zero hotfixes visible `+3` · patch warning `+2` |
| **SMB / Open Ports** | Each risky listening port, weighted by severity `+1…3` |
| **Services** | Each highlighted risky service, weighted by severity `+1…2` |
| **Third-party Software** | Each high-risk app `+2` · each medium-risk app `+1` |

Unauthenticated (limited-visibility) records are scored **only** on port evidence. A credential-free
result will never claim a machine has no antivirus — it reports that it could not tell.

## Threat analysis and NIST CSF 2.0

`endpointradar threats` interprets an existing scan — it never re-runs checks or modifies the record.
Each finding becomes a threat with a **likelihood (1–5)** and an **impact (1–5)**; their product is
the threat score.

| Score | Threat risk level |
| ---: | --- |
| `1–5` | LOW |
| `6–14` | MEDIUM |
| `15–25` | HIGH |

Categories map to NIST CSF 2.0 functions:

| Category | CSF function |
| --- | --- |
| Firewall, Open Ports, OS / Patching, Services, Third-party Software | **Protect** |
| Antivirus (detection capability disabled or missing) | **Detect** |

```powershell
endpointradar threats -v
```

```
  Threat analysis - WIN-DEMO-01 (5 threats)

RISK   SCORE CSF     CATEGORY             THREAT
------ ----- ------- -------------------- ---------------------------------------
MEDIUM 6     Protect OS / Patching        Potential missing cumulative updates
HIGH   16    Protect Open Ports           SMB exploitation risk (Port 445)
MEDIUM 12    Protect Services             SMB server service exposure
HIGH   16    Protect Third-party Software Outdated software exploitation
MEDIUM 9     Protect Third-party Software Software inventory gaps
```

## Scan record format

Every mode emits the same JSON shape. A full anonymised example ships at
[`examples/sample-scan.json`](examples/sample-scan.json).

```jsonc
{
  "hostname": "WIN-DEMO-01",
  "device_id": "10.0.0.51",
  "target_ip": "10.0.0.51",
  "risk_score": 9,
  "risk_level": "MEDIUM",              // LOW | MEDIUM | HIGH | CRITICAL
  "connection_status": "Local Scan",   // Local Scan | Online | Unauthenticated ...
  "last_scan_at": "2026-09-14T10:15:00+00:00",

  "vulnerabilities": [
    {
      "title": "Risky port listening: 445",
      "severity": "HIGH",              // LOW | MEDIUM | HIGH
      "description": "Plain-English detail, what it means, and why it matters.",
      "fix": "The concrete remediation step."
    }
  ],

  "system_info":  { "hostname": "...", "ip_address": "...", "os_name": "...", "os_version": "..." },
  "antivirus":    { "found": true, "status": "ENABLED", "realtime_protection": true, "products": [] },
  "patches":      { "total_patches": 12, "days_since_last_patch": 9, "patch_warning": "" },
  "firewall":     { "profiles": { "Domain": {"state": "ON"}, "Private": {}, "Public": {} } },
  "open_ports":   { "listening_ports": [], "risky_open": [{ "port": 445, "severity": "HIGH" }] },
  "services":     { "running": [], "highlighted": [{ "name": "LanmanServer", "severity": "HIGH" }] },

  "installed_apps": [{ "name": "...", "version": "...", "publisher": "...", "install_date": "..." }],
  "risky_apps":     [{ "name": "...", "version": "...", "risk_level": "HIGH", "reason": "..." }],

  "device_type": "Windows",            // Windows | Mobile | Unknown
  "device_type_label": "Windows PC",
  "scan_supported": true
}
```

## Desktop dashboard

```powershell
pip install -e ".[gui]"
endpointradar dashboard
```

A dark-themed Tkinter dashboard over the same engine: a device list, risk gauges and matplotlib
charts, per-device drill-down across findings, external exposure, software inventory and live
processes, plus one-click Word and Excel export. Discovery, unauthenticated sweeps and WinRM
scans all run from here with live progress and ETA.

## Web dashboard and JSON API

```powershell
pip install -e ".[web]"
endpointradar serve --port 5000
```

A **read-only** Flask view over `scan_results.json`, useful for presenting results on a second
screen or wiring into something else.

| Route | Returns |
| --- | --- |
| `GET /` | Rendered HTML dashboard |
| `GET /devices` | Every saved device with summary risk data |
| `GET /device/<device_id>` | Full detail, component cards and threat analysis |
| `GET /device/<device_id>/live-applications` | Running-process list for that device |

It binds to `127.0.0.1` by default. It has **no authentication** — do not expose it to a network you
do not control.

## Word and Excel reports

```powershell
pip install -e ".[report]"

endpointradar report fleet  -o fleet-audit.docx      # every saved scan
endpointradar report threat -d WIN-DEMO-01 -o box.docx   # NIST analysis for one device
```

The fleet report covers scope, methodology, per-device findings and a risk summary. The threat
report expands one device's NIST CSF analysis with likelihood, impact and recommendations. Excel
export is available from the desktop dashboard.

## Remote scanning over WinRM

On the **target** machine, as administrator:

```powershell
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "<scanner-ip>" -Force
```

The target also needs **Python 3.10+ on `PATH`** (the runner locates it via the `py -3` launcher).

Then from the scanner:

```powershell
pip install -e ".[remote]"
$env:ENDPOINTRADAR_PASSWORD = 'your-password'
endpointradar remote 10.0.0.51 -u Administrator
```

**What actually happens:** EndpointRadar creates `C:\temp\endpointradar_remote_scan` on the target,
base64-streams the five stdlib-only modules into it, runs a small throwaway runner script, reads
back the resulting JSON, and reports. NTLM is tried first, then Basic. Nothing is installed, no
service is registered, and no scheduled task is created.

> Use HTTPS-configured WinRM on any network you do not fully control. Basic auth over plain HTTP
> transmits credentials in a trivially reversible form.

## Requirements

| | |
| --- | --- |
| **Scanning target** | Windows 10 / 11 / Server. The checks call WMI, PowerShell, `netsh` and the registry |
| **Python** | 3.10 or newer |
| **Core dependency** | `psutil` |
| **Privileges** | Works unelevated; an elevated terminal gives full service and port visibility |
| **Analysis on any OS** | `show`, `threats`, `report` and the test suite run fine on Linux and macOS against saved scan JSON |

## Project structure

```
EndpointRadar/
├── src/endpointradar/
│   ├── cli.py              # the command line interface
│   ├── os_check.py         # local Windows checks (stdlib + psutil only)
│   ├── installed_apps.py   # registry software inventory (stdlib only)
│   ├── risk.py             # component scoring and explanations (stdlib only)
│   ├── scanner.py          # orchestration, discovery, sweep, WinRM staging
│   ├── threats.py          # NIST CSF 2.0 threat analysis
│   ├── reporting.py        # Word report generation
│   ├── gui.py              # Tkinter desktop dashboard
│   ├── server.py           # Flask read-only API
│   └── templates/
├── docs/index.html         # the GitHub Pages site
├── examples/sample-scan.json
├── tests/
└── .github/workflows/      # ci.yml, pages.yml
```

The four modules marked *stdlib only* are exactly the set staged onto remote hosts — that constraint
is why they carry no third-party imports.

## Development

```powershell
pip install -e ".[all,dev]"
pytest -q
ruff check src tests
```

The test suite runs from the checked-in sample scan rather than touching the host, so it passes on
every platform and exercises the same scoring code a real Windows scan uses.

To preview the site locally:

```powershell
cp examples/sample-scan.json docs/sample-scan.json
py -m http.server 8765 --directory docs
```

## Security, privacy and legal

- **Scan only what you are allowed to scan.** `discover` and `sweep` send traffic to every address
  in the range you give them. Use them on networks you own or have **written permission** to test.
- **Nothing leaves your machine.** No telemetry, no accounts, no outbound calls. Results are local
  JSON files.
- **Scan output is sensitive.** It contains hostnames, IP addresses, MAC addresses and a full
  software inventory. Every output file is gitignored by default — keep it that way.
- **Credentials are never arguments.** WinRM passwords come from an environment variable or an
  interactive prompt, so they stay out of shell history and the process list.
- **Findings need human judgement.** Some checks (third-party AV state, patch visibility) can report
  `UNKNOWN` on a locked-down host. The tool says so rather than assuming the worst.

Found a security issue? See [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome — especially new checks, better vendor/OUI coverage, and
non-English remediation text. See [CONTRIBUTING.md](CONTRIBUTING.md).

Good first contributions:

- Add a port to the exposure map in `scanner.py`
- Add a risky-service signature in `os_check.py`
- Improve software-version heuristics in `risk.py`
- Add a MAC OUI prefix to `KNOWN_OUI_VENDORS`

## License

[MIT](LICENSE) © Aryan Walia

---

<div align="center">

**If EndpointRadar saved you some time, a ⭐ helps other people find it.**

[Live demo](https://4ryanwalia.github.io/EndpointRadar/) ·
[Report a bug](https://github.com/4ryanwalia/EndpointRadar/issues) ·
[Star the repo](https://github.com/4ryanwalia/EndpointRadar)

</div>
