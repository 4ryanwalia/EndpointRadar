# Security Policy

## Supported versions

EndpointRadar is developed on `main`. Fixes land there; please test against the latest commit
before reporting.

## Reporting a vulnerability

Please **do not open a public issue** for a security vulnerability.

Use GitHub's private reporting instead:
[Report a vulnerability](https://github.com/4ryanwalia/EndpointRadar/security/advisories/new)

Include what you can: affected version or commit, reproduction steps, and the impact you see.
You can expect an acknowledgement within a few days.

## Scope

In scope:

- Command or PowerShell injection through subnet, hostname, username or file input
- Credential exposure — passwords reaching argv, logs, shell history or scan output
- Path traversal or unsafe writes in the WinRM staging flow
- Anything that makes the tool harm the machine it is auditing

Out of scope:

- The Flask server (`endpointradar serve`) being unauthenticated. This is documented and intentional;
  it binds to `127.0.0.1` and is meant for local viewing only.
- Findings you disagree with. Scoring debates belong in a normal issue — open one, they are welcome.
- Running the tool against systems you do not have permission to scan.

## Using this tool responsibly

`discover` and `sweep` send traffic to every address in the range given. Scan only networks you own
or have written authorisation to test. Scan output contains hostnames, IP addresses, MAC addresses
and full software inventories — treat those files as sensitive and keep them out of version control.
