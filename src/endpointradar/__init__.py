"""EndpointRadar - agentless Windows endpoint security posture scanner.

This package is deliberately import-light: nothing here pulls in Flask,
matplotlib, python-docx or tkinter, because the stdlib-only subset of these
modules gets staged onto remote hosts that have no packages installed.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
