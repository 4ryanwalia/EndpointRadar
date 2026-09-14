"""Allow `python -m endpointradar` to behave exactly like the installed command."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
