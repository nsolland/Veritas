"""CLI for Veritas receipt verification."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from veritas.worm import WORMLog


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="veritas-verify",
        description="Verify a Veritas WORM receipt ledger.",
    )
    parser.add_argument("ledger", help="Path to a newline-delimited JSON ledger")
    args = parser.parse_args(argv)
    try:
        log = WORMLog.load(args.ledger)
    except FileNotFoundError:
        print(f"ledger not found: {args.ledger}", file=sys.stderr)
        return 2
    if log.verify():
        print(f"VERITAS OK: {len(log.read_all())} entries, chain intact.")
        return 0
    print("VERITAS FAILED: chain integrity broken.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
