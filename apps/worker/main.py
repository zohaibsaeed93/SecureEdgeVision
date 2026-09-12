"""Edge worker entry point reserved for the local vision pipeline task."""

from __future__ import annotations


def main() -> int:
    """Return a non-zero status until the privacy worker is implemented."""

    print("SecureEdgeVision worker is not implemented at the foundation stage.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
