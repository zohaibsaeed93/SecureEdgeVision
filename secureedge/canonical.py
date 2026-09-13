"""Deterministic byte representation for signed detection-event bodies."""

from __future__ import annotations

import json

from pydantic import TypeAdapter

from secureedge.contracts import DetectionEvent


def canonical_event_bytes(event: DetectionEvent) -> bytes:
    """Return compact, key-sorted UTF-8 JSON for a validated event body.

    The signed content boundary is deliberately limited to ``DetectionEvent``.
    Envelope metadata and signatures are excluded by construction.
    """

    if not isinstance(event, DetectionEvent):
        raise TypeError("event must be a DetectionEvent")

    try:
        # Serialize through the authoritative base schema so subclasses cannot
        # extend or override the signed body boundary.
        json_value = TypeAdapter(DetectionEvent).dump_python(event, mode="json")
        canonical_json = json.dumps(
            json_value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("event contains a value that cannot be canonically serialized") from exc

    return canonical_json.encode("utf-8")


__all__ = ["canonical_event_bytes"]
