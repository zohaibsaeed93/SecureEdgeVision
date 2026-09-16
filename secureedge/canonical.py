"""Deterministic byte representation for signed detection-event bodies."""

from __future__ import annotations

import json

from pydantic import TypeAdapter

import secureedge.contracts as contract_models
from secureedge.contracts import DetectionEvent


def canonical_event_bytes(event: DetectionEvent) -> bytes:
    """Return compact, key-sorted UTF-8 JSON for a validated event body.

    The signed content boundary is deliberately limited to ``DetectionEvent``.
    Envelope metadata and signatures are excluded by construction.
    """

    event_model = contract_models.DetectionEvent
    event_type = type(event)
    if isinstance(event, event_model):
        validated_event = event
    elif (
        event_type.__module__ == event_model.__module__
        and event_type.__qualname__ == event_model.__qualname__
    ):
        try:
            validated_event = event_model.model_validate(event.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise TypeError("event must be a DetectionEvent") from exc
    else:
        raise TypeError("event must be a DetectionEvent")

    try:
        # Serialize through the authoritative base schema so subclasses cannot
        # extend or override the signed body boundary.
        json_value = TypeAdapter(event_model).dump_python(validated_event, mode="json")
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
