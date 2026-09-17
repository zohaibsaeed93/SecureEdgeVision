"""Explicit runtime construction for the Milestone 1 aggregator."""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import cast

import uvicorn
from pydantic import ValidationError
from secureedge.config import ConfigurationError, SecuritySettings, load_settings
from secureedge.contracts import NodeRegistration
from secureedge.persistence import (
    PersistenceError,
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
    seed_node_registry,
)
from secureedge.security import EventSecurityConfigurationError, ReplayFreshnessPolicy

from apps.aggregator.api import create_app


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the SecureEdgeVision aggregator")
    parser.add_argument("--config", required=True)
    parser.add_argument("--database-url", required=True)
    parser.add_argument(
        "--node-public-key",
        action="append",
        default=[],
        metavar="NODE_ID=PUBLIC_KEY_B64",
        help="seed one registered public node identity; may be repeated",
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    return parser


def _registrations(values: Sequence[str]) -> list[NodeRegistration]:
    registrations: list[NodeRegistration] = []
    for value in values:
        node_id, separator, public_key_b64 = value.partition("=")
        if not separator:
            raise ValueError("node registration must use NODE_ID=PUBLIC_KEY_B64")
        registrations.append(
            NodeRegistration(node_id=node_id, public_key_b64=public_key_b64)
        )
    return registrations


def _runtime_security_settings(value: object) -> SecuritySettings:
    """Copy validated settings across explicit runtime construction boundaries."""

    value_type = type(value)
    if not (
        isinstance(value, SecuritySettings)
        or (
            value_type.__module__ == SecuritySettings.__module__
            and value_type.__qualname__ == SecuritySettings.__qualname__
        )
    ):
        raise ValueError("security settings are invalid")
    try:
        payload = cast(SecuritySettings, value).model_dump(
            mode="python",
            warnings="error",
        )
        return SecuritySettings.model_validate(payload, strict=True)
    except (AttributeError, TypeError, ValidationError, ValueError):
        raise ValueError("security settings are invalid") from None


def main(argv: Sequence[str] | None = None) -> int:
    """Initialize explicit local dependencies, then run one Uvicorn worker."""

    args = _parser().parse_args(argv)
    engine = None
    try:
        settings = load_settings(args.config, environ=os.environ)
        security_settings = _runtime_security_settings(settings.security)
        registrations = _registrations(args.node_public_key)
        engine = create_sqlite_engine(args.database_url)
        initialize_database(engine)
        session_factory = create_session_factory(engine)
        if registrations:
            seed_node_registry(
                session_factory,
                registrations,
                registered_at_utc=datetime.now(UTC),
            )
        replay_policy = ReplayFreshnessPolicy(security_settings)
        app = create_app(
            security_settings=security_settings,
            session_factory=session_factory,
            replay_policy=replay_policy,
        )
        uvicorn.run(app, host=args.host, port=args.port, workers=1)
    except (
        ConfigurationError,
        EventSecurityConfigurationError,
        PersistenceError,
        ValidationError,
        TypeError,
        ValueError,
    ):
        print("SecureEdgeVision aggregator startup failed.")
        return 2
    finally:
        if engine is not None:
            engine.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
