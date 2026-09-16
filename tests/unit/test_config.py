from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from secureedge.config import ConfigurationError, load_settings

ROOT = Path(__file__).parents[2]
SYSTEM_CONFIG = ROOT / "config" / "system.yaml"


def _write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "system.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_loads_exact_starting_values() -> None:
    settings = load_settings(SYSTEM_CONFIG)

    assert settings.mode == "privacy"
    assert str(settings.aggregator_url) == "http://aggregator:8000/"
    assert settings.security.max_clock_skew_seconds == 30
    assert settings.security.nonce_ttl_seconds == 300
    assert settings.security.max_request_bytes == 262_144
    assert settings.vision.model == "yolo26n.pt"
    assert settings.vision.device == "auto"
    assert settings.vision.image_size == 640
    assert settings.vision.confidence == 0.25
    assert settings.vision.frame_sample_fps == 2
    assert settings.transport.request_timeout_seconds == 5
    assert settings.transport.heartbeat_interval_seconds == 10
    assert settings.consensus.policy == "trust_weighted"
    assert settings.consensus.iou_threshold == 0.50
    assert settings.consensus.accept_threshold == 0.60
    assert settings.consensus.alpha == 0.85
    assert settings.consensus.trust_min == 0.05


def test_applies_allowlisted_environment_overrides() -> None:
    settings = load_settings(
        SYSTEM_CONFIG,
        {
            "SEV_CONFIG__AGGREGATOR_URL": "https://collector.example.test:8443",
            "SEV_CONFIG__SECURITY__MAX_CLOCK_SKEW_SECONDS": "45",
            "SEV_CONFIG__VISION__CONFIDENCE": "0.4",
            "SEV_CONFIG__VISION__FRAME_SAMPLE_FPS": "3.5",
            "SEV_CONFIG__TRANSPORT__REQUEST_TIMEOUT_SECONDS": "7.5",
            "SEV_CONFIG__TRANSPORT__HEARTBEAT_INTERVAL_SECONDS": "15",
            "SEV_NODE_ID": "ignored-by-system-settings",
        },
    )

    assert str(settings.aggregator_url) == "https://collector.example.test:8443/"
    assert settings.security.max_clock_skew_seconds == 45
    assert settings.vision.confidence == 0.4
    assert settings.vision.frame_sample_fps == 3.5
    assert settings.transport.request_timeout_seconds == 7.5
    assert settings.transport.heartbeat_interval_seconds == 15


@pytest.mark.parametrize(
    ("override", "value", "field"),
    [
        ("SEV_CONFIG__MODE", "benchmark", "mode"),
        ("SEV_CONFIG__AGGREGATOR_URL", "collector:8000", "aggregator_url"),
        ("SEV_CONFIG__SECURITY__NONCE_TTL_SECONDS", "0", "security.nonce_ttl_seconds"),
        ("SEV_CONFIG__SECURITY__MAX_REQUEST_BYTES", "100", "security.max_request_bytes"),
        ("SEV_CONFIG__VISION__MODEL", "yolo.pt", "vision.model"),
        ("SEV_CONFIG__VISION__IMAGE_SIZE", "8", "vision.image_size"),
        ("SEV_CONFIG__VISION__CONFIDENCE", "1.1", "vision.confidence"),
        ("SEV_CONFIG__VISION__FRAME_SAMPLE_FPS", "0", "vision.frame_sample_fps"),
        (
            "SEV_CONFIG__TRANSPORT__REQUEST_TIMEOUT_SECONDS",
            "0",
            "transport.request_timeout_seconds",
        ),
        (
            "SEV_CONFIG__TRANSPORT__HEARTBEAT_INTERVAL_SECONDS",
            "3601",
            "transport.heartbeat_interval_seconds",
        ),
        ("SEV_CONFIG__CONSENSUS__IOU_THRESHOLD", "-0.1", "consensus.iou_threshold"),
        ("SEV_CONFIG__CONSENSUS__ALPHA", "1.1", "consensus.alpha"),
    ],
)
def test_rejects_invalid_values(override: str, value: str, field: str) -> None:
    with pytest.raises(ConfigurationError, match=field.replace(".", r"\.")):
        load_settings(SYSTEM_CONFIG, {override: value})


def test_reports_malformed_override_and_unknown_override() -> None:
    with pytest.raises(ConfigurationError, match="VISION__IMAGE_SIZE.*vision.image_size"):
        load_settings(SYSTEM_CONFIG, {"SEV_CONFIG__VISION__IMAGE_SIZE": "large"})

    with pytest.raises(ConfigurationError, match="SEV_CONFIG__PRIVATE_KEY"):
        load_settings(SYSTEM_CONFIG, {"SEV_CONFIG__PRIVATE_KEY": "do-not-accept"})


def test_rejects_url_credentials_and_unknown_yaml_fields(tmp_path: Path) -> None:
    content = SYSTEM_CONFIG.read_text(encoding="utf-8")
    credentialed = _write_config(
        tmp_path,
        content.replace("http://aggregator:8000", "http://user:secret@aggregator:8000"),
    )
    with pytest.raises(ConfigurationError, match="aggregator_url.*credentials"):
        load_settings(credentialed)

    for unsafe_url in (
        "http://aggregator:8000/base",
        "http://aggregator:8000?token=value",
        "http://aggregator:8000#fragment",
    ):
        unsafe = _write_config(
            tmp_path,
            content.replace("http://aggregator:8000", unsafe_url),
        )
        with pytest.raises(ConfigurationError, match="aggregator_url"):
            load_settings(unsafe)

    extra = _write_config(tmp_path, content + "\nprivate_key: forbidden\n")
    with pytest.raises(ConfigurationError, match="private_key.*Extra inputs"):
        load_settings(extra)


def test_reports_missing_malformed_and_non_mapping_yaml(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="cannot read system configuration"):
        load_settings(tmp_path / "missing.yaml")

    malformed = _write_config(tmp_path, "mode: [privacy\n")
    with pytest.raises(ConfigurationError, match="malformed YAML"):
        load_settings(malformed)

    sequence = _write_config(tmp_path, "- privacy\n")
    with pytest.raises(ConfigurationError, match="top-level value must be a mapping"):
        load_settings(sequence)


def test_missing_nested_mapping_has_actionable_field_path(tmp_path: Path) -> None:
    incomplete = _write_config(tmp_path, "mode: privacy\naggregator_url: http://localhost:8000\n")
    with pytest.raises(ConfigurationError, match="security: Field required"):
        load_settings(incomplete)


def test_import_has_no_io_or_environment_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    import pathlib

    def fail_read(*args: object, **kwargs: object) -> str:
        raise AssertionError("configuration module import performed file I/O")

    monkeypatch.setattr(pathlib.Path, "read_text", fail_read)
    module = importlib.import_module("secureedge.config")
    importlib.reload(module)
