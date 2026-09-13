from __future__ import annotations

import importlib
import os
import stat
from pathlib import Path

import pytest
from scripts import generate_node_keys
from secureedge.crypto import encode_public_key, load_private_key


def test_key_generation_writes_expected_pair_and_restrictive_permissions(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "secrets"
    paths = generate_node_keys.generate_node_key_files("edge-1", output_dir)

    private_pem = paths.private_key.read_bytes()
    public_b64 = paths.public_key.read_text(encoding="ascii")
    private_key = load_private_key(private_pem)

    assert paths.private_key == output_dir / "edge-1.key"
    assert paths.public_key == output_dir / "edge-1.pub"
    assert paths.public_key_b64 == public_b64
    assert public_b64 == encode_public_key(private_key.public_key())
    assert "\n" not in public_b64
    assert "PRIVATE KEY" not in public_b64

    if os.name == "posix":
        assert stat.S_IMODE(output_dir.stat().st_mode) == 0o700
        assert stat.S_IMODE(paths.private_key.stat().st_mode) == 0o600
        assert stat.S_IMODE(paths.public_key.stat().st_mode) == 0o600


def test_cli_reports_public_material_but_never_private_pem(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert generate_node_keys.main(["--node-id", "edge-1", "--output-dir", str(tmp_path)]) == 0
    captured = capsys.readouterr()

    assert "private_key:" in captured.out
    assert "public_key:" in captured.out
    assert "public_key_b64:" in captured.out
    assert "BEGIN PRIVATE KEY" not in captured.out
    assert "BEGIN PRIVATE KEY" not in captured.err


@pytest.mark.parametrize("node_id", ["", "../edge-1", "edge/one", r"edge\one", " edge-1", "edge 1"])
def test_node_id_must_match_existing_safe_identifier_contract(
    node_id: str,
    tmp_path: Path,
) -> None:
    with pytest.raises(generate_node_keys.KeyGenerationError, match="node ID"):
        generate_node_keys.generate_node_key_files(node_id, tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_second_invocation_refuses_to_overwrite_both_files(tmp_path: Path) -> None:
    paths = generate_node_keys.generate_node_key_files("edge-1", tmp_path)
    private_before = paths.private_key.read_bytes()
    public_before = paths.public_key.read_bytes()

    with pytest.raises(generate_node_keys.KeyGenerationError, match="overwrite"):
        generate_node_keys.generate_node_key_files("edge-1", tmp_path)

    assert paths.private_key.read_bytes() == private_before
    assert paths.public_key.read_bytes() == public_before


def test_existing_public_target_prevents_private_file_creation(tmp_path: Path) -> None:
    public_path = tmp_path / "edge-1.pub"
    public_path.write_text("existing", encoding="ascii")

    with pytest.raises(generate_node_keys.KeyGenerationError, match="overwrite"):
        generate_node_keys.generate_node_key_files("edge-1", tmp_path)

    assert public_path.read_text(encoding="ascii") == "existing"
    assert not (tmp_path / "edge-1.key").exists()


def test_preexisting_symlink_target_is_rejected_without_following_it(tmp_path: Path) -> None:
    target = tmp_path / "sentinel"
    target.write_text("do not change", encoding="ascii")
    link = tmp_path / "edge-1.key"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symbolic links are unavailable on this platform")

    with pytest.raises(generate_node_keys.KeyGenerationError, match="overwrite"):
        generate_node_keys.generate_node_key_files("edge-1", tmp_path)

    assert target.read_text(encoding="ascii") == "do not change"
    assert link.is_symlink()


def test_failed_second_file_write_cleans_only_new_first_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_write_exclusive = generate_node_keys._write_exclusive
    calls = 0

    def fail_second(path: Path, data: bytes, created: list[tuple[Path, int, int]]) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise generate_node_keys.KeyGenerationError("simulated second-file failure")
        real_write_exclusive(path, data, created)

    monkeypatch.setattr(generate_node_keys, "_write_exclusive", fail_second)
    with pytest.raises(generate_node_keys.KeyGenerationError, match="second-file"):
        generate_node_keys.generate_node_key_files("edge-1", tmp_path)

    assert not (tmp_path / "edge-1.key").exists()
    assert not (tmp_path / "edge-1.pub").exists()


def test_key_script_import_is_side_effect_free(monkeypatch: pytest.MonkeyPatch) -> None:
    import pathlib
    import socket
    import sqlite3

    def fail(*args: object, **kwargs: object) -> None:
        raise AssertionError("key script import performed an external side effect")

    monkeypatch.setattr(pathlib.Path, "read_text", fail)
    monkeypatch.setattr(pathlib.Path, "write_bytes", fail)
    monkeypatch.setattr(socket, "socket", fail)
    monkeypatch.setattr(sqlite3, "connect", fail)

    importlib.reload(generate_node_keys)
