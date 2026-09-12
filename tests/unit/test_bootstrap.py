"""Foundation checks that do not start services or load a vision model."""

from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[2]


def test_reusable_package_and_service_entrypoints_import_without_side_effects() -> None:
    modules = (
        "secureedge",
        "apps.aggregator.main",
        "apps.worker.main",
        "apps.dashboard.app",
        "apps.experiment_runner.main",
    )

    for module_name in modules:
        module = importlib.import_module(module_name)
        assert module is not None


def test_project_metadata_targets_supported_python_and_required_stack() -> None:
    with (ROOT / "pyproject.toml").open("rb") as pyproject_file:
        project = tomllib.load(pyproject_file)["project"]

    assert project["requires-python"] == ">=3.11,<3.13"
    dependencies = set(project["dependencies"])
    for name in ("fastapi", "pydantic", "cryptography", "sqlalchemy", "ultralytics"):
        assert any(dependency.startswith(name) for dependency in dependencies)


def test_required_project_directories_and_safe_placeholders_exist() -> None:
    for relative_path in (
        "apps",
        "artifacts",
        "config",
        "data",
        "docs",
        "scripts",
        "secureedge",
        "tests",
        "Makefile",
        "compose.yaml",
        ".env.example",
        ".gitignore",
    ):
        assert (ROOT / relative_path).exists(), relative_path


def test_prohibited_infrastructure_is_not_declared() -> None:
    source = (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()
    for prohibited in ("redis", "kafka", "celery", "kubernetes", "react"):
        assert prohibited not in source
