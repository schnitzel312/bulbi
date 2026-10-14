"""Tests for auto-detection and starter spec generation."""

import json
from pathlib import Path

from bulbi.init import generate_starter_spec


def test_detect_python_project(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "my-app"\n')
    spec = generate_starter_spec(tmp_path)
    assert 'name = "my-app"' in spec
    assert '"python"' in spec
    assert '"pypi.org"' in spec


def test_detect_python_with_poetry(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (tmp_path / "poetry.lock").write_text("")
    spec = generate_starter_spec(tmp_path)
    assert '"poetry"' in spec


def test_detect_python_with_uv(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
    (tmp_path / "uv.lock").write_text("")
    spec = generate_starter_spec(tmp_path)
    assert '"uv"' in spec


def test_detect_node_project(tmp_path: Path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "my-node-app"}))
    spec = generate_starter_spec(tmp_path)
    assert 'name = "my-node-app"' in spec
    assert '"node"' in spec
    assert '"registry.npmjs.org"' in spec


def test_detect_node_with_pnpm(tmp_path: Path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
    (tmp_path / "pnpm-lock.yaml").write_text("")
    spec = generate_starter_spec(tmp_path)
    assert '"pnpm"' in spec


def test_detect_rust_project(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "my-crate"\n')
    spec = generate_starter_spec(tmp_path)
    assert 'name = "my-crate"' in spec
    assert '"rust"' in spec


def test_detect_go_project(tmp_path: Path):
    (tmp_path / "go.mod").write_text("module example.com/mymod\n")
    spec = generate_starter_spec(tmp_path)
    assert '"go"' in spec
    assert '"proxy.golang.org"' in spec


def test_fallback(tmp_path: Path):
    spec = generate_starter_spec(tmp_path)
    assert '"git"' in spec
    assert '"rg"' in spec
    assert 'spec = "0.1"' in spec


def test_output_is_valid_toml(tmp_path: Path):
    import tomllib

    (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
    spec_text = generate_starter_spec(tmp_path)
    parsed = tomllib.loads(spec_text)
    assert parsed["spec"] == "0.1"
    assert parsed["box"]["name"] == "test"
