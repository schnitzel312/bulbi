"""Tests for project auto-detection and starter spec rendering."""

import json
import tomllib
from pathlib import Path

from bulbi.agents import ClaudeAgent, CodexAgent, NoCredentialProvider
from bulbi.detection import (
    DetectedProject,
    DetectorRegistry,
    GoDetector,
    NodeDetector,
    PythonDetector,
    RustDetector,
    StarterSpecRenderer,
)


def generate_starter_spec(project_root: Path) -> str:
    project = DetectorRegistry.builtin().detect(project_root)
    return StarterSpecRenderer(ClaudeAgent(credentials=NoCredentialProvider())).render(project)


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
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
    spec_text = generate_starter_spec(tmp_path)
    parsed = tomllib.loads(spec_text)
    assert parsed["spec"] == "0.1"
    assert parsed["box"]["name"] == "test"


def test_python_detector_details(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "app"\n')
    (tmp_path / "uv.lock").write_text("")
    assert PythonDetector().detect(tmp_path) == DetectedProject(
        name="app",
        language="python",
        tools=("python", "git", "rg", "uv"),
        registry_domains=("pypi.org", "files.pythonhosted.org"),
    )


def test_python_detector_reads_poetry_name(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text('[tool.poetry]\nname = "poetic"\n')
    assert PythonDetector().detect(tmp_path).name == "poetic"


def test_malformed_manifests_fall_back_to_directory_name(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("not = = toml")
    (tmp_path / "package.json").write_text("[1, 2]")
    (tmp_path / "Cargo.toml").write_text("[[[")
    for detector in (PythonDetector(), NodeDetector(), RustDetector()):
        assert detector.detect(tmp_path).name == tmp_path.name


def test_node_detector_lockfiles(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "yarn.lock").write_text("")
    assert NodeDetector().detect(tmp_path).tools == ("node", "git", "rg", "yarn")


def test_rust_and_go_tools(tmp_path: Path):
    assert RustDetector().detect(tmp_path).tools == ("rust", "cargo", "git", "rg")
    assert GoDetector().detect(tmp_path).tools == ("go", "git", "rg")


def test_registry_prefers_python_over_node(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("")
    (tmp_path / "package.json").write_text("{}")
    assert DetectorRegistry.builtin().detect(tmp_path).language == "python"


def test_custom_registry_order_wins(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("")
    (tmp_path / "package.json").write_text("{}")
    registry = DetectorRegistry([NodeDetector(), PythonDetector()])
    assert registry.detect(tmp_path).language == "node"


def test_fallback_project(tmp_path: Path):
    project = DetectorRegistry([]).detect(tmp_path)
    assert project == DetectedProject(name=tmp_path.name, language=None, tools=("git", "rg"))


def test_renderer_uses_agent_name_and_domains(tmp_path: Path):
    project = DetectedProject(name='we"ird', language=None, tools=("git",))
    parsed = tomllib.loads(StarterSpecRenderer(CodexAgent()).render(project))
    assert parsed["box"] == {"name": 'we"ird', "agent": "codex"}
    assert parsed["network"]["allow"] == ["api.openai.com"]


def test_setup_comment_says_first_container_start(tmp_path: Path):
    spec = generate_starter_spec(tmp_path)
    assert "first container start" in spec
    assert "when the image is built" not in spec
