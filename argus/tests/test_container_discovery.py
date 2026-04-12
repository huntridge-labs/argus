"""Tests for argus.container.discovery — ContainerTarget, discover, config."""

from pathlib import Path

from argus.container.discovery import (
    ContainerTarget,
    discover_dockerfiles,
    parse_container_config,
)


class TestContainerTarget:
    """Test ContainerTarget dataclass basics."""

    def test_minimal_target(self):
        target = ContainerTarget(name="app", image_ref="app:latest")
        assert target.name == "app"
        assert target.image_ref == "app:latest"
        assert target.dockerfile is None
        assert target.context is None

    def test_target_with_dockerfile(self, tmp_path):
        df = tmp_path / "Dockerfile"
        target = ContainerTarget(
            name="web",
            image_ref="web:scan",
            dockerfile=df,
            context=tmp_path,
        )
        assert target.dockerfile == df
        assert target.context == tmp_path


class TestDiscoverDockerfiles:
    """Test discover_dockerfiles with various naming patterns."""

    def test_finds_standard_dockerfile(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM alpine")
        targets = discover_dockerfiles([str(tmp_path)])
        assert len(targets) == 1
        assert targets[0].dockerfile == tmp_path / "Dockerfile"

    def test_finds_dockerfile_dot_variant(self, tmp_path):
        (tmp_path / "Dockerfile.worker").write_text("FROM alpine")
        targets = discover_dockerfiles([str(tmp_path)])
        assert len(targets) == 1
        assert targets[0].name == "worker"

    def test_finds_suffix_variant(self, tmp_path):
        (tmp_path / "api.Dockerfile").write_text("FROM alpine")
        targets = discover_dockerfiles([str(tmp_path)])
        assert len(targets) == 1
        assert targets[0].name == "api"

    def test_finds_multiple_variants(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM alpine")
        (tmp_path / "Dockerfile.worker").write_text("FROM node")
        (tmp_path / "api.Dockerfile").write_text("FROM python")
        targets = discover_dockerfiles([str(tmp_path)])
        names = {t.name for t in targets}
        assert "worker" in names
        assert "api" in names
        assert len(targets) == 3

    def test_nested_dockerfile(self, tmp_path):
        docker_dir = tmp_path / "docker"
        docker_dir.mkdir()
        (docker_dir / "Dockerfile.web").write_text("FROM nginx")
        targets = discover_dockerfiles([str(tmp_path)])
        assert len(targets) == 1
        assert targets[0].name == "web"

    def test_deduplicates_same_file(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM alpine")
        targets = discover_dockerfiles([str(tmp_path), str(tmp_path)])
        assert len(targets) == 1

    def test_nonexistent_path_returns_empty(self, tmp_path):
        targets = discover_dockerfiles([str(tmp_path / "no-such-dir")])
        assert targets == []

    def test_empty_search_paths(self):
        targets = discover_dockerfiles([])
        assert targets == []

    def test_ignores_non_dockerfiles(self, tmp_path):
        (tmp_path / "README.md").write_text("# hi")
        (tmp_path / "app.py").write_text("print('hi')")
        targets = discover_dockerfiles([str(tmp_path)])
        assert targets == []

    def test_image_ref_includes_argus_scan_tag(self, tmp_path):
        (tmp_path / "Dockerfile.worker").write_text("FROM alpine")
        targets = discover_dockerfiles([str(tmp_path)])
        assert targets[0].image_ref == "worker:argus-scan"

    def test_context_is_parent_of_dockerfile(self, tmp_path):
        sub = tmp_path / "services" / "web"
        sub.mkdir(parents=True)
        (sub / "Dockerfile").write_text("FROM alpine")
        targets = discover_dockerfiles([str(tmp_path)])
        assert len(targets) == 1
        assert targets[0].context == sub


class TestParseContainerConfig:
    """Test parse_container_config with explicit images and discovery."""

    def test_explicit_images(self):
        config = {
            "containers": {
                "images": [
                    {"image": "myapp:latest", "dockerfile": "Dockerfile"},
                    {"image": "worker:1.0"},
                ],
            },
        }
        targets = parse_container_config(config)
        assert len(targets) == 2
        assert targets[0].image_ref == "myapp:latest"
        assert targets[0].name == "myapp"
        assert targets[0].dockerfile == Path("Dockerfile")
        assert targets[1].image_ref == "worker:1.0"
        assert targets[1].dockerfile is None

    def test_image_with_context(self):
        config = {
            "containers": {
                "images": [
                    {
                        "image": "myapp:latest",
                        "dockerfile": "docker/Dockerfile",
                        "context": ".",
                    },
                ],
            },
        }
        targets = parse_container_config(config)
        assert targets[0].context == Path(".")

    def test_discover_true(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM alpine")
        config = {
            "containers": {
                "discover": True,
                "search_paths": [str(tmp_path)],
            },
        }
        targets = parse_container_config(config)
        assert len(targets) == 1

    def test_discover_skips_duplicates_of_explicit(self, tmp_path):
        """Discovered targets that match an explicit name are skipped."""
        (tmp_path / "Dockerfile.worker").write_text("FROM alpine")
        config = {
            "containers": {
                "images": [
                    {"image": "worker:custom"},
                ],
                "discover": True,
                "search_paths": [str(tmp_path)],
            },
        }
        targets = parse_container_config(config)
        assert len(targets) == 1
        assert targets[0].image_ref == "worker:custom"

    def test_empty_config_returns_empty(self):
        targets = parse_container_config({})
        assert targets == []

    def test_containers_not_dict_returns_empty(self):
        targets = parse_container_config({"containers": "invalid"})
        assert targets == []

    def test_skips_invalid_image_entries(self):
        config = {
            "containers": {
                "images": [
                    "not-a-dict",
                    {"image": ""},
                    {"image": "valid:latest"},
                ],
            },
        }
        targets = parse_container_config(config)
        assert len(targets) == 1
        assert targets[0].image_ref == "valid:latest"

    def test_name_derives_from_image_ref(self):
        config = {
            "containers": {
                "images": [
                    {"image": "org/myapp:v2"},
                ],
            },
        }
        targets = parse_container_config(config)
        assert targets[0].name == "org-myapp"
