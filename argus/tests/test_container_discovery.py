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


class TestParseContainerConfigUnwrappedShape:
    """Regression: ``parse_container_config`` must accept the inner-mapping
    shape returned by the CLI's ``_load_container_config``.

    The bug: dispatch path for ``argus scan container --config argus.yml``
    extracted just the inner ``containers:`` mapping (matching the
    rest of the engine's top-level key access — ``images``,
    ``search_paths``, ``scanners``) and passed that to
    ``ContainerEngine``. The parser's strict ``config.get("containers")``
    lookup found nothing and the scan dropped all config-defined
    targets with a "No container targets found" error despite a
    well-formed config.
    """

    def test_unwrapped_shape_resolves_explicit_images(self):
        # The user's exact repro from the bug report — top-level
        # ``containers:`` block in argus.yml with one image entry,
        # extracted into the inner-mapping shape by the CLI before
        # being passed to the engine.
        config = {
            "images": [
                {
                    "image": "docker:argus-scan",
                    "dockerfile": "docker/Dockerfile",
                    "context": ".",
                },
            ],
        }
        targets = parse_container_config(config)
        assert len(targets) == 1
        target = targets[0]
        assert target.image_ref == "docker:argus-scan"
        assert target.dockerfile == Path("docker/Dockerfile")
        assert target.context == Path(".")

    def test_unwrapped_shape_with_discover(self, tmp_path):
        # Verifies the unwrapped path also honors ``discover: true`` +
        # ``search_paths``, not just explicit images. Combined with
        # the test above this covers both target sources end-to-end.
        (tmp_path / "Dockerfile").write_text("FROM scratch\n")
        config = {
            "discover": True,
            "search_paths": [str(tmp_path)],
        }
        targets = parse_container_config(config)
        assert len(targets) == 1
        assert targets[0].dockerfile == (tmp_path / "Dockerfile").resolve()

    def test_wrapped_shape_takes_precedence_when_both_keys_present(self):
        # Defensive: if a config has BOTH a top-level ``containers:``
        # mapping AND top-level ``images``/``discover`` keys, prefer
        # the wrapped form to match the historical contract. The
        # unwrapped fallback only fires when ``containers`` isn't a
        # mapping at the top level.
        config = {
            "containers": {
                "images": [{"image": "wrapped:1.0"}],
            },
            "images": [{"image": "unwrapped:1.0"}],
        }
        targets = parse_container_config(config)
        assert len(targets) == 1
        assert targets[0].image_ref == "wrapped:1.0"

    def test_unwrapped_with_digest_pin_preserved(self):
        # Digest-pinned refs are the recommended form (per
        # argus.example.yml). Round-trip through the unwrapped path
        # without losing the @sha256: suffix.
        ref = (
            "ghcr.io/myorg/app:1.0@sha256:"
            "f1e2d3c4b5a6f7e8d9c0b1a2c3d4e5f6"
            "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2"
        )
        targets = parse_container_config({"images": [{"image": ref}]})
        assert len(targets) == 1
        assert targets[0].image_ref == ref


class TestGrypePrefixCollisionWarning:
    """Image refs that collide with Grype's CLI source-scheme prefixes
    (``docker:``, ``podman:``, ``registry:``, etc.) get mis-parsed by
    Grype as scheme requests. Argus warns at config-load so users see
    the issue before the build runs."""

    def test_warn_on_docker_prefix(self):
        from argus.container.discovery import warn_on_grype_prefix_collision
        msg = warn_on_grype_prefix_collision("docker:argus-scan")
        assert msg is not None
        # Names the actual prefix and explains the misparse.
        assert "docker:" in msg
        assert "scheme" in msg.lower() or "mis-parse" in msg.lower()
        # Suggests a rename path.
        assert "Rename" in msg or "rename" in msg

    def test_warn_on_each_reserved_prefix(self):
        from argus.container.discovery import (
            GRYPE_RESERVED_PREFIXES,
            warn_on_grype_prefix_collision,
        )
        # Sanity: the documented reserved-prefix list is non-empty
        # and every entry triggers the warning.
        assert len(GRYPE_RESERVED_PREFIXES) >= 5
        for prefix in GRYPE_RESERVED_PREFIXES:
            ref = f"{prefix}myapp"
            msg = warn_on_grype_prefix_collision(ref)
            assert msg is not None, f"expected warning for {ref!r}"

    def test_no_warning_for_clean_refs(self):
        from argus.container.discovery import warn_on_grype_prefix_collision
        for ref in (
            "myapp:dev",
            "argus-app:dev",
            "myorg/app:1.0",
            "ghcr.io/myorg/app:1.0",
            "alpine:3.20@sha256:abc123",
        ):
            assert warn_on_grype_prefix_collision(ref) is None, (
                f"unexpected warning for {ref!r}"
            )

    def test_warning_logged_during_parse(self, caplog):
        # Integration: parse_container_config logs the warning when
        # an image ref collides. caplog captures it via the
        # ``argus.container`` logger.
        import logging
        caplog.set_level(logging.WARNING, logger="argus.container")

        config = {
            "images": [
                {"image": "docker:argus-scan", "dockerfile": "Dockerfile"},
            ],
        }
        targets = parse_container_config(config)
        # Target is still resolved — the warning is non-fatal.
        assert len(targets) == 1
        # And the warning surfaced.
        assert any(
            "docker:argus-scan" in record.message
            and "scheme" in record.message.lower()
            for record in caplog.records
        ), "expected a Grype prefix-collision warning during parse"

    def test_non_string_image_ref_does_not_crash(self):
        from argus.container.discovery import warn_on_grype_prefix_collision
        # Defensive — never raise on malformed input.
        assert warn_on_grype_prefix_collision(None) is None  # type: ignore[arg-type]
        assert warn_on_grype_prefix_collision(123) is None  # type: ignore[arg-type]
