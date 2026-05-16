"""Tests for docsite.builder — main build orchestration."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from docsite import config
from docsite.builder import build


@pytest.fixture(autouse=True)
def _reset_config():
    """Reset config state between tests."""
    config.CATEGORY_LABELS = {}
    config.CATEGORY_ICONS = {}
    config.EXCLUDED_ACTIONS = set()
    config.EXCLUDED_WORKFLOWS = set()
    config.EXCLUDED_GUIDE_DIRS = set()
    config.GITHUB_BLOB = ""
    config.GROUP_LABELS = {}
    yield


class TestBuild:
    """Tests for build()."""

    def test_creates_output_directory(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        assert out.exists()
        assert (out / "docs").exists()

    def test_generates_mkdocs_yml(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        mkdocs_yml = out / "mkdocs.yml"
        assert mkdocs_yml.exists()
        content = mkdocs_yml.read_text()
        assert "site_name" in content

    def test_generates_index_page(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        assert (out / "docs" / "index.md").exists()

    def test_generates_action_pages(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        actions_dir = out / "docs" / "actions"
        assert actions_dir.exists()
        assert (actions_dir / "index.md").exists()
        assert (actions_dir / "scanner-bandit.md").exists()
        assert (actions_dir / "scanner-gitleaks.md").exists()

    def test_excludes_excluded_actions(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        assert not (out / "docs" / "actions" / "comment-pr.md").exists()

    def test_generates_workflow_pages(
        self, tmp_repo: Path, tmp_path: Path, sample_workflow: Path,
    ):
        out = tmp_path / "output"
        build(tmp_repo, out)
        wf_dir = out / "docs" / "workflows"
        assert wf_dir.exists()
        assert (wf_dir / "index.md").exists()
        assert (wf_dir / "security-scan.md").exists()

    def test_copies_custom_css(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        assert (out / "docs" / "assets" / "custom.css").exists()

    def test_copies_images(self, tmp_repo: Path, tmp_path: Path):
        (tmp_repo / "img" / "logo.png").write_text("fake-image")
        out = tmp_path / "output"
        build(tmp_repo, out)
        assert (out / "docs" / "assets" / "logo.png").exists()

    def test_generates_guide_pages(self, tmp_repo: Path, tmp_path: Path):
        (tmp_repo / "docs" / "scanners.md").write_text("# Scanner Guide\n")
        out = tmp_path / "output"
        build(tmp_repo, out)
        assert (out / "docs" / "guides" / "scanners.md").exists()

    def test_clean_rebuilds(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        # Build again — should clean and rebuild
        build(tmp_repo, out)
        assert (out / "docs" / "index.md").exists()

    def test_generates_examples(self, tmp_repo: Path, tmp_path: Path):
        examples_dir = tmp_repo / "examples"
        examples_dir.mkdir()
        (examples_dir / "security-scan.yml").write_text(
            "name: Example\non: push\njobs: {}\n",
        )
        out = tmp_path / "output"
        build(tmp_repo, out)
        assert (out / "docs" / "examples").exists()

    def test_nav_structure(self, tmp_repo: Path, tmp_path: Path):
        out = tmp_path / "output"
        build(tmp_repo, out)
        mkdocs_content = (out / "mkdocs.yml").read_text()
        assert "Home" in mkdocs_content
        assert "Actions" in mkdocs_content

    def test_generates_ci_platform_pages(
        self, tmp_repo: Path, tmp_path: Path,
    ):
        """examples/ci-platforms/{gitlab-ci.yml,Jenkinsfile,azure-devops.yml}
        each get a dedicated docs page under examples/ci/.
        """
        ci_dir = tmp_repo / "examples" / "ci-platforms"
        ci_dir.mkdir(parents=True)
        (ci_dir / "gitlab-ci.yml").write_text("# gitlab\nimage: argus\n")
        (ci_dir / "Jenkinsfile").write_text("// jenkins\npipeline {}\n")
        (ci_dir / "azure-devops.yml").write_text("# azure\ntrigger: main\n")
        # Examples needs a README for the Overview page
        (tmp_repo / "examples" / "README.md").write_text("# Examples\n")

        out = tmp_path / "output"
        build(tmp_repo, out)

        ci_out = out / "docs" / "examples" / "ci"
        assert (ci_out / "gitlab-ci-yml.md").exists()
        assert (ci_out / "jenkinsfile.md").exists()
        assert (ci_out / "azure-devops-yml.md").exists()

    def test_ci_platform_page_wraps_source_with_intro(
        self, tmp_repo: Path, tmp_path: Path,
    ):
        """Each generated page has the display-name title, the SDK
        portability intro, a canonical-source link, and the file
        contents in a syntax-highlighted code fence.
        """
        ci_dir = tmp_repo / "examples" / "ci-platforms"
        ci_dir.mkdir(parents=True)
        body = "image: argus\nstage: scan\n"
        (ci_dir / "gitlab-ci.yml").write_text(body)
        (tmp_repo / "examples" / "README.md").write_text("# Examples\n")

        out = tmp_path / "output"
        build(tmp_repo, out)

        page = (out / "docs" / "examples" / "ci" / "gitlab-ci-yml.md").read_text()
        # Title
        assert page.startswith("# GitLab CI\n")
        # SDK portability framing
        assert "platform-agnostic" in page
        # Canonical-source link back to the repo
        assert "examples/ci-platforms/gitlab-ci.yml" in page
        # Source content in a yaml-tagged fence
        assert "```yaml" in page
        assert body.strip() in page

    def test_jenkinsfile_uses_groovy_highlight(
        self, tmp_repo: Path, tmp_path: Path,
    ):
        ci_dir = tmp_repo / "examples" / "ci-platforms"
        ci_dir.mkdir(parents=True)
        (ci_dir / "Jenkinsfile").write_text("pipeline { agent any }\n")
        (tmp_repo / "examples" / "README.md").write_text("# Examples\n")

        out = tmp_path / "output"
        build(tmp_repo, out)

        page = (out / "docs" / "examples" / "ci" / "jenkinsfile.md").read_text()
        # Groovy syntax-highlighting hint for Jenkinsfiles
        assert "```groovy" in page

    def test_ci_platform_files_excluded_from_generic_dump(
        self, tmp_repo: Path, tmp_path: Path,
    ):
        """The generic examples/*.yml dump must NOT duplicate ci-platforms
        files at examples/ci-platforms/*.md — those have their own
        richer pages under examples/ci/.
        """
        ci_dir = tmp_repo / "examples" / "ci-platforms"
        ci_dir.mkdir(parents=True)
        (ci_dir / "gitlab-ci.yml").write_text("image: argus\n")
        # And a non-ci-platforms example to confirm the generic loop
        # still works for everything else.
        (tmp_repo / "examples" / "other.yml").write_text("foo: bar\n")
        (tmp_repo / "examples" / "README.md").write_text("# Examples\n")

        out = tmp_path / "output"
        build(tmp_repo, out)

        # Generic dump did NOT write the ci-platforms duplicate:
        assert not (
            out / "docs" / "examples" / "ci-platforms" / "gitlab-ci.md"
        ).exists()
        # …but it DID write the unrelated example:
        assert (out / "docs" / "examples" / "other.md").exists()
        # …and the ci-platforms page lives at its dedicated path:
        assert (
            out / "docs" / "examples" / "ci" / "gitlab-ci-yml.md"
        ).exists()

    def test_nav_nests_github_actions_under_examples_ci(
        self, tmp_repo: Path, tmp_path: Path,
    ):
        """GitHub Actions is no longer a top-level nav entry — it lives
        under Examples > CI alongside GitLab CI, Jenkins, and Azure
        DevOps as peer integrations.
        """
        ci_dir = tmp_repo / "examples" / "ci-platforms"
        ci_dir.mkdir(parents=True)
        (ci_dir / "gitlab-ci.yml").write_text("image: argus\n")
        (ci_dir / "Jenkinsfile").write_text("pipeline {}\n")
        (ci_dir / "azure-devops.yml").write_text("trigger: main\n")
        (tmp_repo / "examples" / "README.md").write_text("# Examples\n")

        out = tmp_path / "output"
        build(tmp_repo, out)
        mkdocs = (out / "mkdocs.yml").read_text()

        # All four CI integrations referenced in the nav
        assert "GitHub Actions" in mkdocs
        assert "GitLab CI" in mkdocs
        assert "Jenkins" in mkdocs
        assert "Azure DevOps" in mkdocs
        # And they live under an Examples > CI tree, not top-level.
        # mkdocs.yml serializes the nav as nested YAML; the CI block
        # appears AFTER the Examples line, before Changelog.
        examples_idx = mkdocs.find("Examples:")
        ci_idx = mkdocs.find("CI:")
        changelog_idx = mkdocs.find("Changelog:")
        assert 0 < examples_idx < ci_idx < changelog_idx, (
            f"Nav ordering wrong: examples={examples_idx} "
            f"ci={ci_idx} changelog={changelog_idx}"
        )

    def test_nav_omits_obe_view_roadtest(
        self, tmp_repo: Path, tmp_path: Path,
    ):
        """The view-roadtest doc is OBE — view-browser + view-terminal
        are the canonical landings. Build must not surface a roadtest
        page even if a stray file appears.
        """
        out = tmp_path / "output"
        build(tmp_repo, out)
        mkdocs = (out / "mkdocs.yml").read_text()
        assert "view-roadtest" not in mkdocs.lower()
        assert "roadtest" not in mkdocs.lower()
