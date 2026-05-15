"""Main build orchestration — assembles docs, assets, nav tree, and mkdocs.yml."""

from __future__ import annotations

import shutil
from pathlib import Path

from .categories import (
    category_icon,
    category_label,
    get_categorized_actions,
    load_docsite_config,
)
from . import config
from .config import load_site_config
from .helpers import get_version, parse_action_yml, read, rewrite_repo_links, write
from .indexes import make_actions_index, make_home, make_workflows_index
from .mkdocs_config import build_mkdocs_config
from .pages import make_action_page, make_workflow_page
from .parsers import parse_workflow_meta


# ─── Custom CSS ──────────────────────────────────────────────────────────────

CUSTOM_CSS = (
    ".md-header__topic {\n"
    "  height: 48px;\n"
    "  display: flex;\n"
    "  align-items: center;\n"
    "}\n"
    ".md-header__topic:first-child .md-ellipsis {\n"
    "  display: flex;\n"
    "  flex-direction: column;\n"
    "  line-height: 1.2;\n"
    "}\n"
    ".md-header__topic:first-child .md-ellipsis::after {\n"
    '  content: "Perception is Protection";\n'
    "  font-size: 0.55em;\n"
    "  opacity: 0.6;\n"
    "  font-weight: 400;\n"
    "  letter-spacing: 0.05em;\n"
    "}\n"
)


# ─── Build ───────────────────────────────────────────────────────────────────

def build(repo_root: Path, output_dir: Path, *, ref: str | None = None) -> None:
    """Generate the full MkDocs documentation site.

    ``ref`` controls the git ref embedded in cross-repo blob URLs (see
    ``config.load_site_config``). Pass the release tag for versioned
    builds; ``main`` (or ``None``) for unversioned / dev builds. The
    docsite CLI's ``--ref`` flag and ``ARGUS_DOCS_REF`` env var are
    routed through here.
    """
    # Load site config from docsite.yml before anything else
    load_site_config(repo_root, ref=ref)

    version = get_version(repo_root)
    actions_dir = repo_root / ".github" / "actions"
    workflows_dir = repo_root / ".github" / "workflows"
    docs_out = output_dir / "docs"

    print(f"🔨 Building Argus docs v{version}")
    print(f"   Repo:   {repo_root}")
    print(f"   Output: {output_dir}")

    if docs_out.exists():
        shutil.rmtree(docs_out)
    docs_out.mkdir(parents=True)

    # ── Assets ───────────────────────────────────────────────────────────
    assets_dir = docs_out / "assets"
    assets_dir.mkdir()
    write(assets_dir / "custom.css", CUSTOM_CSS)

    img_dir = repo_root / "img"
    if img_dir.exists():
        for img_file in img_dir.iterdir():
            if img_file.is_file():
                shutil.copy2(img_file, assets_dir / img_file.name)

    # ── Core pages ───────────────────────────────────────────────────────
    write(docs_out / "index.md", make_home(repo_root, version))

    quick_start = read(repo_root / "QUICK-START.md")
    if quick_start:
        write(docs_out / "quick-start.md", quick_start)

    changelog = read(repo_root / "CHANGELOG.md")
    if changelog:
        write(docs_out / "changelog.md", changelog)

    for fname in ("CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md"):
        content = read(repo_root / fname)
        if content:
            write(docs_out / fname.lower(), content)

    # ── Guides (from docs/) ──────────────────────────────────────────────
    existing_docs_dir = repo_root / "docs"
    extra_pages: dict[str, str] = {}
    if existing_docs_dir.exists():
        for md_file in existing_docs_dir.rglob("*.md"):
            rel = md_file.relative_to(existing_docs_dir)
            if rel.parts[0] in config.EXCLUDED_GUIDE_DIRS:
                continue
            content = read(md_file)
            source_rel = f"docs/{rel}"
            content = rewrite_repo_links(content, source_rel)
            write(docs_out / "guides" / rel, content)
            extra_pages[str(rel)] = f"guides/{rel}"

    # ── Actions ──────────────────────────────────────────────────────────
    actions_out = docs_out / "actions"
    write(actions_out / "index.md", make_actions_index(actions_dir, version))
    all_action_dirs = sorted([
        d for d in actions_dir.iterdir()
        if d.is_dir() and d.name not in config.EXCLUDED_ACTIONS
    ])
    for action_dir in all_action_dirs:
        write(
            actions_out / f"{action_dir.name}.md",
            make_action_page(action_dir, version),
        )
    print(f"   ✅ Generated {len(all_action_dirs)} action pages")

    # ── Workflows ────────────────────────────────────────────────────────
    workflows_out = docs_out / "workflows"
    write(workflows_out / "index.md", make_workflows_index(workflows_dir, version))
    public_workflows = [
        p for p in sorted(workflows_dir.glob("*.yml"))
        if not p.stem.startswith("test-")
        and p.stem not in config.EXCLUDED_WORKFLOWS
    ]
    for wf in public_workflows:
        write(
            workflows_out / f"{wf.stem}.md",
            make_workflow_page(wf, actions_dir, version, docs_out),
        )
    print(f"   ✅ Generated {len(public_workflows)} workflow pages")

    # ── Examples ─────────────────────────────────────────────────────────
    examples_dir = repo_root / "examples"
    examples_out = docs_out / "examples"
    ci_platform_nav_entries: list[dict] = []
    if examples_dir.exists():
        examples_readme = read(examples_dir / "README.md")
        if examples_readme:
            examples_readme = rewrite_repo_links(examples_readme, "examples/README.md")
        write(examples_out / "index.md", examples_readme or "# Examples\n")
        for yml_file in sorted(examples_dir.rglob("*.yml")):
            # ci-platforms files get a richer dedicated page (built below)
            # and are excluded from the generic dump to avoid two copies.
            if "ci-platforms" in yml_file.parts:
                continue
            rel = yml_file.relative_to(examples_dir)
            content = read(yml_file)
            page = f"# `{yml_file.name}`\n\n```yaml\n{content}\n```\n"
            write(examples_out / str(rel).replace(".yml", ".md"), page)

        # ── CI platform integrations (Examples > CI > <platform>) ────
        # argus is platform-agnostic; these are the major non-GitHub CI
        # surfaces we ship templates for. Each becomes a peer entry to
        # GitHub Actions in the Examples > CI nav tree.
        ci_platforms_dir = examples_dir / "ci-platforms"
        ci_platforms = [
            # (filename, display name, syntax-highlight hint)
            ("gitlab-ci.yml",   "GitLab CI",    "yaml"),
            ("Jenkinsfile",     "Jenkins",      "groovy"),
            ("azure-devops.yml", "Azure DevOps", "yaml"),
        ]
        for filename, display, lang in ci_platforms:
            src = ci_platforms_dir / filename
            if not src.exists():
                continue
            file_content = read(src)
            slug = filename.lower().replace(".", "-")
            page = (
                f"# {display}\n\n"
                f"argus is platform-agnostic. Drop this template into a "
                f"**{display}** project to run the same `argus scan` you "
                f"run locally — same scanners, same canonical "
                f"`argus-results.json`, integrated with the platform's "
                f"native PR-comment / artifact surface.\n\n"
                f"Canonical source: "
                f"[`examples/ci-platforms/{filename}`]"
                f"(https://github.com/huntridge-labs/argus/blob/main/"
                f"examples/ci-platforms/{filename})\n\n"
                f"```{lang}\n{file_content}\n```\n"
            )
            write(examples_out / "ci" / f"{slug}.md", page)
            ci_platform_nav_entries.append(
                {display: f"examples/ci/{slug}.md"},
            )

    # ── Navigation tree ──────────────────────────────────────────────────
    actions_nav = _build_actions_nav(actions_dir, all_action_dirs)

    workflows_nav = _build_workflows_nav(workflows_dir)

    guides_nav = [
        {Path(k).stem.replace("-", " ").title(): v}
        for k, v in sorted(extra_pages.items())
    ]

    # Argus is a platform-agnostic Python SDK / CLI; CI integration is
    # one of many ways to invoke it, and GitHub Actions is one CI among
    # many. The nav reflects that hierarchy:
    #   Examples
    #     ├── Overview
    #     └── CI
    #         ├── GitHub Actions    (Actions + Workflows pages)
    #         ├── GitLab CI
    #         ├── Jenkins
    #         └── Azure DevOps
    # The argus actions + workflows pages are still generated from
    # .github/actions/ and .github/workflows/ — only their nav placement
    # changes. URLs stay at /actions/<name>/ and /workflows/<name>/.
    nav = [
        {"Home": "index.md"},
        {"Quick Start": "quick-start.md"},
    ]
    if guides_nav:
        nav.append({"Guides": guides_nav})

    if (examples_out / "index.md").exists():
        github_actions_nav = [
            {"Actions": actions_nav},
            {"Workflows": workflows_nav},
        ]
        ci_nav: list = [{"GitHub Actions": github_actions_nav}]
        ci_nav.extend(ci_platform_nav_entries)

        examples_nav = [
            {"Overview": "examples/index.md"},
            {"CI": ci_nav},
        ]
        nav.append({"Examples": examples_nav})

    nav.append({"Changelog": "changelog.md"})

    # ── Architecture page (self-contained interactive diagram) ───────────
    #
    # Derived from .ai/architecture.yaml + runtime SDK introspection.
    # The view model is the same JSON the FastAPI viewer's /architecture
    # route and the argus://architecture MCP resource serve. Lives at
    # docs/architecture/index.html as a fully standalone page (no MkDocs
    # markdown wrapper) so it works under file:// when saved.
    try:
        from .architecture import (
            build_view_model_from_repo,
            render_standalone_html,
        )
        view_model = build_view_model_from_repo(repo_root)
        arch_out = docs_out / "architecture"
        render_standalone_html(view_model, arch_out)
        print(
            f"   ✅ Architecture page generated "
            f"({len(view_model.get('nodes', []))} nodes, "
            f"{len(view_model.get('flows', []))} flows)"
        )
    except Exception as exc:
        # Don't fail the whole docsite build on a missing SDK import.
        # The page is a nice-to-have; the rest of the docs ship without it.
        print(f"   ⚠️  Architecture page skipped: {exc}")

    write(output_dir / "mkdocs.yml", build_mkdocs_config(version, nav))
    print("   ✅ mkdocs.yml written")
    print(f"\n✨ Done!\n")
    print(f"   cd {output_dir} && mkdocs serve\n")


# ─── Navigation helpers ─────────────────────────────────────────────────────

def _build_actions_nav(actions_dir: Path, all_action_dirs: list[Path]) -> list:
    """Build the Actions section of the nav tree from .docsite.yml + fallback."""
    nav = [{"Overview": "actions/index.md"}]
    categories = get_categorized_actions(actions_dir)

    for cat, members in categories.items():
        icon = category_icon(cat)
        label = category_label(cat)
        cat_entries: list[dict] = []
        for action_name in members:
            action_dir = actions_dir / action_name
            if not action_dir.exists():
                continue
            docsite = load_docsite_config(action_dir)
            meta = parse_action_yml(action_dir / "action.yml")
            display = (
                docsite.sidebar_label if docsite and docsite.sidebar_label
                else meta.get("name", action_name)
            )
            cat_entries.append({display: f"actions/{action_name}.md"})
        if cat_entries:
            nav.append({f"{icon} {label}": cat_entries})

    return nav


def _build_workflows_nav(workflows_dir: Path) -> list:
    """Build the Workflows section of the nav tree."""
    public_workflows = [
        p for p in sorted(workflows_dir.glob("*.yml"))
        if not p.stem.startswith("test-")
        and p.stem not in config.EXCLUDED_WORKFLOWS
    ]

    nav: list = [{"Overview": "workflows/index.md"}]
    for wf in public_workflows:
        meta = parse_workflow_meta(wf)
        nav.append({meta.get("name", wf.stem): f"workflows/{wf.stem}.md"})

    return nav
