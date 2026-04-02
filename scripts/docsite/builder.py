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

# ─── Social Media Meta Tags ──────────────────────────────────────────────────

SOCIAL_META_HTML = '''{% extends "base.html" %}

{% block extrahead %}
  <!-- OpenGraph metadata for LinkedIn, Facebook, etc. -->
  <meta property="og:type" content="website">
  <meta property="og:image" content="{{ config.site_url }}assets/argus_readme_cover.png">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">

  <!-- Twitter Card metadata -->
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:image" content="{{ config.site_url }}assets/argus_readme_cover.png">

  {{ super() }}
{% endblock %}
'''


# ─── Build ───────────────────────────────────────────────────────────────────

def build(repo_root: Path, output_dir: Path) -> None:
    """Generate the full MkDocs documentation site."""
    # Load site config from docsite.yml before anything else
    load_site_config(repo_root)

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

    # ── Theme Overrides (for social media meta tags) ────────────────────
    overrides_dir = output_dir / "overrides"
    overrides_dir.mkdir(exist_ok=True)
    write(overrides_dir / "main.html", SOCIAL_META_HTML)

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
    if examples_dir.exists():
        examples_readme = read(examples_dir / "README.md")
        if examples_readme:
            examples_readme = rewrite_repo_links(examples_readme, "examples/README.md")
        write(examples_out / "index.md", examples_readme or "# Examples\n")
        for yml_file in sorted(examples_dir.rglob("*.yml")):
            rel = yml_file.relative_to(examples_dir)
            content = read(yml_file)
            page = f"# `{yml_file.name}`\n\n```yaml\n{content}\n```\n"
            write(examples_out / str(rel).replace(".yml", ".md"), page)

    # ── Navigation tree ──────────────────────────────────────────────────
    actions_nav = _build_actions_nav(actions_dir, all_action_dirs)

    workflows_nav = _build_workflows_nav(workflows_dir)

    guides_nav = [
        {Path(k).stem.replace("-", " ").title(): v}
        for k, v in sorted(extra_pages.items())
    ]

    nav = [
        {"Home": "index.md"},
        {"Quick Start": "quick-start.md"},
        {"Actions": actions_nav},
        {"Workflows": workflows_nav},
        {"Changelog": "changelog.md"},
    ]
    if guides_nav:
        nav.insert(4, {"Guides": guides_nav})
    if (examples_out / "index.md").exists():
        nav.insert(-1, {"Examples": "examples/index.md"})

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
    main_wf = workflows_dir / "reusable-security-hardening.yml"
    scanner_wfs_nav = [
        {parse_workflow_meta(p)["name"]: f"workflows/{p.stem}.md"}
        for p in sorted(workflows_dir.glob("scanner-*.yml"))
    ]
    other_wfs_nav = [
        {parse_workflow_meta(p)["name"]: f"workflows/{p.stem}.md"}
        for p in sorted(workflows_dir.glob("*.yml"))
        if p != main_wf
        and not p.stem.startswith("scanner-")
        and not p.stem.startswith("test-")
        and p.stem not in config.EXCLUDED_WORKFLOWS
    ]

    nav: list = [
        {"Overview": "workflows/index.md"},
        {"Reusable Security Hardening": "workflows/reusable-security-hardening.md"},
    ]
    if scanner_wfs_nav:
        nav.append({"Individual Scanners": scanner_wfs_nav})
    if other_wfs_nav:
        nav.append({"Utility Workflows": other_wfs_nav})

    return nav
