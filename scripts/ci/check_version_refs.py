#!/usr/bin/env python3
"""
Version Reference Coverage Checker

Finds all version-like references in the repo (action @refs, workflow @refs,
schema URLs, HRL_REF fallbacks) and verifies each is covered by a release-it
regex-bumper rule. Reports any gaps that would leave stale version references
after a release.
"""

import json
import re
import sys
from pathlib import Path

# Directories and files to skip when scanning
SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.venv', 'venv',
    'htmlcov', 'coverage', '.tox', '.pytest_cache', 'site-build',
    '.claude', '.agents',
}
SKIP_FILES = {
    'CHANGELOG.md', 'package-lock.json', 'check_version_refs.py',
    '.release-it.json', 'copilot-instructions.md', 'release_output.txt',
    'test_check_version_refs.py',
}

# Inline marker to suppress version-ref warnings on a specific line
IGNORE_MARKER = 'release-it-ignore'

# Patterns that represent version references in this repo
VERSION_REF_PATTERNS = [
    # huntridge-labs/argus/.github/actions/<name>@<ref>
    re.compile(r'huntridge-labs/argus/\.github/actions/[^@\s]+@[^\s\'"]+'),
    # huntridge-labs/argus/.github/workflows/<name>.yml@<ref>
    re.compile(r'huntridge-labs/argus/\.github/workflows/[\w-]+\.yml@[^\s\'"]+'),
    # raw.githubusercontent.com/huntridge-labs/argus/<ref>/.github/
    re.compile(r'raw\.githubusercontent\.com/huntridge-labs/argus/[^/]+/\.github/'),
    # HRL_REF fallback: || '<ref>'
    re.compile(r"HRL_REF:.*\|\| '[^']+'"),
]


def _expand_braces(pattern: str) -> list:
    """Expand brace patterns like *.{yml,yaml,md} into multiple patterns."""
    if '{' not in pattern:
        return [pattern]
    base, rest = pattern.split('{', 1)
    exts, suffix = rest.split('}', 1)
    return [f'{base}{ext}{suffix}' for ext in exts.split(',')]


def load_release_it_rules(repo_root: Path) -> list:
    """Extract regex-bumper rules from .release-it.json.

    Uses Path.glob() to expand file patterns into actual file paths,
    avoiding custom glob matching logic entirely.
    """
    config_path = repo_root / '.release-it.json'
    with open(config_path, 'r', encoding='utf-8') as f:
        config = json.load(f)

    bumper = config.get('plugins', {}).get('@j-ulrich/release-it-regex-bumper', {})
    out_entries = bumper.get('out', [])

    rules = []
    for entry in out_entries:
        if isinstance(entry, str):
            rules.append({
                'covered_files': {entry},
                'pattern': None,
            })
        elif isinstance(entry, dict):
            covered = set()
            for glob_pat in entry.get('files', []):
                for expanded in _expand_braces(glob_pat):
                    for matched in repo_root.glob(expanded):
                        if matched.is_file():
                            covered.add(str(matched.relative_to(repo_root)))

            search = entry.get('search', {})
            pattern = search.get('pattern')
            rules.append({
                'covered_files': covered,
                'pattern': pattern,
            })

    return rules


def is_ref_covered(file_rel: str, ref_text: str, full_line: str, rules: list) -> bool:
    """Check if a version reference in a file is covered by any release-it rule."""
    for rule in rules:
        if file_rel not in rule['covered_files']:
            continue

        # If rule has no pattern (e.g. version.yaml), it covers the whole file
        if rule['pattern'] is None:
            return True

        # Check if the rule's search pattern matches the ref or the full line
        # Some patterns (e.g. schema $id) require surrounding line context
        try:
            if re.search(rule['pattern'], ref_text) or re.search(rule['pattern'], full_line):
                return True
        except re.error:
            continue

    return False


def find_version_refs(repo_root: Path) -> list:
    """Find all version references in the repo."""
    refs = []

    for path in sorted(repo_root.rglob('*')):
        if not path.is_file():
            continue

        # Skip excluded directories
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue

        # Skip excluded files
        if path.name in SKIP_FILES:
            continue

        # Only scan text-like files
        if path.suffix.lower() not in {
            '.yml', '.yaml', '.md', '.json', '.txt', '.py', '.js', '.ts',
        }:
            continue

        rel_path = str(path.relative_to(repo_root))

        try:
            content = path.read_text(encoding='utf-8')
        except (UnicodeDecodeError, OSError):
            continue

        for line_num, line in enumerate(content.splitlines(), 1):
            if IGNORE_MARKER in line:
                continue
            for pattern in VERSION_REF_PATTERNS:
                for match in pattern.finditer(line):
                    refs.append({
                        'file': rel_path,
                        'line': line_num,
                        'text': match.group(0),
                        'full_line': line,
                    })

    return refs


def main():
    repo_root = Path(__file__).resolve().parent.parent.parent

    rules = load_release_it_rules(repo_root)
    refs = find_version_refs(repo_root)

    if not refs:
        print('No version references found.')
        return 0

    uncovered = []
    for ref in refs:
        if not is_ref_covered(ref['file'], ref['text'], ref['full_line'], rules):
            uncovered.append(ref)

    files_with_refs = len({r['file'] for r in refs})
    print(f'Version refs found: {len(refs)} across {files_with_refs} files')

    if not uncovered:
        print('All covered by release-it config.')
        return 0

    uncovered_files = len({r['file'] for r in uncovered})
    print(f'\nUNCOVERED ({len(uncovered)} refs in {uncovered_files} files):')
    for ref in uncovered:
        print(f"  {ref['file']}:{ref['line']}  {ref['text']}")

    return 1


if __name__ == '__main__':
    sys.exit(main())
