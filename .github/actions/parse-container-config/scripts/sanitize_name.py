#!/usr/bin/env python3
"""
Container name sanitizer using python-slugify.

Can be used as:
  - CLI single:  python3 sanitize_name.py "my.app" → prints "my-app"
  - CLI list:    python3 sanitize_name.py --list "my.app" "my@app" → prints "my-app my-app-2"
  - Import:      from sanitize_name import sanitize_container_name, sanitize_names
"""

import sys

from slugify import slugify


def sanitize_container_name(name: str, fallback: str = "container", max_length: int = 50) -> str:
    """
    Sanitize a container name to match ^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,49}$

    Args:
        name: The original container name
        fallback: Fallback name if result is empty (default: "container")
        max_length: Maximum allowed length (default: 50)

    Returns:
        A valid, sanitized container name
    """
    if not name or not isinstance(name, str):
        return fallback

    # slugify handles: unicode→ascii, special chars→hyphen, collapse hyphens, strip edges
    # regex_pattern keeps only alphanumeric, underscore, hyphen (replaces everything else)
    result = slugify(
        name,
        lowercase=False,
        max_length=max_length,
        regex_pattern=r'[^a-zA-Z0-9_]+',
    )

    if not result:
        return fallback

    return result


def resolve_name_collision(name: str, seen_names: dict, max_length: int = 50) -> str:
    """
    Resolve name collisions by appending suffix (-2, -3, etc.).

    Args:
        name: The sanitized container name
        seen_names: Dict tracking name usage counts (mutated)
        max_length: Maximum allowed length (default: 50)

    Returns:
        Unique name with suffix if needed, truncated to max_length
    """
    if name not in seen_names:
        seen_names[name] = 1
        return name

    seen_names[name] += 1
    suffix = f"-{seen_names[name]}"

    # Truncate base name to leave room for suffix
    max_base = max_length - len(suffix)
    truncated = name[:max_base].rstrip('-')

    return f"{truncated}{suffix}"


def sanitize_names(names: list, fallback: str = "container", max_length: int = 50) -> list:
    """
    Sanitize a list of container names, resolving collisions with suffixes.

    Args:
        names: List of original container names
        fallback: Fallback name if result is empty (default: "container")
        max_length: Maximum allowed length (default: 50)

    Returns:
        List of sanitized names with collisions resolved
    """
    seen = {}
    results = []
    for name in names:
        sanitized = sanitize_container_name(name, fallback, max_length)
        sanitized = resolve_name_collision(sanitized, seen, max_length)
        results.append(sanitized)
    return results


def main():
    """CLI entrypoint."""
    if len(sys.argv) < 2:
        print("Usage: sanitize_name.py [--list] <name> [name2 ...] [--fallback <fallback>]", file=sys.stderr)
        sys.exit(1)

    args = sys.argv[1:]
    list_mode = False
    fallback = "container"
    names = []

    i = 0
    while i < len(args):
        if args[i] == "--list":
            list_mode = True
        elif args[i] == "--fallback" and i + 1 < len(args):
            fallback = args[i + 1]
            i += 1
        else:
            names.append(args[i])
        i += 1

    if not names:
        print("Error: No names provided", file=sys.stderr)
        sys.exit(1)

    if list_mode:
        # Sanitize all names with collision detection
        results = sanitize_names(names, fallback)
        print(" ".join(results))
    else:
        # Single name mode (no collision detection)
        print(sanitize_container_name(names[0], fallback))


if __name__ == "__main__":
    main()
