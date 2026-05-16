"""SCN configuration schemas.

Provides access to the JSON schema used for SCN config validation.
"""

from pathlib import Path


_SCHEMA_DIR = Path(__file__).resolve().parent


def get_schema_path(name: str = "scn-config") -> Path:
    """Return the absolute path to a bundled SCN schema file.

    Args:
        name: Schema name without extension (default: ``scn-config``).

    Returns:
        Path to the ``.schema.json`` file inside the package.

    Raises:
        FileNotFoundError: If the requested schema does not exist.
    """
    path = _SCHEMA_DIR / f"{name}.schema.json"
    if not path.is_file():
        raise FileNotFoundError(f"Schema not found: {path}")
    return path
