"""JSON reporter — serialize full scan summary to JSON."""

import json
from typing import Optional
from pathlib import Path

from argus.core.models import ScanSummary


_DEFAULT_OUTPUT_DIR = Path("./argus-results")


class JsonReporter:
    """Generate JSON report."""

    def report(self, summary: ScanSummary, output_dir: Optional[Path] = None) -> Path:
        """Write JSON report to output_dir/argus-results.json.

        Returns the path to the written file.
        """
        dest = Path(output_dir) if output_dir else _DEFAULT_OUTPUT_DIR
        dest.mkdir(parents=True, exist_ok=True)
        filepath = dest / "argus-results.json"

        data = summary.to_dict()
        filepath.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return filepath
