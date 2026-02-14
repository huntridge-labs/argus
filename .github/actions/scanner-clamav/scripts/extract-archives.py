#!/usr/bin/env python3
"""
Archive Extraction Utility for ClamAV Scanning

This script recursively extracts nested archives to prepare them for ClamAV scanning.
It supports various archive formats and outputs paths for subsequent scanning.
ClamAV scanning is handled separately by the workflow.
"""

import shutil
import logging
import tempfile
from pathlib import Path
from argparse import ArgumentParser
import tarfile
import gzip
import zipfile
try:
    import rarfile
    HAS_RARFILE = True
except ImportError:
    HAS_RARFILE = False
from typing import List

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ArchiveExtractor:
    """
    A class for recursively extracting nested archives of various formats.
    """

    SUPPORTED_EXTENSIONS = {
        # Tar formats
        'tar', 'tgz', 'tbz', 'tb2', 'tar.gz', 'tar.bz2', 'tar.xz',
        # Zip formats
        'zip',
        # Rar formats
        'rar',
        # Gzip
        'gz'
    }

    def __init__(self, output_dir: str = None, base_path: Path = None):
        self.output_dir = Path(output_dir) if output_dir else Path(tempfile.mkdtemp())
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.extracted_paths = []
        self.errors = []
        # Base directories/patterns to exclude from scanning
        self.exclude_dirs = {
            '.git', 'node_modules', '__pycache__', '.venv', 'venv', '.tox',
            '.pytest_cache', 'htmlcov', 'coverage', '.coverage',
            'tests', 'test', '__tests__', 'spec', 'specs'
        }
        # Load additional exclusions from ignore files
        self.exclude_patterns = set()
        if base_path:
            self._load_ignore_files(base_path)

    def is_archive(self, file_path: Path) -> bool:
        """Check if a file is a supported archive."""
        return file_path.suffix.lower().lstrip('.') in self.SUPPORTED_EXTENSIONS

    def _load_ignore_files(self, base_path: Path) -> None:
        """Load patterns from .gitignore and .dockerignore files."""
        ignore_files = ['.gitignore', '.dockerignore']

        for ignore_file in ignore_files:
            ignore_path = base_path / ignore_file
            if ignore_path.exists():
                try:
                    with open(ignore_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            # Skip comments and empty lines
                            if line and not line.startswith('#'):
                                # Remove leading/trailing slashes for consistency
                                pattern = line.strip('/')
                                self.exclude_patterns.add(pattern)
                    logger.info("Loaded exclusions from %s", ignore_file)
                except (OSError, UnicodeDecodeError) as e:
                    logger.warning("Failed to read %s: %s", ignore_file, e)

    def _should_exclude(self, path: Path, base_path: Path = None) -> bool:
        """Check if a path should be excluded based on patterns and directory names."""
        # Check if any parent directory matches exclude_dirs
        if any(part in self.exclude_dirs for part in path.parts):
            return True

        # Check against patterns from ignore files
        if base_path and self.exclude_patterns:
            try:
                rel_path = path.relative_to(base_path)
                rel_path_str = str(rel_path)

                for pattern in self.exclude_patterns:
                    # Simple pattern matching (not full gitignore spec, but covers common cases)
                    if pattern in rel_path_str or rel_path_str.startswith(pattern):
                        return True
                    # Check if any component matches
                    if pattern in path.parts:
                        return True
            except ValueError:
                # Path is not relative to base_path
                pass

        return False

    def extract_archive(self, archive_path: Path, extract_to: Path) -> bool:
        """Extract a single archive file."""
        try:
            if archive_path.suffix.lower() in ['.tar', '.tgz', '.tbz', '.tb2', '.tar.gz', '.tar.bz2', '.tar.xz']:
                return self._extract_tar(archive_path, extract_to)
            elif archive_path.suffix.lower() == '.zip':
                return self._extract_zip(archive_path, extract_to)
            elif archive_path.suffix.lower() == '.rar':
                return self._extract_rar(archive_path, extract_to)
            elif archive_path.suffix.lower() == '.gz':
                return self._extract_gz(archive_path, extract_to)
            else:
                logger.warning("Unsupported archive format: %s", archive_path)
                return False
        except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as e:
            logger.error("Failed to extract %s: %s", archive_path, e)
            self.errors.append(str(e))
            return False

    def _extract_tar(self, archive_path: Path, extract_to: Path) -> bool:
        """Extract tar archives."""
        try:
            with tarfile.open(archive_path, 'r:*') as tar:
                tar.extractall(extract_to)
            return True
        except (OSError, tarfile.TarError) as e:
            logger.error("Failed to extract tar %s: %s", archive_path, e)
            return False

    def _extract_zip(self, archive_path: Path, extract_to: Path) -> bool:
        """Extract zip archives."""
        try:
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
            return True
        except (OSError, zipfile.BadZipFile) as e:
            logger.error("Failed to extract zip %s: %s", archive_path, e)
            return False

    def _extract_rar(self, archive_path: Path, extract_to: Path) -> bool:
        """Extract rar archives."""
        if not HAS_RARFILE:
            logger.warning("rarfile module not available, skipping RAR extraction: %s", archive_path)
            return False
        try:
            with rarfile.RarFile(archive_path, 'r') as rar:
                rar.extractall(extract_to)
            return True
        except (OSError, rarfile.Error) as e:
            logger.error("Failed to extract rar %s: %s", archive_path, e)
            return False

    def _extract_gz(self, archive_path: Path, extract_to: Path) -> bool:
        """Extract gzipped files."""
        try:
            output_file = extract_to / archive_path.stem
            with gzip.open(archive_path, 'rb') as f_in:
                with open(output_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            return True
        except (OSError, gzip.BadGzipFile) as e:
            logger.error("Failed to extract gz %s: %s", archive_path, e)
            return False

    def extract_recursively(self, input_path: Path, base_path: Path = None) -> List[Path]:
        """Recursively extract archives starting from input_path.

        Args:
            input_path: Path to extract from
            base_path: Base path for relative pattern matching (usually the original scan root)
        """
        if not input_path.exists():
            logger.warning("Path does not exist: %s", input_path)
            return []

        # Resolve to absolute path to properly compare with output_dir
        input_path = input_path.resolve()
        output_dir_resolved = self.output_dir.resolve()

        # Skip if this path is inside the output directory (prevent infinite loops)
        try:
            input_path.relative_to(output_dir_resolved)
            logger.debug("Skipping path inside output directory: %s", input_path)
            return []
        except ValueError:
            # Path is not relative to output_dir, continue processing
            pass

        # Skip excluded paths
        if self._should_exclude(input_path, base_path):
            logger.debug("Skipping excluded path: %s", input_path)
            return []

        if input_path.is_file():
            if self.is_archive(input_path):
                extract_dir = self.output_dir / f"extracted_{input_path.stem}_{len(self.extracted_paths)}"
                extract_dir.mkdir(parents=True, exist_ok=True)

                if self.extract_archive(input_path, extract_dir):
                    self.extracted_paths.append(extract_dir)
                    logger.info("Extracted %s to %s", input_path, extract_dir)

                    # Recursively extract any archives found in the extracted content
                    for item in extract_dir.rglob('*'):
                        if item.is_file() and self.is_archive(item):
                            self.extract_recursively(item, base_path)
                else:
                    logger.error("Failed to extract %s", input_path)
            # Note: Non-archive files are NOT copied - they'll be scanned in place

        elif input_path.is_dir():
            # If the input is a directory, iterate over its contents
            # Only process archives, skip excluded directories
            for item in input_path.iterdir():
                # Skip excluded paths
                if self._should_exclude(item, base_path):
                    logger.debug("Skipping excluded path: %s", item)
                    continue

                # Only recursively process if it's an archive or a directory (to find archives)
                if item.is_file():
                    if self.is_archive(item):
                        self.extract_recursively(item, base_path)
                    # Skip non-archive files - they'll be scanned directly
                elif item.is_dir():
                    self.extract_recursively(item, base_path)

        return self.extracted_paths

def main(input_paths: List[str], output_dir: str):
    """
    Main function to extract archives for ClamAV scanning.

    Args:
        input_paths (List[str]): List of input file or directory paths.
        output_dir (str): Output directory for extracted files.

    Returns:
        Prints paths to scan (original path and/or extracted directories) to stdout.
    """
    paths_to_scan = []

    for input_path in input_paths:
        path = Path(input_path).resolve()
        if not path.exists():
            logger.warning("Path does not exist: %s", path)
            continue

        logger.info("Processing %s", path)

        # Determine base path for exclusion patterns
        base_path = path if path.is_dir() else path.parent

        # Create extractor with exclusions
        extractor = ArchiveExtractor(output_dir, base_path=base_path)

        # Extract any archives found
        extracted_paths = extractor.extract_recursively(path, base_path=base_path)

        if extracted_paths:
            logger.info("Found and extracted %d archive(s)", len(extracted_paths))
            # Add extraction output directory to scan paths
            paths_to_scan.append(str(extractor.output_dir))

        # If input is a directory or a non-archive file, add it to scan paths
        if path.is_dir():
            paths_to_scan.append(str(path))
        elif path.is_file() and not extractor.is_archive(path):
            paths_to_scan.append(str(path))

    # Output paths to scan (one per line for easy parsing)
    if paths_to_scan:
        logger.info("Paths to scan:")
        for scan_path in paths_to_scan:
            print(scan_path)
            logger.info("  - %s", scan_path)
    else:
        logger.warning("No paths to scan")

if __name__ == "__main__":
    parser = ArgumentParser(description="Archive Extraction Utility for ClamAV Scanning")
    parser.add_argument('input_paths', nargs='+', help="Input file or directory paths")
    parser.add_argument('--output-dir', dest='output_dir', default=tempfile.mkdtemp(),
                        help="Output directory for extracted files (default: temp directory)")
    args = parser.parse_args()

    main(args.input_paths, args.output_dir)
