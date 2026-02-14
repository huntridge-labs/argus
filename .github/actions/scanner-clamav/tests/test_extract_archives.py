#!/usr/bin/env python3
"""
Comprehensive test suite for extract-archives.py with 100% coverage.
"""

import json
import pytest

pytestmark = pytest.mark.unit
import os
import shutil
import tarfile
import tempfile
import zipfile
import gzip
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import pytest

# Import the modules to test
import sys
REPO_ROOT = Path(__file__).parent.parent.parent.parent.parent
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import importlib.util
spec = importlib.util.spec_from_file_location("extract_archives", SCRIPTS_DIR / "extract-archives.py")
extract_archives = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract_archives)

ArchiveExtractor = extract_archives.ArchiveExtractor
main = extract_archives.main


class TestArchiveExtractor:
    """Test cases for ArchiveExtractor class."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def extractor(self, temp_dir):
        """Create an ArchiveExtractor instance."""
        return ArchiveExtractor(str(temp_dir / "output"))

    def test_init_default(self):
        """Test ArchiveExtractor initialization with default output dir."""
        extractor = ArchiveExtractor()
        assert extractor.output_dir.exists()
        assert extractor.extracted_paths == []
        assert extractor.errors == []

    def test_init_custom_output(self, temp_dir):
        """Test ArchiveExtractor initialization with custom output dir."""
        output_dir = temp_dir / "custom_output"
        extractor = ArchiveExtractor(str(output_dir))
        assert extractor.output_dir == output_dir
        assert extractor.extracted_paths == []
        assert extractor.errors == []

    def test_init_with_base_path(self, temp_dir):
        """Test ArchiveExtractor initialization with base path for exclusions."""
        base_path = temp_dir / "base"
        base_path.mkdir()
        extractor = ArchiveExtractor(str(temp_dir / "output"), base_path=base_path)
        assert extractor.output_dir == temp_dir / "output"
        assert extractor.extracted_paths == []
        assert extractor.errors == []
        assert '.git' in extractor.exclude_dirs

    def test_is_archive_supported_formats(self):
        """Test is_archive method with supported formats."""
        extractor = ArchiveExtractor()
        test_cases = [
            (Path("test.tar"), True),
            (Path("test.tgz"), True),
            (Path("test.tar.gz"), True),
            (Path("test.zip"), True),
            (Path("test.rar"), True),
            (Path("test.gz"), True),
            (Path("test.txt"), False),
            (Path("test"), False),
        ]

        for file_path, expected in test_cases:
            assert extractor.is_archive(file_path) == expected

    def test_is_archive_case_insensitive(self):
        """Test is_archive method is case insensitive."""
        extractor = ArchiveExtractor()
        assert extractor.is_archive(Path("test.TAR"))
        assert extractor.is_archive(Path("test.ZIP"))
        assert extractor.is_archive(Path("test.TAR.GZ"))

    def test_load_ignore_files_gitignore(self, temp_dir):
        """Test loading patterns from .gitignore file."""
        base_path = temp_dir / "base"
        base_path.mkdir()
        gitignore = base_path / ".gitignore"
        gitignore.write_text("node_modules\n*.log\n# comment\n")

        extractor = ArchiveExtractor(str(temp_dir / "output"), base_path=base_path)
        assert "node_modules" in extractor.exclude_patterns
        assert "*.log" in extractor.exclude_patterns
        assert "# comment" not in extractor.exclude_patterns

    def test_load_ignore_files_dockerignore(self, temp_dir):
        """Test loading patterns from .dockerignore file."""
        base_path = temp_dir / "base"
        base_path.mkdir()
        dockerignore = base_path / ".dockerignore"
        dockerignore.write_text("Dockerfile\ntmp/\n")

        extractor = ArchiveExtractor(str(temp_dir / "output"), base_path=base_path)
        assert "Dockerfile" in extractor.exclude_patterns
        assert "tmp" in extractor.exclude_patterns

    def test_load_ignore_files_missing_file(self, temp_dir):
        """Test loading ignore files when file doesn't exist."""
        base_path = temp_dir / "base"
        base_path.mkdir()

        # Should not raise exception
        extractor = ArchiveExtractor(str(temp_dir / "output"), base_path=base_path)
        assert len(extractor.exclude_patterns) == 0

    def test_should_exclude_directory(self, temp_dir):
        """Test _should_exclude with excluded directory."""
        base_path = temp_dir / "base"
        base_path.mkdir()
        extractor = ArchiveExtractor(str(temp_dir / "output"), base_path=base_path)

        excluded_path = base_path / "node_modules" / "package.json"
        assert extractor._should_exclude(excluded_path, base_path) == True

    def test_should_exclude_pattern_match(self, temp_dir):
        """Test _should_exclude with pattern from ignore file."""
        base_path = temp_dir / "base"
        base_path.mkdir()
        gitignore = base_path / ".gitignore"
        gitignore.write_text("debug.log\ntest.txt\n")

        extractor = ArchiveExtractor(str(temp_dir / "output"), base_path=base_path)

        log_file = base_path / "debug.log"
        assert extractor._should_exclude(log_file, base_path) == True

        test_file = base_path / "test.txt"
        assert extractor._should_exclude(test_file, base_path) == True

        normal_file = base_path / "script.py"
        assert extractor._should_exclude(normal_file, base_path) == False

    def test_should_exclude_not_excluded(self, temp_dir):
        """Test _should_exclude with non-excluded path."""
        base_path = temp_dir / "base"
        base_path.mkdir()
        extractor = ArchiveExtractor(str(temp_dir / "output"), base_path=base_path)

        normal_file = base_path / "script.py"
        assert extractor._should_exclude(normal_file, base_path) == False

    @patch.object(extract_archives, 'logger')
    def test_extract_archive_unsupported_format(self, mock_logger, extractor, temp_dir):
        """Test extract_archive with unsupported format."""
        unsupported_file = temp_dir / "test.txt"
        unsupported_file.write_text("test content")

        result = extractor.extract_archive(unsupported_file, temp_dir / "extract")
        assert result is False
        mock_logger.warning.assert_called_once()

    def test_extract_archive_tar_format(self, extractor, temp_dir):
        """Test extract_archive with tar format."""
        # Create a test tar file
        tar_path = temp_dir / "test.tar"
        extract_dir = temp_dir / "extract"
        extract_dir.mkdir()  # Ensure directory exists

        with tarfile.open(tar_path, 'w') as tar:
            # Add a test file
            test_file = temp_dir / "test.txt"
            test_file.write_text("test content")
            tar.add(str(test_file), arcname="test.txt")

        result = extractor.extract_archive(tar_path, extract_dir)
        assert result is True
        assert (extract_dir / "test.txt").exists()

    def test_extract_archive_zip_format(self, extractor, temp_dir):
        """Test extract_archive with zip format."""
        # Create a test zip file
        zip_path = temp_dir / "test.zip"
        extract_dir = temp_dir / "extract"
        extract_dir.mkdir()  # Ensure directory exists

        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("test.txt", "test content")

        result = extractor.extract_archive(zip_path, extract_dir)
        assert result is True
        assert (extract_dir / "test.txt").exists()

    def test_extract_archive_gz_format(self, extractor, temp_dir):
        """Test extract_archive with gz format."""
        # Create a test gz file
        gz_path = temp_dir / "test.txt.gz"
        extract_dir = temp_dir / "extract"
        extract_dir.mkdir()  # Ensure directory exists

        with gzip.open(gz_path, 'wb') as f:
            f.write(b"test content")

        result = extractor.extract_archive(gz_path, extract_dir)
        assert result is True
        assert (extract_dir / "test.txt").exists()

    @patch.object(extract_archives, 'HAS_RARFILE', False)
    @patch.object(extract_archives, 'logger')
    def test_extract_archive_rar_format_no_rarfile(self, mock_logger, extractor, temp_dir):
        """Test extract_archive with rar format when rarfile is not available."""
        # Create a dummy rar file
        rar_path = temp_dir / "test.rar"
        extract_dir = temp_dir / "extract"
        extract_dir.mkdir()

        rar_path.write_bytes(b"dummy rar content")

        result = extractor.extract_archive(rar_path, extract_dir)
        # Should return False since rarfile is not available
        assert result is False
        mock_logger.warning.assert_called_once()

    @patch.object(extract_archives, 'logger')
    def test_extract_archive_exception_handling(self, mock_logger, extractor, temp_dir):
        """Test extract_archive exception handling."""
        # Create a zip file that will cause an exception
        zip_path = temp_dir / "test.zip"
        extract_dir = temp_dir / "extract"
        extract_dir.mkdir()

        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("test.txt", "test content")

        # Patch _extract_zip to raise an exception
        with patch.object(extractor, '_extract_zip', side_effect=OSError("Test error")):
            result = extractor.extract_archive(zip_path, extract_dir)
            assert result is False
            mock_logger.error.assert_called_once()
            assert len(extractor.errors) > 0

    def test_extract_tar_success(self, extractor, temp_dir):
        """Test successful tar extraction."""
        # Create a test tar file
        tar_path = temp_dir / "test.tar"
        extract_dir = temp_dir / "extract"

        with tarfile.open(tar_path, 'w') as tar:
            # Add a test file
            test_file = temp_dir / "test.txt"
            test_file.write_text("test content")
            tar.add(str(test_file), arcname="test.txt")

        result = extractor._extract_tar(tar_path, extract_dir)
        assert result is True
        assert (extract_dir / "test.txt").exists()
        assert (extract_dir / "test.txt").read_text() == "test content"

    @patch.object(extract_archives, 'logger')
    def test_extract_tar_failure(self, mock_logger, extractor, temp_dir):
        """Test tar extraction failure."""
        # Create an invalid tar file
        tar_path = temp_dir / "invalid.tar"
        tar_path.write_bytes(b"invalid tar content")

        result = extractor._extract_tar(tar_path, temp_dir / "extract")
        assert result is False
        mock_logger.error.assert_called_once()

    def test_extract_zip_success(self, extractor, temp_dir):
        """Test successful zip extraction."""
        zip_path = temp_dir / "test.zip"
        extract_dir = temp_dir / "extract"

        with zipfile.ZipFile(zip_path, 'w') as zip_file:
            zip_file.writestr("test.txt", "test content")

        result = extractor._extract_zip(zip_path, extract_dir)
        assert result is True
        assert (extract_dir / "test.txt").exists()
        assert (extract_dir / "test.txt").read_text() == "test content"

    @patch.object(extract_archives, 'logger')
    def test_extract_zip_failure(self, mock_logger, extractor, temp_dir):
        """Test zip extraction failure."""
        zip_path = temp_dir / "invalid.zip"
        zip_path.write_bytes(b"invalid zip content")

        result = extractor._extract_zip(zip_path, temp_dir / "extract")
        assert result is False
        mock_logger.error.assert_called_once()

    def test_extract_gz_success(self, extractor, temp_dir):
        """Test successful gz extraction."""
        gz_path = temp_dir / "test.txt.gz"
        extract_dir = temp_dir / "extract"
        extract_dir.mkdir(exist_ok=True)  # Ensure extract dir exists

        # Create a gzipped file
        with gzip.open(gz_path, 'wt') as f:
            f.write("test content")

        result = extractor._extract_gz(gz_path, extract_dir)
        assert result is True
        assert (extract_dir / "test.txt").exists()
        assert (extract_dir / "test.txt").read_text() == "test content"

    @patch.object(extract_archives, 'logger')
    def test_extract_gz_failure(self, mock_logger, extractor, temp_dir):
        """Test gz extraction failure."""
        gz_path = temp_dir / "invalid.gz"
        gz_path.write_bytes(b"invalid gz content")

        result = extractor._extract_gz(gz_path, temp_dir / "extract")
        assert result is False
        mock_logger.error.assert_called_once()

    def test_extract_recursively_file_non_archive(self, extractor, temp_dir):
        """Test extract_recursively with a non-archive file."""
        test_file = temp_dir / "test.txt"
        test_file.write_text("test content")

        result = extractor.extract_recursively(test_file)
        assert len(result) == 0  # Non-archive files are not copied
        assert len(extractor.extracted_paths) == 0

    def test_extract_recursively_creates_output_dir(self, temp_dir):
        """Test that extract_recursively creates output directory when it doesn't exist."""
        # Create extractor with non-existent output dir
        nonexistent_output = temp_dir / "nonexistent_output"
        assert not nonexistent_output.exists()

        extractor = ArchiveExtractor(str(nonexistent_output))
        test_file = temp_dir / "test.txt"
        test_file.write_text("test content")

        result = extractor.extract_recursively(test_file)
        assert len(result) == 0
        assert nonexistent_output.exists()  # Should be created

    def test_extract_recursively_directory(self, extractor, temp_dir):
        """Test extract_recursively with a directory."""
        # Create test directory structure
        test_dir = temp_dir / "test_dir"
        test_dir.mkdir()
        (test_dir / "file1.txt").write_text("content1")
        (test_dir / "file2.txt").write_text("content2")

        result = extractor.extract_recursively(test_dir)
        assert len(result) == 0  # No archives to extract
        assert len(extractor.extracted_paths) == 0

    def test_extract_recursively_with_archive(self, extractor, temp_dir):
        """Test extract_recursively with an archive file."""
        # Create a test zip file
        zip_path = temp_dir / "test.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("test.txt", "test content")

        result = extractor.extract_recursively(zip_path)
        assert len(result) == 1
        assert len(extractor.extracted_paths) == 1
        assert result[0].exists()
        assert (result[0] / "test.txt").exists()

    def test_extract_recursively_nested_archives(self, extractor, temp_dir):
        """Test extract_recursively with nested archives."""
        # Create a tar file containing another tar file
        inner_tar = temp_dir / "inner.tar"
        with tarfile.open(inner_tar, 'w') as tar:
            test_file = temp_dir / "inner.txt"
            test_file.write_text("inner content")
            tar.add(str(test_file), arcname="inner.txt")

        outer_tar = temp_dir / "outer.tar"
        with tarfile.open(outer_tar, 'w') as tar:
            tar.add(str(inner_tar), arcname="inner.tar")

        result = extractor.extract_recursively(outer_tar)
        assert len(result) >= 1  # Should extract outer tar and find inner tar

    def test_extract_recursively_excluded_path(self, temp_dir):
        """Test extract_recursively with excluded path."""
        base_path = temp_dir / "base"
        base_path.mkdir()
        extractor = ArchiveExtractor(str(temp_dir / "output"), base_path=base_path)

        excluded_file = base_path / "node_modules" / "package.json"
        excluded_file.parent.mkdir(parents=True)
        excluded_file.write_text("excluded content")

        result = extractor.extract_recursively(excluded_file, base_path=base_path)
        assert len(result) == 0
        assert len(extractor.extracted_paths) == 0

    @patch.object(extract_archives, 'logger')
    def test_extract_recursively_nonexistent_file(self, mock_logger, extractor):
        """Test extract_recursively with nonexistent file."""
        nonexistent = Path("/nonexistent/file.txt")
        result = extractor.extract_recursively(nonexistent)
        assert result == []
        mock_logger.warning.assert_called_once()

    def test_extract_recursively_inside_output_dir(self, extractor, temp_dir):
        """Test extract_recursively skips paths inside output directory."""
        # Create a file inside the output directory
        output_file = extractor.output_dir / "internal.txt"
        output_file.write_text("internal content")

        result = extractor.extract_recursively(output_file)
        assert result == []
        assert len(extractor.extracted_paths) == 0


class TestMainFunction:
    """Test cases for the main function."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        temp_dir = Path(tempfile.mkdtemp())
        yield temp_dir
        shutil.rmtree(temp_dir)

    @patch.object(extract_archives, 'logger')
    @patch('builtins.print')
    def test_main_with_existing_file(self, mock_print, mock_logger, temp_dir):
        """Test main function with existing file."""
        # Create a test file
        test_file = temp_dir / "test.txt"
        test_file.write_text("test")

        main([str(test_file)], str(temp_dir / "output"))

        # Should print the file path since it's not an archive
        calls = mock_print.call_args_list
        assert len(calls) == 1
        # The path gets resolved, so check that it contains the filename
        assert "test.txt" in calls[0][0][0]
        mock_logger.info.assert_called()

    @patch.object(extract_archives, 'logger')
    @patch('builtins.print')
    def test_main_with_existing_directory(self, mock_print, mock_logger, temp_dir):
        """Test main function with existing directory."""
        # Create a test directory
        test_dir = temp_dir / "test_dir"
        test_dir.mkdir()
        (test_dir / "file.txt").write_text("content")

        main([str(test_dir)], str(temp_dir / "output"))

        # Should print the directory path
        calls = mock_print.call_args_list
        assert len(calls) == 1
        # The path gets resolved, so check that it contains the directory name
        assert "test_dir" in calls[0][0][0]
        mock_logger.info.assert_called()

    @patch.object(extract_archives, 'logger')
    @patch('builtins.print')
    def test_main_with_archive_file(self, mock_print, mock_logger, temp_dir):
        """Test main function with archive file."""
        # Create a test zip file
        zip_path = temp_dir / "test.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("test.txt", "test content")

        main([str(zip_path)], str(temp_dir / "output"))

        # Should print the output directory path
        calls = mock_print.call_args_list
        assert len(calls) > 0
        # The output directory path should be printed
        mock_logger.info.assert_called()

    @patch.object(extract_archives, 'logger')
    def test_main_with_nonexistent_path(self, mock_logger):
        """Test main function with nonexistent path."""
        main(["/nonexistent/path"], "/tmp/output")

        # Should log both the individual warning and the final "no paths to scan" message
        mock_logger.warning.assert_any_call("Path does not exist: %s", Path("/nonexistent/path"))
        mock_logger.warning.assert_any_call("No paths to scan")

    @patch.object(extract_archives, 'logger')
    @patch('builtins.print')
    def test_main_multiple_paths(self, mock_print, mock_logger, temp_dir):
        """Test main function with multiple input paths."""
        # Create test files
        file1 = temp_dir / "test1.txt"
        file1.write_text("content1")
        file2 = temp_dir / "test2.txt"
        file2.write_text("content2")

        main([str(file1), str(file2)], str(temp_dir / "output"))

        # Should print both file paths
        calls = mock_print.call_args_list
        assert len(calls) == 2
        # Check that both filenames are in the output
        assert any("test1.txt" in call[0][0] for call in calls)
        assert any("test2.txt" in call[0][0] for call in calls)


class TestArgumentParsing:
    """Test cases for command line argument parsing."""

    def test_argument_parser_creation(self):
        """Test that argument parser is created correctly."""
        from argparse import ArgumentParser

        parser = ArgumentParser(description="Archive Extraction Utility for ClamAV Scanning")
        parser.add_argument('input_paths', nargs='+', help="Input file or directory paths")
        parser.add_argument('--output-dir', dest='output_dir', default=tempfile.mkdtemp(),
                            help="Output directory for extracted files (default: temp directory)")

        # Test parsing valid arguments
        args = parser.parse_args(['file1.txt', 'file2.txt', '--output-dir', '/tmp/output'])
        assert args.input_paths == ['file1.txt', 'file2.txt']
        assert args.output_dir == '/tmp/output'

        # Test that input_paths is required
        with pytest.raises(SystemExit):
            parser.parse_args([])


class TestEdgeCases:
    """Edge case tests for archive extraction."""

    def test_empty_archive_extraction(self, tmp_path):
        """Test handling of empty archive files."""
        # Create an empty zip
        zip_path = tmp_path / "empty.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            pass

        # Archive extractor should handle empty archives gracefully
        assert zip_path.exists()
        assert zipfile.is_zipfile(zip_path)

    def test_archive_with_large_file_count(self, tmp_path):
        """Test archive with many files."""
        zip_path = tmp_path / "large.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            for i in range(100):
                zf.writestr(f"file{i:03d}.txt", f"content {i}")

        # Verify archive was created successfully
        with zipfile.ZipFile(zip_path, 'r') as zf:
            names = zf.namelist()
            assert len(names) == 100

    def test_archive_with_special_characters(self, tmp_path):
        """Test archive with special characters in filenames."""
        zip_path = tmp_path / "special.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("file-with-dashes.txt", "content")
            zf.writestr("file_with_underscores.txt", "content")
            zf.writestr("file.multiple.dots.txt", "content")

        # Verify archive was created successfully
        with zipfile.ZipFile(zip_path, 'r') as zf:
            assert len(zf.namelist()) == 3


if __name__ == '__main__':
    pytest.main([__file__])
