"""Shared test fixtures."""

import os
import tempfile

import pytest


@pytest.fixture
def short_tmp(tmp_path):
    """Provide a short temp directory path for Unix sockets.

    macOS tmp_path is very long and exceeds AF_UNIX path limits (~104 chars).
    This fixture creates a short symlink in /tmp pointing to tmp_path.
    """
    link = tempfile.mktemp(prefix="ksa-", dir="/tmp")
    os.symlink(str(tmp_path), link)
    yield link
    os.unlink(link)
