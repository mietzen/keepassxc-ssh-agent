"""Shared test fixtures."""

from __future__ import annotations

import os
import tempfile

import pytest


@pytest.fixture
def short_tmp(tmp_path):
    """Provide a short temp directory path for Unix sockets.

    AF_UNIX socket paths are limited to ~104 chars; the default tmp_path
    (especially on macOS) can exceed that. This fixture creates a short
    symlink in /tmp pointing to tmp_path.
    """
    link = tempfile.mktemp(prefix="ksa-", dir="/tmp")
    os.symlink(str(tmp_path), link)
    yield link
    os.unlink(link)
