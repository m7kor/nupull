"""Build and runtime diagnostic information for Nupull."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from typing import Any

from . import __version__

import importlib

try:
    _meta = importlib.import_module("._build_meta", package=__package__)
    _EMBEDDED_COMMIT: str | None = getattr(_meta, "COMMIT", None)
except Exception:
    _EMBEDDED_COMMIT = None

# Baked fallback commit SHA when running without git and without embedded metadata
BUILD_COMMIT: str = "32333dd4abe4ed09a2b13e629eaab58e748e3524"


def get_git_commit() -> str:
    """Return the current git commit SHA or the baked fallback commit."""
    if _EMBEDDED_COMMIT:
        return _EMBEDDED_COMMIT
    try:
        git_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".git")
        if os.path.exists(git_dir):
            out = subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2,
            ).strip()
            if out:
                return out
    except Exception:
        pass
    return BUILD_COMMIT


def get_build_info() -> dict[str, Any]:
    """Return structured build and runtime metadata."""
    is_frozen = bool(getattr(sys, "frozen", False))
    commit = get_git_commit()
    py_ver = platform.python_version()
    os_name = platform.platform(terse=True)
    arch = platform.machine() or "AMD64"

    if "-rc" in __version__ or "rc" in __version__:
        channel = "Release Candidate"
    elif "-beta" in __version__ or "beta" in __version__:
        channel = "Beta"
    elif "-alpha" in __version__ or "alpha" in __version__:
        channel = "Alpha"
    else:
        channel = "Stable"

    return {
        "package_name": "nupull",
        "version": __version__,
        "commit": commit,
        "channel": channel,
        "frozen": is_frozen,
        "python_version": py_ver,
        "platform": os_name,
        "architecture": arch,
    }


def format_build_info() -> str:
    """Return a human-readable diagnostic build summary."""
    info = get_build_info()
    frozen_str = "Yes (Standalone Binary)" if info["frozen"] else "No (Python Source)"
    lines = [
        "==================================================",
        " Nupull NX Container Studio — Build Diagnostics",
        "==================================================",
        f" Package Version : {info['version']}",
        f" Release Channel : {info['channel']}",
        f" Source Commit   : {info['commit']}",
        f" Executable Mode : {frozen_str}",
        f" Python Runtime  : {info['python_version']} ({info['architecture']})",
        f" OS Platform     : {info['platform']}",
        "==================================================",
    ]
    return "\n".join(lines)
