"""Tool inventory: honest availability / version detection for every scanner.

Phase 4: the UI (and operators) must see which scanners are actually installed
and callable, never be told a scanner "ran" when its binary is absent.  This
module answers that against the real filesystem via ``shutil.which`` and a
version probe, and enriches each tool with its last persisted result.

Phase 10.2 adds an explicit, testable health vocabulary::

    installed        -- binary resolved AND a version probe succeeded.
    missing          -- binary not resolvable on PATH.
    version_unknown  -- binary resolvable, version probe failed/timed out
                        (tool is still schedulable; its version is unconfirmed).
    permission_error -- binary resolvable but not executable.

``installed`` remains bool for backward compatibility (``True`` whenever the
binary resolves), while ``health_status`` carries the finer-grained answer.
Detection is real: ``which`` plus running ``<binary> --version`` (or a
binary-specific probe) with a hard timeout.  Nothing here is ever fabricated
as available.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time

from app.tools.adapters.registry import ADAPTERS as ADAPTER_REGISTRY, get_adapter
from app.tools.manifest import manifest, manifest_tools

logger = logging.getLogger("cyberagent.inventory")

_VERSION_PROBE_TIMEOUT = 5

# Optional, per-tool version arguments (checked in order until one succeeds).
_VERSION_ARGS: dict[str, list[list[str]]] = {
    "subfinder": [["subfinder", "-version"], ["subfinder", "--version"]],
    "assetfinder": [["assetfinder", "-version"], ["assetfinder", "--version"]],
    "dnsx": [["dnsx", "-version"], ["dnsx", "--version"]],
    "nmap": [["nmap", "--version"], ["nmap", "-V"]],
    "httpx": [["httpx", "-version"], ["httpx", "--version"]],
    "gau": [["gau", "--version"], ["gau", "-version"]],
    "whatweb": [["whatweb", "--version"], ["whatweb", "-v"]],
    "nuclei": [["nuclei", "-version"], ["nuclei", "--version"]],
}

# Health-status vocabulary (Phase 10.2).
HEALTH_INSTALLED = "installed"
HEALTH_MISSING = "missing"
HEALTH_VERSION_UNKNOWN = "version_unknown"
HEALTH_PERMISSION_ERROR = "permission_error"
HEALTH_STATUSES = (HEALTH_INSTALLED, HEALTH_MISSING, HEALTH_VERSION_UNKNOWN, HEALTH_PERMISSION_ERROR)

# Cap version output noise.
_VERSION_OUTPUT_LIMIT = 40
_VERSION_PROBE_CACHE: dict[str, str | None] = {}
_VERSION_PROBE_CACHE_TTL = 60.0
_VERSION_PROBE_CACHE_AT: dict[str, float] = {}


def _run_version_probe(binary: str) -> str | None:
    """Return a short, real version string for an installed binary, or None."""
    candidates = _VERSION_ARGS.get(binary, [[binary, "-V"], [binary, "--version"]])
    for args in candidates:
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=_VERSION_PROBE_TIMEOUT,
                shell=False,
            )
            if proc.returncode != 0:
                continue
            text = (proc.stdout or proc.stderr or "").strip()
            if not text:
                continue
            # First line, trimmed; keeps the surface small and honest.
            return text.splitlines()[0][:_VERSION_OUTPUT_LIMIT].strip()
        except Exception:  # pragma: no cover - environment specific
            continue
    return None


def _cached_probe(binary: str) -> str | None:
    now = time.monotonic()
    hit_at = _VERSION_PROBE_CACHE_AT.get(binary)
    if hit_at is not None and now - hit_at < _VERSION_PROBE_CACHE_TTL:
        return _VERSION_PROBE_CACHE.get(binary)
    version = _run_version_probe(binary)
    _VERSION_PROBE_CACHE[binary] = version
    _VERSION_PROBE_CACHE_AT[binary] = now
    return version


def probe_health(binary: str) -> dict:
    """Probe one binary and return its concrete, observable health.

    Returns always::

        {"binary", "health_status", "installed", "path", "version", "note"}
    """
    if not binary:
        return {"binary": binary, "health_status": HEALTH_MISSING, "installed": False,
                "path": None, "version": None, "note": "no binary name registered"}
    path = shutil.which(binary)
    if path is None:
        return {"binary": binary, "health_status": HEALTH_MISSING, "installed": False,
                "path": None, "version": None, "note": f"{binary} not found on PATH"}
    if not os.access(path, os.X_OK):
        return {"binary": binary, "health_status": HEALTH_PERMISSION_ERROR,
                "installed": False, "path": path, "version": None,
                "note": f"{binary} found but is not executable ({path})"}
    version = _cached_probe(binary)
    if version is None:
        return {"binary": binary, "health_status": HEALTH_VERSION_UNKNOWN,
                "installed": True, "path": path, "version": None,
                "note": f"{binary} resolved but its version could not be confirmed"}
    return {"binary": binary, "health_status": HEALTH_INSTALLED, "installed": True,
            "path": path, "version": version, "note": None}


def _category(name: str) -> str:
    m = manifest(name)
    if m is not None:
        return m.category
    if name in ("subfinder", "assetfinder"):
        return "recon"
    if name == "dnsx":
        return "dns"
    if name == "nmap":
        return "service"
    if name in ("httpx", "gau", "whatweb"):
        return "http"
    if name == "nuclei":
        return "vulnerability"
    return "probe"


def _inventory_tool_names() -> list[str]:
    """Every tool the pipeline can schedule, in manifest order."""
    names = []
    for m in manifest_tools():
        if m == "native_http":
            continue  # internal engine capability, not a CLI scanner
        names.append(m)
    # Adapter-only tools that predate the manifest still surface.
    for name in ADAPTER_REGISTRY:
        if name not in names:
            names.append(name)
    return names


def tool_inventory() -> list[dict]:
    """Real snapshot of every registered scanner + the stdlib probes."""
    tools = []
    for name in _inventory_tool_names():
        m = manifest(name)
        binary = (m.binary if m is not None else name) or name
        if m is not None and m.native:
            tools.append({
                "tool": name,
                "binary": None,
                "installed": True,
                "path": None,
                "version": None,
                "category": m.category,
                "health_status": HEALTH_INSTALLED,
                "note": "native capability (no external binary required)",
            })
            continue
        health = probe_health(binary)
        tools.append({
            "tool": name,
            "binary": binary,
            "installed": health["installed"],
            "path": health["path"],
            "version": health["version"],
            "category": _category(name),
            "health_status": health["health_status"],
            "note": health["note"],
        })
    return tools


def tool_health_summary() -> dict:
    """Categorized health snapshot for the readiness UI."""
    tools = tool_inventory()
    counts = {status: 0 for status in HEALTH_STATUSES}
    for t in tools:
        counts[t["health_status"]] = counts.get(t["health_status"], 0) + 1
    return {
        "tools": tools,
        "counts": counts,
        "installed_count": sum(1 for t in tools if t["installed"]),
        "missing_count": sum(1 for t in tools if t["health_status"] == HEALTH_MISSING),
        "version_unknown_count": sum(1 for t in tools if t["health_status"] == HEALTH_VERSION_UNKNOWN),
        "permission_error_count": sum(1 for t in tools if t["health_status"] == HEALTH_PERMISSION_ERROR),
    }


__all__ = [
    "HEALTH_INSTALLED",
    "HEALTH_MISSING",
    "HEALTH_PERMISSION_ERROR",
    "HEALTH_STATUSES",
    "HEALTH_VERSION_UNKNOWN",
    "probe_health",
    "tool_health_summary",
    "tool_inventory",
]