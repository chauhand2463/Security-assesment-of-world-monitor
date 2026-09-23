"""Phase 10 — orchestrator & tool-abstraction tests.

Phase 10.2 surfaces a canonical, deterministic tool manifest whose health
vocabulary is richer than installed/missing: installed | missing |
version_unknown | permission_error.  Capability claims stay honest (reported
only when the tool is operational), opt-in fuzzing tools never run blind, and
``native_http`` is an engine capability, not a CLI scanner.
"""

import shutil

from app.tools.capabilities import CAP_DIRECTORY_FUZZING, CAP_HTTP_REQUEST
from app.tools.inventory import (
    HEALTH_INSTALLED,
    HEALTH_MISSING,
    HEALTH_PERMISSION_ERROR,
    HEALTH_VERSION_UNKNOWN,
    probe_health,
    tool_health_summary,
    tool_inventory,
)
from app.tools.manifest import build_manifests, manifest, manifest_tools


def test_manifest_covers_every_schedulable_tool():
    names = set(manifest_tools())
    assert {"real_dns", "real_tcp", "real_http", "subfinder", "assetfinder",
            "dnsx", "nmap", "httpx", "gau", "whatweb", "nuclei",
            "ffuf", "nikto", "sqlmap", "testssl", "world_monitor_discovery"} <= names
    # native_http is an engine capability, not a CLI scanner.
    assert "native_http" in names


def test_manifest_gating_and_capabilities():
    ffuf = manifest("ffuf")
    assert ffuf is not None and ffuf.opt_in is True
    assert CAP_DIRECTORY_FUZZING in ffuf.capabilities
    nmap = manifest("nmap")
    assert nmap is not None and nmap.default_options.get("ports")
    assert CAP_HTTP_REQUEST in manifest("native_http").capabilities
    probe = manifest("real_dns")
    assert probe is not None and probe.native is True and probe.binary is None


def test_build_manifests_keeps_declared_capabilities_and_reports_availability():
    out = {m["tool"]: m for m in build_manifests(inventory=None)}
    for tool in ("nmap", "nuclei", "subfinder", "ffuf", "real_dns", "native_http"):
        assert tool in out, f"manifest missing {tool}"
        assert out[tool]["declared_capabilities"], f"{tool} must declare capabilities"
    # Capabilities are surfaced only when operational (never fabricated).
    for tool in ("nmap", "nuclei", "ffuf"):
        assert set(out[tool]["capabilities"]) <= set(out[tool]["declared_capabilities"])
    # Native manifests are always installed.
    assert out["real_dns"]["installed"] is True
    assert out["real_dns"]["health_status"] in (HEALTH_INSTALLED, HEALTH_VERSION_UNKNOWN)


def test_probe_health_matches_filesystem_reality():
    # `python` is on PATH and executable everywhere: expect installed or
    # version_unknown (never permission_error/missing).
    py = shutil.which("python")
    assert py, "test environment must provide python on PATH"
    health = probe_health("python")
    assert health["installed"] is True
    assert health["health_status"] in (HEALTH_INSTALLED, HEALTH_VERSION_UNKNOWN)
    # A nonexistent binary is missing.
    missing = probe_health("definitely-not-a-real-binary-5731")
    assert missing["installed"] is False
    assert missing["health_status"] == HEALTH_MISSING


def test_inventory_carries_health_vocabulary():
    tools = {t["tool"]: t for t in tool_inventory()}
    for tool in ("real_dns", "real_tcp", "real_http"):
        assert tools[tool]["installed"] is True
        assert tools[tool]["health_status"] in (
            HEALTH_INSTALLED, HEALTH_VERSION_UNKNOWN)
    for tool in ("subfinder", "assetfinder", "dnsx", "nmap", "httpx",
                 "gau", "whatweb", "nuclei"):
        entry = tools[tool]
        binary = entry["binary"] or tool
        expected = shutil.which(binary) is not None
        assert entry["installed"] == expected, f"{tool} must mirror shutil.which"


def test_health_summary_counts_are_consistent():
    summary = tool_health_summary()
    by_status = summary["counts"]
    assert sum(by_status.values()) == len(summary["tools"])
    assert summary["installed_count"] == sum(
        1 for t in summary["tools"] if t["installed"])
    assert summary["missing_count"] == by_status.get(HEALTH_MISSING, 0)


def test_tools_manifest_endpoint(client, auth_headers):
    resp = client.get("/tools/manifest", headers=auth_headers)
    assert resp.status_code == 200
    manifests = {m["tool"]: m for m in resp.json()["manifests"]}
    assert "nmap" in manifests and "nuclei" in manifests
    assert set(manifests["native_http"]["capabilities"]) <= set(
        manifests["native_http"]["declared_capabilities"])


def test_tools_health_endpoint(client, auth_headers):
    resp = client.get("/tools/health", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["installed_count"] + body["missing_count"] + \
        body["version_unknown_count"] + body["permission_error_count"] == len(body["tools"])


def test_manifest_never_claims_capability_for_missing_tool(client, auth_headers):
    resp = client.get("/tools/manifest", headers=auth_headers)
    body = resp.json()
    for m in body["manifests"]:
        if not m["native"] and not m["installed"]:
            assert m["capabilities"] == [], (
                f"{m['tool']} reports capabilities while not installed")
            assert m["health_status"] in (
                HEALTH_MISSING, HEALTH_PERMISSION_ERROR, HEALTH_VERSION_UNKNOWN) or \
                m["health_status"] == HEALTH_INSTALLED


# Keep the status-panel endpoint healthy with the extended inventory.
def test_tool_status_buckets_still_consistent(client, auth_headers):
    resp = client.get("/tools/status", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["installed_count"] == len(body["installed"])
    assert body["missing_count"] == len(body["missing"])
    assert body["total"] == len(body["installed"]) + len(body["missing"])