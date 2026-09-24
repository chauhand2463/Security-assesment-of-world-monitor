"""Phase 7 pipeline stage catalogue.

Each stage maps onto a legacy ``Scan.stage`` value so every Phase 4 consumer
(SSE, get_scan, coverage endpoints) keeps working while the Phase 7 pipeline
runs through the finer-grained stage ledger (``scan_stages`` rows).
"""
from __future__ import annotations

PRECHECK = "PRECHECK"
TARGET_NORMALIZATION = "TARGET_NORMALIZATION"
PASSIVE_RECON = "PASSIVE_RECON"
DNS_DISCOVERY = "DNS_DISCOVERY"
PORT_SERVICE_DISCOVERY = "PORT_SERVICE_DISCOVERY"
HTTP_DISCOVERY = "HTTP_DISCOVERY"
TECHNOLOGY_IDENTIFICATION = "TECHNOLOGY_IDENTIFICATION"
VULNERABILITY_DISCOVERY = "VULNERABILITY_DISCOVERY"
DETERMINISTIC_ASSESSMENT = "DETERMINISTIC_ASSESSMENT"
VALIDATION = "VALIDATION"
FINDING_FINALIZATION = "FINDING_FINALIZATION"
COVERAGE = "COVERAGE"
REPORTING = "REPORTING"

STAGE_ORDER: tuple[str, ...] = (
    PRECHECK,
    TARGET_NORMALIZATION,
    PASSIVE_RECON,
    DNS_DISCOVERY,
    PORT_SERVICE_DISCOVERY,
    HTTP_DISCOVERY,
    TECHNOLOGY_IDENTIFICATION,
    VULNERABILITY_DISCOVERY,
    DETERMINISTIC_ASSESSMENT,
    VALIDATION,
    FINDING_FINALIZATION,
    COVERAGE,
    REPORTING,
)

# Stage -> legacy coarse stage (Scan.stage stays compatible with Phase 4).
LEGACY_STAGE: dict[str, str] = {
    PRECHECK: "starting",
    TARGET_NORMALIZATION: "starting",
    PASSIVE_RECON: "recon",
    DNS_DISCOVERY: "discovery",
    PORT_SERVICE_DISCOVERY: "service_scan",
    HTTP_DISCOVERY: "http_scan",
    TECHNOLOGY_IDENTIFICATION: "http_scan",
    VULNERABILITY_DISCOVERY: "vulnerability_scan",
    DETERMINISTIC_ASSESSMENT: "analysis",
    VALIDATION: "analysis",
    FINDING_FINALIZATION: "reporting",
    COVERAGE: "reporting",
    REPORTING: "reporting",
}

# Operators can request the conservative built-in set per stage.  External
# Phase 5 adapter tools beyond the built-ins are opt-in (default off) so a scan
# never does heavy fuzzing/sql-testing without an explicit operator decision.
_PENTEST_EXTRAS = ("ffuf", "nikto", "sqlmap", "testssl")

TOOL_TO_STAGE: dict[str, str] = {
    # stdlib probes (target normalization / passive observations feeding the
    # deterministic engine)
    "real_dns": TARGET_NORMALIZATION,
    "real_tcp": TARGET_NORMALIZATION,
    "real_http": TARGET_NORMALIZATION,
    # Phase 8: World Monitor deployment discovery (explicit config only)
    "world_monitor_discovery": TARGET_NORMALIZATION,
    # recon
    "subfinder": PASSIVE_RECON,
    "assetfinder": PASSIVE_RECON,
    # discovery
    "dnsx": DNS_DISCOVERY,
    # service discovery
    "nmap": PORT_SERVICE_DISCOVERY,
    # http discovery
    "httpx": HTTP_DISCOVERY,
    "gau": HTTP_DISCOVERY,
    "endpoint_discovery": HTTP_DISCOVERY,
    # technology identification
    "whatweb": TECHNOLOGY_IDENTIFICATION,
    # vulnerability discovery (extras opt-in)
    "nuclei": VULNERABILITY_DISCOVERY,
    "ffuf": VULNERABILITY_DISCOVERY,
    "nikto": VULNERABILITY_DISCOVERY,
    "sqlmap": VULNERABILITY_DISCOVERY,
    "testssl": VULNERABILITY_DISCOVERY,
}

# Default enabled tools per stage (extras default off).
DEFAULT_TOOLS: dict[str, bool] = {
    "real_dns": True,
    "real_tcp": True,
    "real_http": True,
    "world_monitor_discovery": True,
    "subfinder": True,
    "assetfinder": True,
    "dnsx": True,
    "nmap": True,
    "httpx": True,
    "gau": True,
    "endpoint_discovery": True,
    "whatweb": True,
    "nuclei": True,
    "ffuf": False,
    "nikto": False,
    "sqlmap": False,
    "testssl": False,
}

STAGE_TOOLS: dict[str, tuple[str, ...]] = {}
for _name, _stage in TOOL_TO_STAGE.items():
    STAGE_TOOLS.setdefault(_stage, []).append(_name)
STAGE_TOOLS = {k: tuple(v) for k, v in STAGE_TOOLS.items()}


def is_extra(tool: str) -> bool:
    return tool in _PENTEST_EXTRAS


def enabled(config: dict, tool: str) -> bool:
    """Operator intent: True unless explicitly disabled (extras: opt-in).

    ``world_monitor_discovery`` is conditional: it is only planned when the scan
    explicitly carries a World Monitor deployment reference, so an ordinary scan
    never records a meaningless World Monitor skip.
    """
    config = config or {}
    if tool == "world_monitor_discovery":
        if (config.get("tools") or {}).get(tool) is False:
            return False
        return bool(config.get("world_monitor"))
    if not is_extra(tool):
        return bool((config.get("tools", {}) or {}).get(tool, True))
    return bool((config.get("tools", {}) or {}).get(tool, False))


def plan_tasks(config: dict | None = None) -> list[str]:
    """Ordered plan of ``stage:<NAME>`` and ``tool:<NAME>`` tasks for a run.

    Excluded tools (disabled or missing at plan time) are still recorded as
    ``skipped`` executions; the plan itself never fabricates success.
    """
    config = config or {}
    tasks: list[str] = []
    for stage in STAGE_ORDER:
        tasks.append(f"stage:{stage}")
        for tool in STAGE_TOOLS.get(stage, ()):
            if enabled(config, tool):
                tasks.append(f"tool:{tool}")
    return tasks


def plan_tool_count(config: dict | None = None) -> int:
    return sum(1 for t in plan_tasks(config) if t.startswith("tool:"))


__all__ = [
    "STAGE_ORDER", "LEGACY_STAGE", "TOOL_TO_STAGE", "DEFAULT_TOOLS",
    "STAGE_TOOLS", "enabled", "is_extra", "plan_tasks", "plan_tool_count",
    "PRECHECK", "TARGET_NORMALIZATION", "PASSIVE_RECON", "DNS_DISCOVERY",
    "PORT_SERVICE_DISCOVERY", "HTTP_DISCOVERY", "TECHNOLOGY_IDENTIFICATION",
    "VULNERABILITY_DISCOVERY", "DETERMINISTIC_ASSESSMENT", "VALIDATION",
    "FINDING_FINALIZATION", "COVERAGE", "REPORTING",
]