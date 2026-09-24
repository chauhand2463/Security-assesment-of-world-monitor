"""Scanner manifest registry (Phase 10.2).

Phase 5 answered "installed / not installed" and per-tool capabilities.  Phase
10.2 consolidates **everything the planner, the preflight, the New Scan wizard
and the UI are allowed to know about a scanner** into one deterministic,
auditable declaration:

  * identity            -- tool name, binary name, adapter kind,
  * capability          -- declared capabilities (see ``app.tools.capabilities``),
  * category            -- recon / dns / service / http / vulnerability / probe,
  * cooperation         -- input requirements + output format + active flag,
  * lifecycle checks    -- health command (version probe) used by preflight,
  * gating              -- ``opt_in`` tools never run without explicit
                           ``tool_options`` in scan configuration.

The manifest is a *declaration*, never an inference.  Install state is merged
per request from the real inventory (``app.tools.inventory.tool_inventory``);
a tool's capabilities are only ever reported as available when the tool is
actually installed (or is a native stdlib capability).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.tools.capabilities import CAP_AUTHORIZATION_TESTING, CAP_CORS_ANALYSIS, \
    CAP_DIRECTORY_FUZZING, CAP_DISCLOSURE_ANALYSIS, CAP_DNS_RESOLUTION, CAP_HEADER_ANALYSIS, \
    CAP_HTTP_FINGERPRINT, CAP_HTTP_PROBE, CAP_HTTP_REQUEST, CAP_JWT_ANALYSIS, \
    CAP_METHOD_ANALYSIS, CAP_PARAMETER_FUZZING, CAP_PORT_SCAN, CAP_REDIRECT_ANALYSIS, \
    CAP_SERVICE_DETECTION, CAP_SQLI_VALIDATION, CAP_SQL_INJECTION, CAP_SSTI_VALIDATION, \
    CAP_SUBDOMAIN_ENUMERATION, CAP_TECHNOLOGY_FINGERPRINT, CAP_TLS_ANALYSIS, \
    CAP_URL_DISCOVERY, CAP_VERSION_DETECTION, CAP_VULNERABILITY_SCAN, CAP_WEB_SERVER_SCAN, \
    CAP_XSS_VALIDATION


@dataclass(frozen=True)
class ScannerManifest:
    """Static declaration for one scanner the pipeline can schedule."""

    tool: str
    binary: str | None
    category: str
    adapter_kind: str          # external | legacy | probe | native
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    input_requirements: tuple[str, ...] = field(default_factory=tuple)
    output_format: str = "text"
    active: bool = False       # True when the tool mutates the target
    native: bool = False       # stdlib, always available
    description: str = ""
    health_command: tuple[str, ...] = field(default_factory=tuple)
    opt_in: bool = False       # never runs without explicit tool_options
    default_options: dict = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.tool)


# ---------------------------------------------------------------------------
# The canonical registry.  Order matters: it is the order tools are shown in
# the New Scan wizard and the readiness panel.
# ---------------------------------------------------------------------------
MANIFESTS: tuple[ScannerManifest, ...] = (
    ScannerManifest(
        tool="real_dns", binary=None, category="probe", adapter_kind="probe",
        capabilities=(CAP_DNS_RESOLUTION,), output_format="structured", native=True,
        description="Native stdlib DNS resolution probe (real A/AAAA facts).",
    ),
    ScannerManifest(
        tool="real_tcp", binary=None, category="probe", adapter_kind="probe",
        capabilities=(CAP_PORT_SCAN, CAP_SERVICE_DETECTION), output_format="structured",
        native=True,
        description="Native stdlib TCP connect probe over a curated port list.",
    ),
    ScannerManifest(
        tool="real_http", binary=None, category="probe", adapter_kind="probe",
        capabilities=(CAP_HTTP_PROBE, CAP_HTTP_FINGERPRINT, CAP_HTTP_REQUEST,
                      CAP_HEADER_ANALYSIS), output_format="structured", native=True,
        description="Native stdlib HTTP(S) GET probe (status/headers/title/body).",
    ),
    ScannerManifest(
        tool="world_monitor_discovery", binary=None, category="probe",
        adapter_kind="probe",
        capabilities=(), output_format="structured", native=True,
        description="World Monitor deployment discovery over real HTTP (explicit config only).",
    ),
    ScannerManifest(
        tool="endpoint_discovery", binary=None, category="http",
        adapter_kind="probe",
        capabilities=(CAP_URL_DISCOVERY,), output_format="structured", native=True,
        description="Native endpoint/parameter discovery from robots.txt, sitemap and root HTML links (real evidence only).",
    ),
    ScannerManifest(
        tool="subfinder", binary="subfinder", category="recon", adapter_kind="legacy",
        capabilities=(CAP_SUBDOMAIN_ENUMERATION,), input_requirements=("domain",),
        active=False,
        description="Passive subdomain enumeration (ProjectDiscovery).",
        health_command=("subfinder", "-version"),
    ),
    ScannerManifest(
        tool="assetfinder", binary="assetfinder", category="recon", adapter_kind="legacy",
        capabilities=(CAP_SUBDOMAIN_ENUMERATION,), input_requirements=("domain",),
        active=False,
        description="Passive asset/subdomain discovery (tomnomnom).",
        health_command=("assetfinder", "-version"),
    ),
    ScannerManifest(
        tool="dnsx", binary="dnsx", category="dns", adapter_kind="legacy",
        capabilities=(CAP_DNS_RESOLUTION,), input_requirements=("host",), active=False,
        description="DNS resolution / record probing (ProjectDiscovery).",
        health_command=("dnsx", "-version"),
    ),
    ScannerManifest(
        tool="nmap", binary="nmap", category="service", adapter_kind="external",
        capabilities=(CAP_PORT_SCAN, CAP_SERVICE_DETECTION, CAP_VERSION_DETECTION),
        input_requirements=("host",), output_format="text", active=True,
        description="Port and service/version detection.",
        health_command=("nmap", "--version"),
        default_options={"ports": "80,443,22,3000,3306,5432,8080,8443"},
    ),
    ScannerManifest(
        tool="httpx", binary="httpx", category="http", adapter_kind="external",
        capabilities=(CAP_HTTP_PROBE, CAP_HTTP_FINGERPRINT), input_requirements=("url", "host"),
        output_format="text", active=True,
        description="HTTP probing and server/title fingerprinting.",
        health_command=("httpx", "-version"),
    ),
    ScannerManifest(
        tool="gau", binary="gau", category="http", adapter_kind="legacy",
        capabilities=(CAP_URL_DISCOVERY,), input_requirements=("domain",), active=False,
        description="Passive URL discovery from public archives.",
        health_command=("gau", "--version"),
    ),
    ScannerManifest(
        tool="whatweb", binary="whatweb", category="http", adapter_kind="legacy",
        capabilities=(CAP_TECHNOLOGY_FINGERPRINT,), input_requirements=("url",),
        active=True, description="Web technology fingerprinting.",
        health_command=("whatweb", "--version"),
    ),
    ScannerManifest(
        tool="nuclei", binary="nuclei", category="vulnerability", adapter_kind="external",
        capabilities=(CAP_VULNERABILITY_SCAN,), input_requirements=("url", "host"),
        output_format="jsonl", active=True,
        description="Template-based vulnerability scanning.",
        health_command=("nuclei", "-version"),
    ),
    ScannerManifest(
        tool="ffuf", binary="ffuf", category="http", adapter_kind="external",
        capabilities=(CAP_DIRECTORY_FUZZING, CAP_PARAMETER_FUZZING),
        input_requirements=("url", "wordlist"), output_format="json", active=True,
        description="Content and parameter fuzzing (active; opt-in).",
        health_command=("ffuf", "-V"), opt_in=True,
    ),
    ScannerManifest(
        tool="nikto", binary="nikto", category="http", adapter_kind="external",
        capabilities=(CAP_WEB_SERVER_SCAN,), input_requirements=("url",),
        output_format="text", active=True,
        description="Web server misconfiguration scanning (active; opt-in).",
        health_command=("nikto", "--version"), opt_in=True,
    ),
    ScannerManifest(
        tool="sqlmap", binary="sqlmap", category="injection", adapter_kind="external",
        capabilities=(CAP_SQL_INJECTION,), input_requirements=("url", "parameter"),
        output_format="text", active=True,
        description="SQL injection testing (active, gated; never destructive here).",
        health_command=("sqlmap", "--version"), opt_in=True,
    ),
    ScannerManifest(
        tool="testssl", binary="testssl", category="tls", adapter_kind="external",
        capabilities=(CAP_TLS_ANALYSIS,), input_requirements=("host", "port"),
        output_format="json", active=False,
        description="TLS/SSL configuration analysis (opt-in).",
        health_command=("testssl", "--version"), opt_in=True,
    ),
    ScannerManifest(
        tool="native_http", binary=None, category="http", adapter_kind="native",
        capabilities=(CAP_HTTP_REQUEST, CAP_HEADER_ANALYSIS, CAP_CORS_ANALYSIS,
                      CAP_METHOD_ANALYSIS, CAP_REDIRECT_ANALYSIS,
                      CAP_DISCLOSURE_ANALYSIS, CAP_AUTHORIZATION_TESTING,
                      CAP_JWT_ANALYSIS, CAP_SQLI_VALIDATION, CAP_SSTI_VALIDATION,
                      CAP_XSS_VALIDATION),
        output_format="structured", active=True, native=True,
        description="Native HTTP observation and differential testing engine.",
    ),
)

_MANIFEST_INDEX: dict[str, ScannerManifest] = {m.tool: m for m in MANIFESTS}


def manifest(tool: str) -> ScannerManifest | None:
    """Return the manifest for ``tool``, or None when not registered."""
    return _MANIFEST_INDEX.get(tool)


def manifests() -> tuple[ScannerManifest, ...]:
    return MANIFESTS


def manifest_tools() -> list[str]:
    return [m.tool for m in MANIFESTS]


def category(tool: str) -> str:
    m = _MANIFEST_INDEX.get(tool)
    return m.category if m else "probe"


def health_command(tool: str) -> tuple[str, ...]:
    m = _MANIFEST_INDEX.get(tool)
    if m is None:
        return (tool, "--version")
    return m.health_command or (m.binary and (m.binary, "--version")) or ()


def default_options(tool: str) -> dict:
    m = _MANIFEST_INDEX.get(tool)
    return dict(m.default_options) if m else {}


def build_manifests(*, inventory: list[dict] | None = None) -> list[dict]:
    """Merge real inventory install state onto the static manifests.

    Every manifest carries its declared capabilities always; the UI-facing
    ``capabilities`` field is populated only when the tool is actually
    operational (installed binary, or a native capability), mirroring Phase 5's
    "reported only when available" rule.
    """
    inv: dict[str, dict] = {}
    if inventory:
        inv = {e.get("tool"): e for e in inventory if e.get("tool")}

    out: list[dict] = []
    for m in MANIFESTS:
        entry = inv.get(m.tool) or {}
        installed = bool(entry.get("installed")) or m.native
        out.append({
            "tool": m.tool,
            "binary": m.binary,
            "category": m.category,
            "adapter_kind": m.adapter_kind,
            "native": m.native,
            "active": m.active,
            "opt_in": m.opt_in,
            "input_requirements": list(m.input_requirements),
            "output_format": m.output_format,
            "description": m.description,
            "installed": installed,
            "path": entry.get("path"),
            "version": entry.get("version"),
            "health_status": entry.get("health_status", "installed" if installed else "missing"),
            "capabilities": list(m.capabilities) if installed else [],
            "declared_capabilities": list(m.capabilities),
            "default_options": m.default_options,
        })
    return out


def build_manifests_index(*, inventory: list[dict] | None = None) -> dict[str, dict]:
    return {m["tool"]: m for m in build_manifests(inventory=inventory)}


__all__ = [
    "MANIFESTS",
    "ScannerManifest",
    "build_manifests",
    "build_manifests_index",
    "category",
    "default_options",
    "health_command",
    "manifest",
    "manifest_tools",
    "manifests",
]